//! Card drift detection (L1.2 completion of the E09-WP6b/f part,
//! unblocked by the L0.7 signing path): the real risk is not a
//! forged card at submission but the legitimate card whose state
//! drifts later. The daily check re-reads the served card and the
//! operator's JWKS and compares JCS canonical hashes against the
//! registry record; any divergence opens an event with notification.
//!
//! Listing state is a GRADIENT with explicit intermediate states —
//! never a binary listed/delisted flip (E09 no. 2: «ein rotiertes
//! Zertifikat wirft keine Gemeinde aus dem Verzeichnis»). There is
//! deliberately NO delisted state in this machine: quarantine is
//! visibly marked, resolution restores — removal would be a
//! registry act outside the checker's authority.

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use oh_sign::{envelope, jwk::JwkSet, jws};

/// The visible listing state (card spec «Grace and quarantine,
/// never binary»). Registry-derived state — never a card field
/// (E16 no. 6: dynamic facts never live in static cards).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum CardState {
    /// Served state matches the record and verifies.
    Listed,
    /// A newly signed card was served: signature VALID under the
    /// anchored key, content changed — a re-verification event
    /// (E09 no. 2). The entry stays listed; the attestation refers
    /// to the prior revision until the Verein re-verifies.
    ReVerificationDue { since: String },
    /// Signature stopped verifying or the anchored kid vanished
    /// from the served JWKS: grace with notification, never a flip.
    Grace { since: String, reason: String },
    /// Unresolved grace escalated: visibly marked, never silently
    /// removed; resolution restores.
    Quarantine { since: String, reason: String },
}

/// Grace escalates to quarantine after this many seconds
/// (checker-owned parameter, 14 days; the card spec fixes the
/// mechanics and leaves the window to the checker).
pub const GRACE_ESCALATION_SECS: i64 = 14 * 86400;

/// One drift-check event, appended to the event log (append-only
/// JSONL, same discipline as the probe history).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftEvent {
    pub entry: String,
    pub kind: String,
    pub detail: String,
    /// RFC 3339 UTC.
    pub at: String,
}

/// What the daily fetch observed for one entry.
pub struct Observation<'a> {
    /// The registry record: the stored envelope (embedded card +
    /// authenticity block) — the reference the spec compares against.
    pub record: &'a Value,
    /// The served /.well-known/agent-card.json as fetched.
    pub served_card: &'a Value,
    /// The operator's JWKS as fetched from keyRef.jwksUri.
    pub served_jwks: &'a JwkSet,
}

/// Assesses one observation against the previous state. Pure —
/// fetching and clocks stay outside (the library never invents
/// time). Returns the next state and the events this transition
/// emits (notifications ride on events, E09-WP6b).
pub fn assess(
    entry: &str,
    observation: &Observation,
    previous: &CardState,
    now_rfc3339: &str,
    now_epoch: i64,
) -> Result<(CardState, Vec<DriftEvent>)> {
    let mut events = Vec::new();
    let event = |kind: &str, detail: String| DriftEvent {
        entry: entry.into(),
        kind: kind.into(),
        detail,
        at: now_rfc3339.into(),
    };

    // The anchored key reference from the RECORD (the registry's
    // truth), never from the served card.
    let kid = observation
        .record
        .pointer("/authenticity/keyRef/kid")
        .and_then(Value::as_str)
        .context("record: authenticity.keyRef.kid missing")?;

    // 1. Revocation surface: the anchored kid must still be served.
    if observation.served_jwks.find(kid).is_err() {
        let reason = format!("anchored kid «{kid}» no longer in the served JWKS (revocation)");
        return Ok(escalate_or_enter_grace(
            previous,
            reason,
            now_rfc3339,
            now_epoch,
            &mut events,
            event,
        ));
    }

    // 2. Does the served card verify under the anchored key?
    let verifies =
        envelope::verify_served_card(observation.served_card, kid, observation.served_jwks).is_ok();
    if !verifies {
        let reason = "served card signature does not verify under the anchored key".to_string();
        return Ok(escalate_or_enter_grace(
            previous,
            reason,
            now_rfc3339,
            now_epoch,
            &mut events,
            event,
        ));
    }

    // 3. Content drift: JCS hash of the served card (minus its
    // signatures member) vs the record's embedded card.
    let mut served_content = observation.served_card.clone();
    if let Some(object) = served_content.as_object_mut() {
        object.remove("signatures");
    }
    let served_hash = sha256_hex(&jws::jcs_bytes(&served_content)?);
    let record_card = observation.record.get("card").context("record: no card")?;
    let record_hash = sha256_hex(&jws::jcs_bytes(record_card)?);

    if served_hash != record_hash {
        // Valid signature + changed content = a NEWLY SIGNED card:
        // a re-verification event, not a failure (E09 no. 2).
        let next = match previous {
            CardState::ReVerificationDue { since } => CardState::ReVerificationDue {
                since: since.clone(),
            },
            _ => {
                events.push(event(
                    "re-verification-due",
                    format!(
                        "newly signed card served (JCS {} → {}); attestation refers to the \
                         prior revision until re-verified",
                        &record_hash[..12],
                        &served_hash[..12]
                    ),
                ));
                CardState::ReVerificationDue {
                    since: now_rfc3339.into(),
                }
            }
        };
        return Ok((next, events));
    }

    // 4. Clean: restore if we were anywhere else.
    if !matches!(previous, CardState::Listed) {
        events.push(event(
            "restored",
            format!("served state matches the record again (was {previous:?})"),
        ));
    }
    Ok((CardState::Listed, events))
}

fn escalate_or_enter_grace(
    previous: &CardState,
    reason: String,
    now_rfc3339: &str,
    now_epoch: i64,
    events: &mut Vec<DriftEvent>,
    event: impl Fn(&str, String) -> DriftEvent,
) -> (CardState, Vec<DriftEvent>) {
    match previous {
        // Already in grace: escalate once the window is exceeded.
        CardState::Grace { since, .. } => {
            let since_epoch = crate::time::rfc3339_to_epoch(since).unwrap_or(now_epoch);
            if now_epoch - since_epoch > GRACE_ESCALATION_SECS {
                events.push(event(
                    "quarantine",
                    format!("grace unresolved past the window: {reason}"),
                ));
                (
                    CardState::Quarantine {
                        since: now_rfc3339.into(),
                        reason,
                    },
                    std::mem::take(events),
                )
            } else {
                (
                    CardState::Grace {
                        since: since.clone(),
                        reason,
                    },
                    std::mem::take(events),
                )
            }
        }
        // Quarantine stays quarantine while the cause persists.
        CardState::Quarantine { since, .. } => (
            CardState::Quarantine {
                since: since.clone(),
                reason,
            },
            std::mem::take(events),
        ),
        // Anything else enters grace WITH notification.
        _ => {
            events.push(event("grace", reason.clone()));
            (
                CardState::Grace {
                    since: now_rfc3339.into(),
                    reason,
                },
                std::mem::take(events),
            )
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = <sha2::Sha256 as sha2::Digest>::digest(bytes);
    digest.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
