//! Conformance suite for the drift state machine (E09-WP6b/f):
//! every transition is proven with REAL cryptography — records and
//! served cards are signed with the oh-sign test keys, tampering
//! breaks real signatures, re-signing produces real new ones.

use oh_check::drift::{self, CardState, GRACE_ESCALATION_SECS, Observation};
use oh_sign::envelope;
use oh_sign::jwk::{Jwk, JwkSet, from_ed25519_seed};
use serde_json::{Value, json};

const NOW: &str = "2026-08-20T12:00:00Z";
const NOW_EPOCH: i64 = 1_787_227_200; // pinned vector (time.rs suite)

fn operator_key() -> Jwk {
    from_ed25519_seed(&[0x42u8; 32], "musterwil-2026-01")
}

fn jwks() -> JwkSet {
    JwkSet {
        keys: vec![operator_key().public()],
    }
}

/// A signed registry record (envelope) and its served card.
fn record_and_served() -> (Value, Value) {
    let mut record = json!({
        "$schema": "https://ld.openhelvetia.swiss/ns/card/0.1/schema",
        "card": {
            "protocolVersion": "1.0",
            "name": "Musterwil drift-test agent",
            "url": "https://musterwil.example/agent",
            "skills": []
        }
    });
    envelope::sign_authenticity(
        &mut record,
        &operator_key(),
        "https://musterwil.example/.well-known/jwks.json",
        "2026-08-19T09:00:00Z",
    )
    .expect("sign record");
    let served = envelope::served_card(&record).expect("served card");
    (record, served)
}

fn assess(
    record: &Value,
    served: &Value,
    served_jwks: &JwkSet,
    previous: &CardState,
) -> (CardState, Vec<drift::DriftEvent>) {
    drift::assess(
        "musterwil",
        &Observation {
            record,
            served_card: served,
            served_jwks,
        },
        previous,
        NOW,
        NOW_EPOCH,
    )
    .expect("assess runs")
}

#[test]
fn clean_state_is_listed_without_events() {
    let (record, served) = record_and_served();
    let (state, events) = assess(&record, &served, &jwks(), &CardState::Listed);
    assert_eq!(state, CardState::Listed);
    assert!(events.is_empty());
}

#[test]
fn recovery_from_grace_restores_with_event() {
    let (record, served) = record_and_served();
    let previous = CardState::Grace {
        since: "2026-08-19T00:00:00Z".into(),
        reason: "earlier outage".into(),
    };
    let (state, events) = assess(&record, &served, &jwks(), &previous);
    assert_eq!(state, CardState::Listed);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "restored");
}

#[test]
fn tampered_served_content_enters_grace_with_notification() {
    let (record, mut served) = record_and_served();
    // Real tampering: content changes, the REAL signature goes stale.
    served["name"] = json!("Hijacked agent");
    let (state, events) = assess(&record, &served, &jwks(), &CardState::Listed);
    assert!(matches!(state, CardState::Grace { .. }), "{state:?}");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "grace");
    assert!(events[0].detail.contains("does not verify"));
}

#[test]
fn kid_removed_from_served_jwks_is_the_revocation_surface() {
    let (record, served) = record_and_served();
    let rotated = JwkSet {
        keys: vec![from_ed25519_seed(&[0x43u8; 32], "musterwil-2026-02").public()],
    };
    let (state, events) = assess(&record, &served, &rotated, &CardState::Listed);
    let CardState::Grace { reason, .. } = &state else {
        panic!("expected grace, got {state:?}");
    };
    assert!(reason.contains("revocation"), "{reason}");
    assert_eq!(events[0].kind, "grace");
}

#[test]
fn unresolved_grace_escalates_to_quarantine_after_the_window() {
    let (record, mut served) = record_and_served();
    served["name"] = json!("still broken");
    // Grace began just past the escalation window.
    let since = oh_check::time::epoch_to_rfc3339(NOW_EPOCH - GRACE_ESCALATION_SECS - 3600);
    let previous = CardState::Grace {
        since,
        reason: "signature failure".into(),
    };
    let (state, events) = assess(&record, &served, &jwks(), &previous);
    assert!(matches!(state, CardState::Quarantine { .. }), "{state:?}");
    assert_eq!(events[0].kind, "quarantine");
}

#[test]
fn grace_inside_the_window_does_not_escalate() {
    let (record, mut served) = record_and_served();
    served["name"] = json!("still broken");
    let since = oh_check::time::epoch_to_rfc3339(NOW_EPOCH - 3600);
    let previous = CardState::Grace {
        since: since.clone(),
        reason: "signature failure".into(),
    };
    let (state, events) = assess(&record, &served, &jwks(), &previous);
    assert_eq!(
        state,
        CardState::Grace {
            since,
            reason: "served card signature does not verify under the anchored key".into()
        }
    );
    assert!(events.is_empty(), "no repeated notification inside grace");
}

#[test]
fn quarantine_persists_while_the_cause_persists_never_delists() {
    let (record, mut served) = record_and_served();
    served["name"] = json!("still broken");
    let previous = CardState::Quarantine {
        since: "2026-08-01T00:00:00Z".into(),
        reason: "old".into(),
    };
    let (state, _) = assess(&record, &served, &jwks(), &previous);
    // Visibly marked, never removed: the machine has NO delisted
    // state — quarantine stays until resolution restores.
    assert!(matches!(state, CardState::Quarantine { since, .. }
        if since == "2026-08-01T00:00:00Z"));
}

#[test]
fn newly_signed_card_is_a_re_verification_event_not_a_failure() {
    let (record, _) = record_and_served();
    // The operator legitimately edits and RE-SIGNS the card.
    let mut revised = json!({
        "$schema": "https://ld.openhelvetia.swiss/ns/card/0.1/schema",
        "card": {
            "protocolVersion": "1.0",
            "name": "Musterwil drift-test agent v2",
            "url": "https://musterwil.example/agent",
            "skills": []
        }
    });
    envelope::sign_authenticity(
        &mut revised,
        &operator_key(),
        "https://musterwil.example/.well-known/jwks.json",
        NOW,
    )
    .expect("re-sign");
    let served = envelope::served_card(&revised).expect("served");

    let (state, events) = assess(&record, &served, &jwks(), &CardState::Listed);
    assert!(
        matches!(state, CardState::ReVerificationDue { .. }),
        "{state:?}"
    );
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "re-verification-due");
    assert!(events[0].detail.contains("prior revision"));

    // A second daily run in the same situation: state persists, no
    // duplicate notification.
    let (state2, events2) = assess(&record, &served, &jwks(), &state);
    assert_eq!(state2, state);
    assert!(events2.is_empty());
}
