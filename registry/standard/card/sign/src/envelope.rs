//! Envelope operations per the card spec's normative signing inputs:
//!
//! - `authenticity.signature` signs `JCS(card)` — the embedded card
//!   object, which MUST NOT contain a `signatures` member.
//! - `attestation.signature` signs
//!   `JCS({"card": <card>, "attestation": <attestation minus
//!   "signature">})` — the attestor's claims bound to the exact card
//!   it verified; an attestation cannot be replayed onto a later
//!   card revision.
//!
//! Placement independence: the build step emits the authenticity JWS
//! into the served card's `signatures` member; A2A verifiers compute
//! the identical payload (card minus `signatures`). Both directions
//! are covered here and test-pinned.

use anyhow::{Context as _, Result, bail};
use serde_json::{Value, json};

use crate::jwk::{Jwk, JwkSet};
use crate::jws::{self, DetachedJws};

fn card_of(envelope: &Value) -> Result<&Value> {
    let card = envelope.get("card").context("envelope: no card member")?;
    if card.get("signatures").is_some() {
        bail!("embedded card MUST NOT contain a signatures member (spec; schema forbids it)");
    }
    Ok(card)
}

fn key_ref(block: &Value) -> Result<(&str, &str)> {
    let key_ref = block.get("keyRef").context("block: no keyRef")?;
    Ok((
        key_ref
            .get("jwksUri")
            .and_then(Value::as_str)
            .context("keyRef.jwksUri missing")?,
        key_ref
            .get("kid")
            .and_then(Value::as_str)
            .context("keyRef.kid missing")?,
    ))
}

/// Signs the embedded card and writes the authenticity block.
/// `signed_at` is caller-provided (RFC 3339) — the library never
/// invents time.
pub fn sign_authenticity(
    envelope: &mut Value,
    key: &Jwk,
    jwks_uri: &str,
    signed_at: &str,
) -> Result<()> {
    let payload = jws::jcs_bytes(card_of(envelope)?)?;
    let jws = jws::sign(&payload, key)?;
    envelope["authenticity"] = json!({
        "signature": { "protected": jws.protected, "signature": jws.signature },
        "keyRef": { "jwksUri": jwks_uri, "kid": key.kid },
        "signedAt": signed_at,
    });
    Ok(())
}

/// Verifies the authenticity block against the embedded card with
/// the operator's JWK Set (fetched elsewhere — the library is
/// offline by construction; daily fetching is checker territory).
pub fn verify_authenticity(envelope: &Value, operator_jwks: &JwkSet) -> Result<()> {
    let authenticity = envelope
        .get("authenticity")
        .context("envelope: no authenticity block")?;
    let (jwks_uri, kid) = key_ref(authenticity)?;
    if !jwks_uri.starts_with("https://") {
        bail!("keyRef.jwksUri must be HTTPS under the operator's domain, got «{jwks_uri}»");
    }
    let jws: DetachedJws = serde_json::from_value(
        authenticity
            .get("signature")
            .context("authenticity: no signature")?
            .clone(),
    )
    .context("authenticity.signature shape")?;
    let payload = jws::jcs_bytes(card_of(envelope)?)?;
    jws::verify(&jws, &payload, operator_jwks.find(kid)?, kid).context("authenticity signature")
}

/// Signs the attestation claims bound to the exact embedded card.
pub fn sign_attestation(
    envelope: &mut Value,
    key: &Jwk,
    jwks_uri: &str,
    level: &str,
    verified_at: &str,
    expires_at: &str,
) -> Result<()> {
    if !["countersigned", "identity-verified", "deep-verified"].contains(&level) {
        bail!("attestation level «{level}» outside the schema enum");
    }
    let claims = json!({
        "level": level,
        "verifiedAt": verified_at,
        "expiresAt": expires_at,
        "keyRef": { "jwksUri": jwks_uri, "kid": key.kid },
    });
    let bound = json!({ "card": card_of(envelope)?, "attestation": claims });
    let jws = jws::sign(&jws::jcs_bytes(&bound)?, key)?;
    let mut attestation = claims;
    attestation["signature"] = json!({ "protected": jws.protected, "signature": jws.signature });
    envelope["attestation"] = attestation;
    Ok(())
}

/// Verifies the attestation block: claims bound to the EXACT card.
pub fn verify_attestation(envelope: &Value, attestor_jwks: &JwkSet) -> Result<()> {
    let attestation = envelope
        .get("attestation")
        .context("envelope: no attestation block")?;
    let (_, kid) = key_ref(attestation)?;
    let jws: DetachedJws = serde_json::from_value(
        attestation
            .get("signature")
            .context("attestation: no signature")?
            .clone(),
    )
    .context("attestation.signature shape")?;
    let mut claims = attestation.clone();
    claims
        .as_object_mut()
        .expect("attestation is object")
        .remove("signature");
    let bound = json!({ "card": card_of(envelope)?, "attestation": claims });
    jws::verify(
        &jws,
        &jws::jcs_bytes(&bound)?,
        attestor_jwks.find(kid)?,
        kid,
    )
    .context("attestation signature")
}

/// Emits the SERVED card (pure A2A 1.0): the embedded card plus a
/// native `signatures` member carrying the envelope's authenticity
/// JWS — placement independence in the serving direction.
pub fn served_card(envelope: &Value) -> Result<Value> {
    let card = card_of(envelope)?.clone();
    let signature = envelope
        .pointer("/authenticity/signature")
        .context("envelope: no authenticity signature to serve")?
        .clone();
    let mut served = card;
    served["signatures"] = json!([signature]);
    Ok(served)
}

/// Verifies a SERVED card (with `signatures` member) directly: the
/// payload is the card minus `signatures` — byte-identical to the
/// envelope path per the JCS profile.
pub fn verify_served_card(served: &Value, kid: &str, operator_jwks: &JwkSet) -> Result<()> {
    let signatures = served
        .get("signatures")
        .and_then(Value::as_array)
        .context("served card: no signatures member")?;
    let jws: DetachedJws = serde_json::from_value(
        signatures
            .first()
            .context("served card: empty signatures")?
            .clone(),
    )
    .context("served signature shape")?;
    let mut stripped = served.clone();
    stripped
        .as_object_mut()
        .expect("card is object")
        .remove("signatures");
    jws::verify(
        &jws,
        &jws::jcs_bytes(&stripped)?,
        operator_jwks.find(kid)?,
        kid,
    )
    .context("served-card signature")
}
