//! Conformance suite for the signing path (L0.7). Same mandate as
//! every gate: each profile rule is PROVEN to fire by a failing
//! negative case. Test keys are deterministic (fixed seeds) so the
//! committed example vectors are reproducible — clearly-marked TEST
//! keys, never real trust anchors.

use oh_sign::jwk::{Alg, Jwk, JwkSet, from_ed25519_seed, from_p256_seed, generate};
use oh_sign::{envelope, jws};
use serde_json::json;

fn test_card() -> serde_json::Value {
    json!({
        "protocolVersion": "1.0",
        "name": "Musterwil test agent",
        "url": "https://musterwil.example/agent",
        "skills": []
    })
}

fn operator_key() -> Jwk {
    from_ed25519_seed(&[0x42u8; 32], "musterwil-2026-01")
}

fn attestor_key() -> Jwk {
    from_p256_seed(&[0x24u8; 32], "oh-attestor-2026-01").expect("valid scalar")
}

fn jwks_of(key: &Jwk) -> JwkSet {
    JwkSet {
        keys: vec![key.public()],
    }
}

fn signed_envelope() -> serde_json::Value {
    let mut env = json!({
        "$schema": "https://ld.openhelvetia.swiss/ns/card/0.1/schema",
        "card": test_card(),
    });
    envelope::sign_authenticity(
        &mut env,
        &operator_key(),
        "https://musterwil.example/.well-known/jwks.json",
        "2026-08-20T12:00:00Z",
    )
    .expect("sign");
    env
}

// --- round trips ------------------------------------------------------

#[test]
fn eddsa_authenticity_round_trip() {
    let env = signed_envelope();
    envelope::verify_authenticity(&env, &jwks_of(&operator_key())).expect("verifies");
}

#[test]
fn es256_round_trip() {
    let key = attestor_key();
    let payload = jws::jcs_bytes(&test_card()).expect("jcs");
    let sig = jws::sign(&payload, &key).expect("sign");
    jws::verify(&sig, &payload, &key.public(), &key.kid).expect("verifies");
}

#[test]
fn generated_keys_round_trip_both_algorithms() {
    for alg in [Alg::EdDsa, Alg::Es256] {
        let key = generate(alg, "fresh").expect("keygen");
        let payload = b"payload".to_vec();
        let sig = jws::sign(&payload, &key).expect("sign");
        jws::verify(&sig, &payload, &key.public(), "fresh").expect("verifies");
    }
}

// --- the signature covers the data model, not a serialization ---------

#[test]
fn reserialization_does_not_break_the_signature() {
    let env = signed_envelope();
    // Same data model, different accidental serialization: rebuild the
    // card with reordered keys.
    let mut reordered = env.clone();
    reordered["card"] = json!({
        "skills": [],
        "url": "https://musterwil.example/agent",
        "protocolVersion": "1.0",
        "name": "Musterwil test agent"
    });
    envelope::verify_authenticity(&reordered, &jwks_of(&operator_key()))
        .expect("JCS covers the data model — key order is irrelevant");
}

#[test]
fn any_content_change_breaks_the_signature() {
    let mut env = signed_envelope();
    env["card"]["name"] = json!("Tampered agent");
    assert!(envelope::verify_authenticity(&env, &jwks_of(&operator_key())).is_err());
}

// --- placement independence -------------------------------------------

#[test]
fn served_card_verifies_with_identical_payload() {
    let env = signed_envelope();
    let served = envelope::served_card(&env).expect("served card");
    assert!(
        served.get("signatures").is_some(),
        "native A2A signatures member"
    );
    envelope::verify_served_card(&served, "musterwil-2026-01", &jwks_of(&operator_key()))
        .expect("payload = card minus signatures, byte-identical to the envelope path");
}

#[test]
fn embedded_card_with_signatures_member_is_refused() {
    let mut env = signed_envelope();
    env["card"]["signatures"] = json!([]);
    assert!(envelope::verify_authenticity(&env, &jwks_of(&operator_key())).is_err());
}

// --- attestation binding ----------------------------------------------

#[test]
fn attestation_binds_to_the_exact_card() {
    let mut env = signed_envelope();
    envelope::sign_attestation(
        &mut env,
        &attestor_key(),
        "https://openhelvetia.swiss/.well-known/jwks.json",
        "identity-verified",
        "2026-08-20T12:00:00Z",
        "2027-08-20T12:00:00Z",
    )
    .expect("attest");
    envelope::verify_attestation(&env, &jwks_of(&attestor_key())).expect("verifies");

    // Replay onto a later card revision MUST fail.
    let mut replayed = env.clone();
    replayed["card"]["name"] = json!("Revised agent");
    assert!(
        envelope::verify_attestation(&replayed, &jwks_of(&attestor_key())).is_err(),
        "an attestation must not be replayable onto a later card revision"
    );
}

#[test]
fn attestation_level_outside_the_enum_is_refused() {
    let mut env = signed_envelope();
    assert!(
        envelope::sign_attestation(
            &mut env,
            &attestor_key(),
            "https://openhelvetia.swiss/.well-known/jwks.json",
            "self-declared",
            "2026-08-20T12:00:00Z",
            "2027-08-20T12:00:00Z",
        )
        .is_err()
    );
}

// --- profile rules -----------------------------------------------------

#[test]
fn kid_mismatch_is_refused() {
    let env = signed_envelope();
    let mut wrong_kid = operator_key();
    wrong_kid.kid = "other-kid".into();
    let jwks = JwkSet {
        keys: vec![wrong_kid.public()],
    };
    // keyRef.kid says musterwil-2026-01; the set only has other-kid.
    assert!(envelope::verify_authenticity(&env, &jwks).is_err());
}

#[test]
fn the_protected_kid_can_be_read_without_a_second_header_parser() {
    // A verifier that has to SELECT the key before it can call verify
    // needs the kid first. It reads it here rather than growing its
    // own base64-and-JSON path — one implementation of the signature
    // profile, one place that decodes its header.
    let key = operator_key();
    let jws = jws::sign(b"payload", &key).expect("sign");
    assert_eq!(
        jws::protected_kid(&jws).expect("kid"),
        key.kid,
        "the header names the key that signed"
    );

    // Reading the kid is not a way around the profile's algorithm
    // rule: a header outside the profile fails here too.
    // {"alg":"none","kid":"x"} in base64url, written out so this test
    // needs no encoder of its own.
    let forged = jws::DetachedJws {
        protected: "eyJhbGciOiJub25lIiwia2lkIjoieCJ9".into(),
        signature: String::new(),
    };
    assert!(
        jws::protected_kid(&forged).is_err(),
        "alg «none» is refused even when only the kid was asked for"
    );

    let garbage = jws::DetachedJws {
        protected: "not base64url!!".into(),
        signature: String::new(),
    };
    assert!(jws::protected_kid(&garbage).is_err());
}

#[test]
fn alg_none_and_hs256_are_rejected_by_construction() {
    assert!(Alg::parse("none").is_err());
    assert!(Alg::parse("HS256").is_err());
    assert!(Alg::parse("RS256").is_err(), "outside the profile");
}

#[test]
fn header_alg_must_match_the_key() {
    // Sign with EdDSA, verify with an ES256 key under the same kid.
    let payload = b"x".to_vec();
    let sig = jws::sign(&payload, &operator_key()).expect("sign");
    let mut es_key = from_p256_seed(&[0x24u8; 32], "musterwil-2026-01").expect("scalar");
    es_key = es_key.public();
    assert!(jws::verify(&sig, &payload, &es_key, "musterwil-2026-01").is_err());
}

#[test]
fn non_https_jwks_uri_is_refused() {
    let mut env = signed_envelope();
    env["authenticity"]["keyRef"]["jwksUri"] = json!("http://musterwil.example/jwks.json");
    assert!(envelope::verify_authenticity(&env, &jwks_of(&operator_key())).is_err());
}

// --- committed example vectors ----------------------------------------

/// The committed examples carry REAL signatures from the fixed test
/// keys — regenerate with tests/regen_examples.rs logic if the card
/// content changes. This test proves the committed bytes verify.
#[test]
fn committed_example_vectors_verify() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples");
    let minimal: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("card-minimal.json")).expect("read"),
    )
    .expect("parse");
    let attested: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("card-attested.json")).expect("read"),
    )
    .expect("parse");
    let operator = jwks_of(&operator_key());
    let attestor = jwks_of(&attestor_key());
    envelope::verify_authenticity(&minimal, &operator).expect("card-minimal authenticity");
    envelope::verify_authenticity(&attested, &operator).expect("card-attested authenticity");
    envelope::verify_attestation(&attested, &attestor).expect("card-attested attestation");
}

/// Regenerates the committed example vectors with REAL signatures
/// from the fixed test keys — run deliberately:
/// `cargo test --test signing regen_committed_examples -- --ignored`.
/// Keeps every claim value (kids, URIs, timestamps) — only the
/// signature blocks change.
#[test]
#[ignore = "rewrites the committed example files; run deliberately"]
fn regen_committed_examples() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples");
    for name in ["card-minimal.json", "card-attested.json"] {
        let path = dir.join(name);
        let mut env: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("parse");
        let signed_at = env["authenticity"]["signedAt"]
            .as_str()
            .expect("signedAt")
            .to_string();
        let auth_uri = env["authenticity"]["keyRef"]["jwksUri"]
            .as_str()
            .expect("uri")
            .to_string();
        envelope::sign_authenticity(&mut env, &operator_key(), &auth_uri, &signed_at)
            .expect("sign authenticity");
        if let Some(att) = env.get("attestation").cloned() {
            let uri = att["keyRef"]["jwksUri"].as_str().expect("uri").to_string();
            envelope::sign_attestation(
                &mut env,
                &attestor_key(),
                &uri,
                att["level"].as_str().expect("level"),
                att["verifiedAt"].as_str().expect("verifiedAt"),
                att["expiresAt"].as_str().expect("expiresAt"),
            )
            .expect("sign attestation");
        }
        let mut out = serde_json::to_string_pretty(&env).expect("serialize");
        out.push('\n');
        std::fs::write(&path, out).expect("write");
    }
    // The PUBLIC test JWK Sets (committed beside the vectors so the
    // house gate can verify them on every commit; TEST keys, never
    // real trust anchors — the fixed seeds are in this file).
    let keys_dir = dir.join("keys");
    std::fs::create_dir_all(&keys_dir).expect("keys dir");
    for (file, key) in [
        ("musterwil.jwks.json", operator_key()),
        ("openhelvetia-attestor.jwks.json", attestor_key()),
    ] {
        let set = jwks_of(&key);
        let mut out = serde_json::to_string_pretty(&serde_json::to_value(&set).expect("jwks"))
            .expect("serialize");
        out.push('\n');
        std::fs::write(keys_dir.join(file), out).expect("write jwks");
    }
}
