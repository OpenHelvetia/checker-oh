//! Detached JWS per the card README's JWS profile: the payload is
//! the JCS canonical form of the JSON data (RFC 8785), the signature
//! block carries only `protected` and `signature`, and the verifier
//! reconstructs the signing input from the content it actually
//! received. Signature covers the data model, not one accidental
//! serialization.

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};

use crate::jwk::{Alg, Jwk};

/// The transported signature block (`authenticity.signature` /
/// `attestation.signature`): detached — no payload member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetachedJws {
    pub protected: String,
    pub signature: String,
}

/// Protected header, restricted to the profile: `alg` and `kid`
/// MUST be present; `kid` MUST equal the envelope's `keyRef.kid`
/// (checked by the caller against its keyRef).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Protected {
    alg: String,
    kid: String,
}

/// JCS canonical bytes of any JSON value (RFC 8785). The profile's
/// number constraint (IEEE-754-double representable) is enforced by
/// serde_jcs itself, which errors on non-representable numbers.
pub fn jcs_bytes(value: &serde_json::Value) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).context("JCS canonicalization (RFC 8785)")
}

fn signing_input(protected_b64: &str, payload: &[u8]) -> Vec<u8> {
    let mut input = protected_b64.as_bytes().to_vec();
    input.push(b'.');
    input.extend_from_slice(B64.encode(payload).as_bytes());
    input
}

/// Signs `payload` (already JCS bytes) with the private JWK.
pub fn sign(payload: &[u8], key: &Jwk) -> Result<DetachedJws> {
    let alg = key.alg()?;
    let protected = Protected {
        alg: alg.as_str().into(),
        kid: key.kid.clone(),
    };
    let protected_b64 = B64.encode(serde_json::to_vec(&protected).context("protected header")?);
    let input = signing_input(&protected_b64, payload);

    let signature = match alg {
        Alg::EdDsa => {
            use ed25519_dalek::Signer as _;
            let seed: [u8; 32] = key
                .d_bytes()?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Ed25519 d must be 32 bytes"))?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            signing_key.sign(&input).to_bytes().to_vec()
        }
        Alg::Es256 => {
            use p256::ecdsa::signature::Signer as _;
            let signing_key = p256::ecdsa::SigningKey::from_slice(&key.d_bytes()?)
                .context("ES256 private scalar")?;
            let signature: p256::ecdsa::Signature = signing_key.sign(&input);
            // JWS ES256 wire format: raw r||s (64 bytes), never DER.
            signature.to_bytes().to_vec()
        }
    };

    Ok(DetachedJws {
        protected: protected_b64,
        signature: B64.encode(signature),
    })
}

/// The `kid` a detached JWS names in its protected header.
///
/// Exists so a verifier that has to SELECT the key before it can call
/// [`verify`] does not grow a second JWS header parser. One
/// implementation of the signature profile, one place that decodes
/// its header (E16's one-implementation rule).
///
/// # Errors
///
/// Fails when the header is not base64url, not JSON, or carries an
/// algorithm outside the profile — the same checks [`verify`] makes,
/// so reading the kid can never be a way around them.
pub fn protected_kid(jws: &DetachedJws) -> Result<String> {
    let raw = B64
        .decode(&jws.protected)
        .context("protected header: invalid base64url")?;
    let protected: Protected =
        serde_json::from_slice(&raw).context("protected header: invalid JSON")?;
    Alg::parse(&protected.alg)?;
    Ok(protected.kid)
}

/// Verifies a detached JWS against `payload` (JCS bytes) with the
/// PUBLIC key selected by the caller. Enforces the profile:
/// admitted algorithms only, header alg must match the key's
/// algorithm, header kid must equal `expected_kid`.
pub fn verify(jws: &DetachedJws, payload: &[u8], key: &Jwk, expected_kid: &str) -> Result<()> {
    let protected_raw = B64
        .decode(&jws.protected)
        .context("protected header: invalid base64url")?;
    let protected: Protected =
        serde_json::from_slice(&protected_raw).context("protected header: invalid JSON")?;
    // Alg::parse rejects "none" and HS* by construction.
    let header_alg = Alg::parse(&protected.alg)?;
    let key_alg = key.alg()?;
    if header_alg != key_alg {
        bail!(
            "header alg {} does not match the key's algorithm {}",
            protected.alg,
            key_alg.as_str()
        );
    }
    if protected.kid != expected_kid {
        bail!(
            "header kid «{}» does not equal keyRef.kid «{expected_kid}» (profile MUST)",
            protected.kid
        );
    }
    if key.kid != expected_kid {
        bail!(
            "selected key kid «{}» does not equal keyRef.kid «{expected_kid}»",
            key.kid
        );
    }

    let signature = B64
        .decode(&jws.signature)
        .context("signature: invalid base64url")?;
    let input = signing_input(&jws.protected, payload);

    match header_alg {
        Alg::EdDsa => {
            use ed25519_dalek::Verifier as _;
            let x: [u8; 32] = key
                .x_bytes()?
                .try_into()
                .map_err(|_| anyhow::anyhow!("Ed25519 x must be 32 bytes"))?;
            let verifying_key =
                ed25519_dalek::VerifyingKey::from_bytes(&x).context("Ed25519 public key")?;
            let sig_bytes: [u8; 64] = signature
                .try_into()
                .map_err(|_| anyhow::anyhow!("EdDSA signature must be 64 bytes"))?;
            verifying_key
                .verify(&input, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
                .map_err(|_| anyhow::anyhow!("EdDSA signature does not verify"))
        }
        Alg::Es256 => {
            use p256::ecdsa::signature::Verifier as _;
            let x = key.x_bytes()?;
            let y = key.y_bytes()?;
            anyhow::ensure!(x.len() == 32 && y.len() == 32, "P-256 x/y must be 32 bytes");
            // SEC1 uncompressed: 0x04 || x || y.
            let mut sec1 = vec![0x04u8];
            sec1.extend_from_slice(&x);
            sec1.extend_from_slice(&y);
            let verifying_key =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).context("P-256 public key")?;
            let signature = p256::ecdsa::Signature::from_slice(&signature)
                .context("ES256 signature must be raw r||s (64 bytes)")?;
            verifying_key
                .verify(&input, &signature)
                .map_err(|_| anyhow::anyhow!("ES256 signature does not verify"))
        }
    }
}
