//! Minimal JWK / JWK Set handling for exactly the two profile
//! algorithms (card README «Algorithms»): EdDSA (Ed25519, OKP) and
//! ES256 (P-256, EC). Deliberately no JOSE framework — the profile
//! is small and every accepted field is understood; anything else is
//! rejected loudly.

use anyhow::{Context as _, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};

/// The two admitted algorithms. `none` and all HS* are rejected at
/// parse time by construction — they simply do not exist here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alg {
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "ES256")]
    Es256,
}

impl Alg {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "EdDSA" => Ok(Self::EdDsa),
            "ES256" => Ok(Self::Es256),
            other => bail!("algorithm «{other}» is not admitted (profile: EdDSA, ES256)"),
        }
    }
}

/// One JSON Web Key, public or private, restricted to the profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub kid: String,
    /// Public: x (both). EC additionally y. Private: additionally d.
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn find(&self, kid: &str) -> Result<&Jwk> {
        self.keys
            .iter()
            .find(|k| k.kid == kid)
            .with_context(|| format!("kid «{kid}» not present in the JWK Set"))
    }
}

impl Jwk {
    pub fn alg(&self) -> Result<Alg> {
        match (self.kty.as_str(), self.crv.as_str()) {
            ("OKP", "Ed25519") => Ok(Alg::EdDsa),
            ("EC", "P-256") => Ok(Alg::Es256),
            (kty, crv) => {
                bail!("key type {kty}/{crv} is not admitted (profile: OKP/Ed25519, EC/P-256)")
            }
        }
    }

    /// The public half (drops `d`).
    pub fn public(&self) -> Jwk {
        Jwk {
            d: None,
            ..self.clone()
        }
    }

    pub fn x_bytes(&self) -> Result<Vec<u8>> {
        B64.decode(&self.x).context("JWK x: invalid base64url")
    }
    pub fn y_bytes(&self) -> Result<Vec<u8>> {
        B64.decode(self.y.as_deref().context("JWK y missing (EC key)")?)
            .context("JWK y: invalid base64url")
    }
    pub fn d_bytes(&self) -> Result<Vec<u8>> {
        B64.decode(
            self.d
                .as_deref()
                .context("JWK d missing (private key required)")?,
        )
        .context("JWK d: invalid base64url")
    }
}

/// Generates a fresh keypair from OS randomness. Returns the PRIVATE
/// JWK (public half derivable via [`Jwk::public`]).
pub fn generate(alg: Alg, kid: &str) -> Result<Jwk> {
    match alg {
        Alg::EdDsa => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).context("OS randomness")?;
            Ok(from_ed25519_seed(&seed, kid))
        }
        Alg::Es256 => {
            // Rejection-sample until the bytes form a valid P-256 scalar.
            loop {
                let mut candidate = [0u8; 32];
                getrandom::fill(&mut candidate).context("OS randomness")?;
                if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&candidate) {
                    return Ok(from_p256_key(&key, kid));
                }
            }
        }
    }
}

/// Deterministic Ed25519 JWK from a fixed seed — for the COMMITTED
/// example test vectors only (clearly-marked test keys, never real
/// trust anchors).
pub fn from_ed25519_seed(seed: &[u8; 32], kid: &str) -> Jwk {
    let key = ed25519_dalek::SigningKey::from_bytes(seed);
    Jwk {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        kid: kid.into(),
        x: B64.encode(key.verifying_key().to_bytes()),
        y: None,
        d: Some(B64.encode(seed)),
    }
}

fn from_p256_key(key: &p256::ecdsa::SigningKey, kid: &str) -> Jwk {
    // SEC1 uncompressed: 0x04 || x (32) || y (32).
    let point = key.verifying_key().to_sec1_point(false);
    let bytes = point.as_bytes();
    Jwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        kid: kid.into(),
        x: B64.encode(&bytes[1..33]),
        y: Some(B64.encode(&bytes[33..65])),
        d: Some(B64.encode(key.to_bytes())),
    }
}

/// Deterministic ES256 JWK from a fixed scalar seed (test vectors).
pub fn from_p256_seed(seed: &[u8; 32], kid: &str) -> Result<Jwk> {
    let key =
        p256::ecdsa::SigningKey::from_slice(seed).context("seed is not a valid P-256 scalar")?;
    Ok(from_p256_key(&key, kid))
}
