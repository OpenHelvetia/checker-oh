//! `oh-sign` — the signing path of the agent-card envelope
//! (masterplan L0.7; spec: registry/standard/card/README.md).
//!
//! Detached JWS over JCS (RFC 8785) canonical bytes, algorithms
//! ES256 and EdDSA only, kid bound to keyRef.kid. Offline by
//! construction: verification takes a caller-provided JWK Set —
//! fetching the operator's well-known is the checker's daily job
//! (E09 no. 6), never this library's.

pub mod envelope;
pub mod jwk;
pub mod jws;
