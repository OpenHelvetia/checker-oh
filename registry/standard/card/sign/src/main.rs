//! CLI for the signing path (L0.7).
//!
//! Usage:
//!   oh-sign keygen --alg EdDSA|ES256 --kid <kid> --out <dir>
//!       writes <dir>/<kid>.private.jwk (0600-sensitive — keep out of
//!       git) and <dir>/jwks.json (the PUBLIC set for /.well-known/).
//!   oh-sign sign --envelope <file> --key <private.jwk> \
//!       --jwks-uri <https://…/jwks.json> --signed-at <RFC3339>
//!       signs the embedded card, writes the authenticity block back.
//!   oh-sign attest --envelope <file> --key <private.jwk> \
//!       --jwks-uri <uri> --level <l> --verified-at <t> --expires-at <t>
//!   oh-sign verify --envelope <file> --jwks <jwks.json> \
//!       [--attestor-jwks <jwks.json>]
//!   oh-sign verify-served --card <file> --kid <kid> --jwks <jwks.json>
//!
//! Time is always caller-provided — the tool never invents it.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context as _, Result};
use oh_sign::{envelope, jwk};

const USAGE: &str = "usage: oh-sign keygen|sign|attest|verify|verify-served (see source header)";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        anyhow::bail!("{USAGE}");
    }
    let command = args.remove(0);

    fn take(args: &mut Vec<String>, flag: &str) -> Result<String> {
        let pos = args
            .iter()
            .position(|a| a == flag)
            .with_context(|| format!("{flag} is required\n{USAGE}"))?;
        anyhow::ensure!(pos + 1 < args.len(), "{flag} needs a value");
        let value = args.remove(pos + 1);
        args.remove(pos);
        Ok(value)
    }
    fn take_optional(args: &mut Vec<String>, flag: &str) -> Option<String> {
        let pos = args.iter().position(|a| a == flag)?;
        if pos + 1 >= args.len() {
            return None;
        }
        let value = args.remove(pos + 1);
        args.remove(pos);
        Some(value)
    }

    match command.as_str() {
        "keygen" => {
            let alg = jwk::Alg::parse(&take(&mut args, "--alg")?)?;
            let kid = take(&mut args, "--kid")?;
            let out = take(&mut args, "--out")?;
            let key = jwk::generate(alg, &kid)?;
            std::fs::create_dir_all(&out)?;
            let private_path = Path::new(&out).join(format!("{kid}.private.jwk"));
            write_json(&private_path, &serde_json::to_value(&key)?)?;
            let jwks = jwk::JwkSet {
                keys: vec![key.public()],
            };
            write_json(
                &Path::new(&out).join("jwks.json"),
                &serde_json::to_value(&jwks)?,
            )?;
            println!(
                "keygen: {} written; PUBLIC set jwks.json for /.well-known/ — keep the private key out of git",
                private_path.display()
            );
        }
        "sign" => {
            let path = take(&mut args, "--envelope")?;
            let key: jwk::Jwk = read_json(&take(&mut args, "--key")?)?;
            let jwks_uri = take(&mut args, "--jwks-uri")?;
            let signed_at = take(&mut args, "--signed-at")?;
            let mut env: serde_json::Value = read_json(&path)?;
            envelope::sign_authenticity(&mut env, &key, &jwks_uri, &signed_at)?;
            write_json(Path::new(&path), &env)?;
            println!("signed: authenticity block written to {path}");
        }
        "attest" => {
            let path = take(&mut args, "--envelope")?;
            let key: jwk::Jwk = read_json(&take(&mut args, "--key")?)?;
            let jwks_uri = take(&mut args, "--jwks-uri")?;
            let level = take(&mut args, "--level")?;
            let verified_at = take(&mut args, "--verified-at")?;
            let expires_at = take(&mut args, "--expires-at")?;
            let mut env: serde_json::Value = read_json(&path)?;
            envelope::sign_attestation(
                &mut env,
                &key,
                &jwks_uri,
                &level,
                &verified_at,
                &expires_at,
            )?;
            write_json(Path::new(&path), &env)?;
            println!("attested: attestation block written to {path}");
        }
        "verify" => {
            let env: serde_json::Value = read_json(&take(&mut args, "--envelope")?)?;
            let jwks: jwk::JwkSet = read_json(&take(&mut args, "--jwks")?)?;
            envelope::verify_authenticity(&env, &jwks)?;
            println!("authenticity: VERIFIED");
            if let Some(attestor) = take_optional(&mut args, "--attestor-jwks") {
                let attestor_jwks: jwk::JwkSet = read_json(&attestor)?;
                envelope::verify_attestation(&env, &attestor_jwks)?;
                println!("attestation: VERIFIED (bound to this exact card)");
            }
        }
        "verify-served" => {
            let card: serde_json::Value = read_json(&take(&mut args, "--card")?)?;
            let kid = take(&mut args, "--kid")?;
            let jwks: jwk::JwkSet = read_json(&take(&mut args, "--jwks")?)?;
            envelope::verify_served_card(&card, &kid, &jwks)?;
            println!("served card: VERIFIED (payload = card minus signatures)");
        }
        other => anyhow::bail!("unknown command «{other}»\n{USAGE}"),
    }
    anyhow::ensure!(args.is_empty(), "unexpected arguments {args:?}");
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {path}"))
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    let mut out = serde_json::to_string_pretty(value)?;
    out.push('\n');
    std::fs::write(path, out).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}
