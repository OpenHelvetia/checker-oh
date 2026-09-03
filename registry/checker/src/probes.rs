//! Probe execution (DIRECTORY.md §3): the minimal harmless call that
//! proves an interface is alive.
//!
//! AUTHORIZATION BOUNDARY (E21 spirit, E13 consent ladder): this
//! module fires real HTTP requests. It runs against OWN
//! infrastructure and local test servers unconditionally; against
//! third-party endpoints only under the declared conditions (probe
//! hints are the operator's declaration in their manifest; regular
//! automated runs switch on with the CI build-out and the E21
//! corpus resolution).

//! **Two MCP kinds, because MCP has two eras (E09 wire finding).**
//! The pinned revision `2026-07-28` has no `initialize` method at all:
//! the handshake era ended with `2025-11-25` and discovery moved to
//! `server/discover`. So an `mcp-initialize` that passes is never
//! evidence about the pinned revision: a server implementing that era
//! alone refuses the call — an answer, which `expect: response`
//! passes, while every real call would fail — and a server
//! implementing several revisions at once answers it through the
//! HANDSHAKE era, which says nothing about `2026-07-28`. The
//! platform's own gateway is the second kind (BJ), measured in
//! `testing/wire`. That gap is closed by vocabulary rather than worked
//! around in code: [`ProbeKind::McpDiscover`] asks the one question
//! that era answers, and `mcp-initialize` stays as the honest probe
//! for a handshake-era server. DIRECTORY.md §3 carries the semantics.
//!
//! Both are built by ONE function below. The envelope was learned on
//! the wire against an independent implementation, not from reading
//! the specification, and every part of it is load-bearing: a missing
//! `text/event-stream` in `Accept` is refused with `406` before any
//! MCP logic runs, and a `_meta` short of `clientCapabilities` is
//! refused with `-32602`. Sharing the builder is what keeps the two
//! kinds from drifting apart in what they send.

use std::time::{Duration, Instant};

use crate::model::{DeclaredProbe, Expect, ProbeKind};

/// Outcome of one probe execution.
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub passed: bool,
    pub status: Option<u16>,
    pub latency_ms: u64,
    pub detail: String,
}

fn agent(timeout_ms: u64) -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            // `expect: response` counts ANY status as liveness — the
            // status decision is ours, never the transport's.
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_millis(timeout_ms)))
            .build(),
    )
}

/// Executes one declared probe.
pub fn execute(probe: &DeclaredProbe, timeout_ms: u64) -> ProbeOutcome {
    let agent = agent(timeout_ms);
    let start = Instant::now();
    let result = match probe.kind {
        ProbeKind::HttpHead => agent.head(&probe.url).call(),
        ProbeKind::HttpGet => agent.get(&probe.url).call(),
        ProbeKind::SparqlAsk => agent
            .get(&probe.url)
            .query("query", "ASK {}")
            .header("accept", "application/sparql-results+json")
            .call(),
        ProbeKind::McpInitialize => mcp_call(&agent, &probe.url, "initialize"),
        ProbeKind::McpDiscover => mcp_call(&agent, &probe.url, "server/discover"),
    };
    let latency_ms = start.elapsed().as_millis() as u64;

    match result {
        Err(e) => ProbeOutcome {
            passed: false,
            status: None,
            latency_ms,
            detail: format!("transport error: {e}"),
        },
        Ok(mut response) => {
            let status = response.status().as_u16();
            let (passed, detail) = judge(probe.expect, status, &mut response);
            ProbeOutcome {
                passed,
                status: Some(status),
                latency_ms,
                detail,
            }
        }
    }
}

/// The MCP revision this platform pins, and the only one these two
/// probes speak.
const MCP_REVISION: &str = "2026-07-28";

/// Builds and sends ONE MCP call — the shared body of both MCP probe
/// kinds (DIRECTORY.md §3).
///
/// The envelope is identical for both; only `initialize` adds the
/// handshake-era parameters it is defined with. Keeping that the only
/// difference is deliberate: two probers would be two places for the
/// envelope to rot, and the envelope is the part that was expensive
/// to learn.
fn mcp_call(
    agent: &ureq::Agent,
    url: &str,
    method: &str,
) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
    let mut params = serde_json::json!({
        "protocolVersion": MCP_REVISION,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MCP_REVISION,
            "io.modelcontextprotocol/clientCapabilities": {}
        }
    });
    if method == "initialize" {
        // Handshake-era parameters, and only there: `server/discover`
        // has no client info to give, which is the point of an era
        // that does not keep a session.
        params["capabilities"] = serde_json::json!({});
        params["clientInfo"] = serde_json::json!({"name": "oh-check", "version": "0.1.0"});
    }
    agent
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", MCP_REVISION)
        .header("mcp-method", method)
        .send_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }))
}

/// The expect semantics (DIRECTORY.md §3), decided on OUR side.
fn judge(
    expect: Expect,
    status: u16,
    response: &mut ureq::http::Response<ureq::Body>,
) -> (bool, String) {
    match expect {
        // ANY HTTP answer proves liveness (bot walls, GET-hostile
        // endpoints) — reaching this arm at all is the proof.
        Expect::Response => (true, format!("answered {status}")),
        Expect::Ok => (
            (200..300).contains(&status),
            format!("status {status} (expect 2xx)"),
        ),
        Expect::Boolean => match response.body_mut().read_json::<serde_json::Value>() {
            Ok(body) if body.get("boolean").is_some() => (
                true,
                format!("SPARQL result document, boolean={}", body["boolean"]),
            ),
            Ok(_) => (false, "JSON without a SPARQL boolean field".into()),
            Err(e) => (false, format!("no SPARQL result document: {e}")),
        },
    }
}

// ---------------------------------------------------------------------
// The facade set (AQ): the platform's OWN origins, probed daily.
//
// This is the one place the checker points at infrastructure the
// association runs itself, so the E21/E13 consent ladder is not in
// play — the module header's authorization boundary says own
// infrastructure runs unconditionally.
//
// What it checks is what the launch runbook §3 promises: the facade
// exists AND is served under the right content type. A `/llms.txt`
// delivered as `text/html` is reachable and useless, and a checker
// that only asked «did it answer» would call that green.
// ---------------------------------------------------------------------

/// One facade the platform publishes about itself.
#[derive(Debug, Clone, Copy)]
pub struct Facade {
    /// Path below the origin.
    pub path: &'static str,
    /// The content type the runbook's deployment plan promises. The
    /// comparison is on the media type only — a `charset` parameter
    /// may be present or absent without being a defect.
    pub content_type: &'static str,
}

/// The facade set, in the order a cold-start reader meets them: the
/// well-known root first, because it is the pointer everything else
/// hangs from.
pub const FACADE_SET: &[Facade] = &[
    Facade {
        path: "/.well-known/openhelvetia.json",
        content_type: "application/json",
    },
    Facade {
        path: "/.well-known/security.txt",
        content_type: "text/plain",
    },
    Facade {
        path: "/directory.json",
        content_type: "application/json",
    },
    Facade {
        path: "/llms.txt",
        content_type: "text/plain",
    },
    Facade {
        path: "/robots.txt",
        content_type: "text/plain",
    },
    Facade {
        path: "/sitemap.xml",
        content_type: "application/xml",
    },
];

/// What a facade probe found — three states, because two would lie.
///
/// The middle state is the one that matters and it was learned by
/// running this against the real origin before launch: the zone
/// answers (`robots.txt` is served) while the facade set is not
/// deployed yet, so most paths come back `404`. Calling that a defect
/// would make the daily run red for weeks over a condition nobody
/// intends to fix before allocation day; calling it «ok» would be the
/// false green. It is neither: it is **absent**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FacadeState {
    /// Served, 2xx, under the content type the runbook promises.
    Correct,
    /// Not there yet: the transport failed, or the origin answered
    /// `404`/`410`. Pre-launch this is the expected state.
    Absent,
    /// The origin answered and the answer is wrong — a 2xx under the
    /// wrong media type, or any other status. This never waits.
    Defect,
}

/// What a facade probe found.
#[derive(Debug, Clone)]
pub struct FacadeOutcome {
    /// The full URL probed.
    pub url: String,
    /// Which of the three states applies.
    pub state: FacadeState,
    pub status: Option<u16>,
    /// The media type actually served, without parameters.
    pub content_type: Option<String>,
    pub detail: String,
}

/// Probes one facade of one origin.
pub fn facade(origin: &str, item: &Facade, timeout_ms: u64) -> FacadeOutcome {
    let url = format!("{}{}", origin.trim_end_matches('/'), item.path);
    let agent = agent(timeout_ms);
    match agent.get(&url).call() {
        Err(error) => FacadeOutcome {
            url,
            state: FacadeState::Absent,
            status: None,
            content_type: None,
            detail: format!("not reachable: {error}"),
        },
        Ok(response) => {
            let status = response.status().as_u16();
            let served = response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .map(|value| {
                    value
                        .split(';')
                        .next()
                        .unwrap_or(value)
                        .trim()
                        .to_ascii_lowercase()
                });
            let type_ok = served.as_deref() == Some(item.content_type);
            let (state, detail) = match status {
                200..=299 if type_ok => (
                    FacadeState::Correct,
                    format!("{status}, {}", item.content_type),
                ),
                200..=299 => (
                    FacadeState::Defect,
                    format!(
                        "served as {} — the runbook §3 plan promises {}",
                        served.clone().unwrap_or_else(|| "<no content-type>".into()),
                        item.content_type
                    ),
                ),
                // Not deployed yet. The distinction from a defect is
                // the whole point of the three states.
                404 | 410 => (
                    FacadeState::Absent,
                    format!("status {status} — not deployed at this origin yet"),
                ),
                _ => (FacadeState::Defect, format!("status {status} (expect 2xx)")),
            };
            FacadeOutcome {
                url,
                state,
                status: Some(status),
                content_type: served,
                detail,
            }
        }
    }
}
