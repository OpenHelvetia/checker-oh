//! Conformance suite for the checker core (L1.2). Probe semantics
//! are proven against a REAL local HTTP server (std TcpListener,
//! real sockets, real ureq transport) — never a mocked transport.
//! Third-party endpoints are NEVER touched here (E21 spirit; the
//! authorization boundary in probes.rs).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread;

use oh_check::gradient::{self, Gradient, Record};
use oh_check::model::{self, DeclaredProbe, Expect, ProbeKind};
use oh_check::probes;

/// Serves exactly one HTTP request with the given status/body on an
/// ephemeral port; returns the base URL.
fn one_shot_server(status: u16, content_type: &str, body: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let content_type = content_type.to_string();
    let body = body.to_string();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        // Read the request until the header terminator (sufficient
        // for these probes; bodies are drained by closing anyway).
        let mut buffer = [0u8; 8192];
        let mut seen = Vec::new();
        loop {
            let n = stream.read(&mut buffer).unwrap_or(0);
            if n == 0 {
                break;
            }
            seen.extend_from_slice(&buffer[..n]);
            if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let reason = if status == 200 { "OK" } else { "X" };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).expect("write");
    });
    format!("http://{addr}/")
}

/// Like [`one_shot_server`], but hands the raw request back so a test
/// can assert what actually went onto the socket. The MCP probes are
/// the reason this exists: their envelope is the part that was
/// expensive to learn (E09), and «the request had the right shape» is
/// not something a status code can tell you.
fn capturing_server(status: u16, body: &str) -> (String, std::sync::mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let body = body.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        // Headers, then exactly the announced body — a POST body does
        // not arrive by closing the pipe, so the length decides.
        let mut buffer = [0u8; 8192];
        let mut seen = Vec::new();
        let mut header_end = None;
        let mut content_length = 0usize;
        loop {
            let n = stream.read(&mut buffer).unwrap_or(0);
            if n == 0 {
                break;
            }
            seen.extend_from_slice(&buffer[..n]);
            if header_end.is_none()
                && let Some(at) = seen.windows(4).position(|w| w == b"\r\n\r\n")
            {
                header_end = Some(at + 4);
                let head = String::from_utf8_lossy(&seen[..at]).to_lowercase();
                content_length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
            }
            if let Some(at) = header_end
                && seen.len() >= at + content_length
            {
                break;
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&seen).to_string());
        let reason = if status == 200 { "OK" } else { "X" };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
    });
    (format!("http://{addr}/"), rx)
}

fn probe(kind: ProbeKind, expect: Expect, url: String) -> DeclaredProbe {
    DeclaredProbe { kind, expect, url }
}

// --- probe semantics (DIRECTORY.md §3) --------------------------------

#[test]
fn http_head_expect_ok_passes_on_2xx() {
    let url = one_shot_server(200, "text/plain", "");
    let outcome = probes::execute(&probe(ProbeKind::HttpHead, Expect::Ok, url), 3000);
    assert!(outcome.passed, "{}", outcome.detail);
    assert_eq!(outcome.status, Some(200));
}

#[test]
fn http_head_expect_ok_fails_on_5xx() {
    let url = one_shot_server(500, "text/plain", "boom");
    let outcome = probes::execute(&probe(ProbeKind::HttpHead, Expect::Ok, url), 3000);
    assert!(!outcome.passed);
    assert_eq!(outcome.status, Some(500));
}

#[test]
fn expect_response_passes_on_any_answer_even_4xx() {
    // Bot walls and GET-hostile endpoints: ANY answer proves liveness.
    let url = one_shot_server(403, "text/html", "denied");
    let outcome = probes::execute(&probe(ProbeKind::HttpGet, Expect::Response, url), 3000);
    assert!(outcome.passed, "{}", outcome.detail);
    assert_eq!(outcome.status, Some(403));
}

#[test]
fn sparql_ask_expect_boolean_passes_on_result_document() {
    let url = one_shot_server(
        200,
        "application/sparql-results+json",
        "{\"head\":{},\"boolean\":true}",
    );
    let outcome = probes::execute(&probe(ProbeKind::SparqlAsk, Expect::Boolean, url), 3000);
    assert!(outcome.passed, "{}", outcome.detail);
    assert!(outcome.detail.contains("boolean=true"));
}

#[test]
fn sparql_ask_expect_boolean_fails_on_html() {
    let url = one_shot_server(200, "text/html", "<html>not sparql</html>");
    let outcome = probes::execute(&probe(ProbeKind::SparqlAsk, Expect::Boolean, url), 3000);
    assert!(!outcome.passed);
}

#[test]
fn mcp_initialize_posts_and_any_answer_passes() {
    let url = one_shot_server(
        200,
        "application/json",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
    );
    let outcome = probes::execute(
        &probe(ProbeKind::McpInitialize, Expect::Response, url),
        3000,
    );
    assert!(outcome.passed, "{}", outcome.detail);
}

#[test]
fn mcp_discover_expect_ok_passes_on_a_stateless_answer() {
    // What a conformant stateless-era endpoint returns: a 2xx whose
    // body names the revisions it supports. Under `expect: ok` that
    // is evidence about MCP, not merely about the transport — which
    // is the whole reason this kind exists beside mcp-initialize.
    let (url, _seen) = capturing_server(
        200,
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"supportedVersions\":[\"2026-07-28\"]}}",
    );
    let outcome = probes::execute(&probe(ProbeKind::McpDiscover, Expect::Ok, url), 3000);
    assert!(outcome.passed, "{}", outcome.detail);
    assert_eq!(outcome.status, Some(200));
}

#[test]
fn mcp_discover_sends_the_complete_per_request_envelope() {
    // Every assertion here is a thing a conformant server refuses the
    // request without, learned on the wire against an independent
    // implementation (E09, testing/wire) rather than from the spec:
    // a missing text/event-stream is 406 before any MCP logic runs,
    // and a _meta short of clientCapabilities is -32602.
    let (url, seen) = capturing_server(200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
    let _ = probes::execute(&probe(ProbeKind::McpDiscover, Expect::Ok, url), 3000);
    let request = seen
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the server saw a request");
    let lower = request.to_lowercase();

    assert!(request.starts_with("POST "), "{request}");
    assert!(
        lower.contains("accept: application/json, text/event-stream"),
        "both media types, or the POST is refused with 406: {request}"
    );
    assert!(
        lower.contains("mcp-protocol-version: 2026-07-28"),
        "the pinned revision travels in the header: {request}"
    );
    assert!(
        lower.contains("mcp-method: server/discover"),
        "the method header must match the body's method: {request}"
    );
    let body = request.split("\r\n\r\n").nth(1).expect("a body");
    let json: serde_json::Value = serde_json::from_str(body).expect("the body is JSON");
    assert_eq!(json["method"], "server/discover");
    let meta = &json["params"]["_meta"];
    assert_eq!(
        meta["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
    assert!(
        meta.get("io.modelcontextprotocol/clientCapabilities")
            .is_some(),
        "without this key the request is refused with -32602: {body}"
    );
    assert!(
        json["params"].get("clientInfo").is_none(),
        "clientInfo is handshake-era; an era that keeps no session has nobody to tell: {body}"
    );
}

#[test]
fn the_two_mcp_kinds_send_the_same_envelope_and_differ_only_in_the_call() {
    // The shared builder, asserted rather than assumed: two probers
    // would be two places for the envelope to rot.
    let (discover_url, discover_seen) = capturing_server(200, "{}");
    let _ = probes::execute(
        &probe(ProbeKind::McpDiscover, Expect::Response, discover_url),
        3000,
    );
    let (init_url, init_seen) = capturing_server(200, "{}");
    let _ = probes::execute(
        &probe(ProbeKind::McpInitialize, Expect::Response, init_url),
        3000,
    );
    let wait = std::time::Duration::from_secs(5);
    let discover = discover_seen.recv_timeout(wait).expect("discover request");
    let initialize = init_seen.recv_timeout(wait).expect("initialize request");

    for header in [
        "accept: application/json, text/event-stream",
        "mcp-protocol-version: 2026-07-28",
    ] {
        assert!(discover.to_lowercase().contains(header), "{discover}");
        assert!(initialize.to_lowercase().contains(header), "{initialize}");
    }
    assert!(
        discover
            .to_lowercase()
            .contains("mcp-method: server/discover")
    );
    assert!(initialize.to_lowercase().contains("mcp-method: initialize"));
}

#[test]
fn transport_failure_is_a_failed_outcome_never_a_panic() {
    // Bind then drop: the port exists but nothing listens.
    let addr = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr")
    };
    let outcome = probes::execute(
        &probe(
            ProbeKind::HttpGet,
            Expect::Response,
            format!("http://{addr}/"),
        ),
        1500,
    );
    assert!(!outcome.passed);
    assert_eq!(outcome.status, None);
    assert!(outcome.detail.contains("transport error"));
}

// --- gradient + history ----------------------------------------------

fn record(entry: &str, index: usize, passed: bool, at: &str) -> Record {
    Record {
        entry: entry.into(),
        interface_index: index,
        kind: "http-get".into(),
        url: "http://127.0.0.1/".into(),
        passed,
        status: Some(if passed { 200 } else { 500 }),
        latency_ms: 1,
        detail: String::new(),
        measured_at: at.into(),
    }
}

#[test]
fn gradient_distinguishes_never_checked_from_checked() {
    let history = vec![record("a", 0, true, "2026-08-20T10:00:00Z")];
    assert!(matches!(
        gradient::for_interface(&history, "a", 0),
        Gradient::Passed { .. }
    ));
    // Same entry, other interface: NEVER conflated with the passed one.
    assert_eq!(
        gradient::for_interface(&history, "a", 1),
        Gradient::NeverChecked
    );
    assert_eq!(
        gradient::for_interface(&history, "b", 0),
        Gradient::NeverChecked
    );
}

#[test]
fn latest_record_wins() {
    let history = vec![
        record("a", 0, false, "2026-08-20T10:00:00Z"),
        record("a", 0, true, "2026-08-20T11:00:00Z"),
    ];
    assert!(matches!(
        gradient::for_interface(&history, "a", 0),
        Gradient::Passed { .. }
    ));
}

#[test]
fn history_is_append_only_jsonl_and_round_trips() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("history");
    let _ = std::fs::remove_dir_all(&dir);
    gradient::append(&dir, &[record("a", 0, true, "2026-08-20T10:00:00Z")]).expect("append 1");
    gradient::append(&dir, &[record("a", 0, false, "2026-08-20T11:00:00Z")]).expect("append 2");
    let history = gradient::load(&dir).expect("load");
    assert_eq!(history.len(), 2, "appends accumulate, never overwrite");
    assert!(matches!(
        gradient::for_interface(&history, "a", 0),
        Gradient::Failed { .. }
    ));
}

// --- plan extraction --------------------------------------------------

#[test]
fn plan_reads_declared_probes_and_target_override() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("plan");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(
        dir.join("testcase.json"),
        serde_json::json!({
            "@id": "https://ld.openhelvetia.swiss/registry/testcase",
            "interfaces": [
                {"@type": "SparqlInterface", "endpoint": "https://e.example/sparql",
                 "probe": {"kind": "sparql-ask", "expect": "boolean"}},
                {"@type": "RestInterface", "endpoint": "https://e.example/api",
                 "probe": {"kind": "http-get", "expect": "response",
                            "target": "https://e.example/api/health"}},
                {"@type": "DownloadInterface", "endpoint": "https://e.example/dump"}
            ]
        })
        .to_string(),
    )
    .expect("write");
    let plan = model::plan(&[dir.display().to_string()]).expect("plan");
    assert_eq!(plan.len(), 3);
    let p0 = plan[0].probe.as_ref().expect("declared");
    assert_eq!(p0.kind, ProbeKind::SparqlAsk);
    assert_eq!(
        p0.url, "https://e.example/sparql",
        "endpoint is the default target"
    );
    let p1 = plan[1].probe.as_ref().expect("declared");
    assert_eq!(
        p1.url, "https://e.example/api/health",
        "target overrides endpoint"
    );
    assert!(
        plan[2].probe.is_none(),
        "no probe declared stays visible in the plan"
    );
}

#[test]
fn plan_covers_the_real_corpus() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let plan = model::plan(&[
        root.join("registry/entries").display().to_string(),
        root.join("registry/standard/test-corpus")
            .display()
            .to_string(),
        root.join("registry/standard/examples")
            .display()
            .to_string(),
    ])
    .expect("plan");
    // The relocated test corpus plus the examples: the count is
    // pinned so a silently shrunken corpus (e.g. a path no-op like
    // the one caught during the relocation) fails loudly.
    assert!(
        plan.len() >= 30,
        "expected the full corpus, got {}",
        plan.len()
    );
    // The L0.8 migration declared a probe on every interface — the
    // plan must see all of them (a probe-less interface here would
    // mean the migration regressed).
    let undeclared: Vec<_> = plan.iter().filter(|i| i.probe.is_none()).collect();
    assert!(
        undeclared.is_empty(),
        "interfaces without probes: {:?}",
        undeclared
            .iter()
            .map(|i| format!("{}#{}", i.entry, i.interface_index))
            .collect::<Vec<_>>()
    );
}

// --- the facade set (AQ): three states, because two would lie -------

#[test]
fn a_facade_served_correctly_is_correct() {
    let url = one_shot_server(200, "text/plain; charset=utf-8", "Contact: mailto:x@y");
    let item = oh_check::probes::Facade {
        path: "",
        content_type: "text/plain",
    };
    let outcome = oh_check::probes::facade(url.trim_end_matches('/'), &item, 3000);
    assert_eq!(outcome.state, oh_check::probes::FacadeState::Correct);
    // The charset parameter is not part of the comparison: present or
    // absent, it is not a defect.
    assert_eq!(outcome.content_type.as_deref(), Some("text/plain"));
}

#[test]
fn a_facade_under_the_wrong_content_type_is_a_defect_not_a_wait() {
    // The failure mode the runbook §3 plan exists to prevent: the file
    // is reachable and useless. A checker that only asked «did it
    // answer» would call this green.
    let url = one_shot_server(200, "text/html", "<html>llms</html>");
    let item = oh_check::probes::Facade {
        path: "",
        content_type: "text/plain",
    };
    let outcome = oh_check::probes::facade(url.trim_end_matches('/'), &item, 3000);
    assert_eq!(outcome.state, oh_check::probes::FacadeState::Defect);
    assert!(
        outcome.detail.contains("promises text/plain"),
        "the message must name the promise: {}",
        outcome.detail
    );
}

#[test]
fn a_facade_that_is_not_deployed_yet_is_absent_not_a_defect() {
    // Learned from the real origin before launch: the zone answers
    // while the facade set is not deployed, so most paths are 404.
    // Red for weeks over a condition nobody intends to fix before
    // allocation day would be noise, not a signal.
    let url = one_shot_server(404, "text/html", "not found");
    let item = oh_check::probes::Facade {
        path: "",
        content_type: "application/json",
    };
    let outcome = oh_check::probes::facade(url.trim_end_matches('/'), &item, 3000);
    assert_eq!(outcome.state, oh_check::probes::FacadeState::Absent);
}

#[test]
fn a_broken_origin_is_a_defect_even_though_nothing_was_deployed() {
    // 5xx is not «absent»: something is there and it is failing.
    let url = one_shot_server(503, "text/html", "boom");
    let item = oh_check::probes::Facade {
        path: "",
        content_type: "application/json",
    };
    let outcome = oh_check::probes::facade(url.trim_end_matches('/'), &item, 3000);
    assert_eq!(outcome.state, oh_check::probes::FacadeState::Defect);
}

#[test]
fn the_facade_set_covers_the_runbook_plan_and_leads_with_the_pointer() {
    let set = oh_check::probes::FACADE_SET;
    assert_eq!(
        set[0].path, "/.well-known/openhelvetia.json",
        "the well-known root is the pointer everything else hangs from"
    );
    for path in [
        "/.well-known/security.txt",
        "/directory.json",
        "/llms.txt",
        "/sitemap.xml",
    ] {
        assert!(
            set.iter().any(|item| item.path == path),
            "{path} is in the runbook §3 plan and must be probed"
        );
    }
}
