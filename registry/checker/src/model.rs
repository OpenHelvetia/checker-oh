//! Probe planning: reads manifests and extracts every interface with
//! its declared liveness probe (DIRECTORY.md §3). Interfaces without
//! a probe stay in the plan — the check gradient must SAY «never
//! deep-checked», never silently skip (E14 Ziff. 3).

use std::path::Path;

use anyhow::{Context as _, Result};
use serde_json::Value;

/// The declared probe kinds (DIRECTORY.md §3, shapes enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    SparqlAsk,
    HttpGet,
    HttpHead,
    McpInitialize,
    /// The stateless era's entry call (`server/discover`). A separate
    /// kind rather than a flag on the one above, because it names
    /// which ERA the endpoint belongs to — and against the wrong era
    /// either call produces an answer that proves nothing.
    McpDiscover,
}

impl ProbeKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sparql-ask" => Some(Self::SparqlAsk),
            "http-get" => Some(Self::HttpGet),
            "http-head" => Some(Self::HttpHead),
            "mcp-initialize" => Some(Self::McpInitialize),
            "mcp-discover" => Some(Self::McpDiscover),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SparqlAsk => "sparql-ask",
            Self::HttpGet => "http-get",
            Self::HttpHead => "http-head",
            Self::McpInitialize => "mcp-initialize",
            Self::McpDiscover => "mcp-discover",
        }
    }
}

/// What proves liveness (DIRECTORY.md §3): `ok` = 2xx; `response` =
/// ANY HTTP answer (bot walls and GET-hostile endpoints included);
/// `boolean` = a SPARQL result document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    Ok,
    Boolean,
    Response,
}

impl Expect {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ok" => Some(Self::Ok),
            "boolean" => Some(Self::Boolean),
            "response" => Some(Self::Response),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Boolean => "boolean",
            Self::Response => "response",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeclaredProbe {
    pub kind: ProbeKind,
    pub expect: Expect,
    /// Probe URL: `probe.target` when declared, else the endpoint.
    pub url: String,
}

/// One interface of one manifest in the plan.
#[derive(Debug, Clone)]
pub struct PlanItem {
    /// Manifest slug (file stem = @id slug, enforced by oh-validate).
    pub entry: String,
    pub interface_index: usize,
    pub interface_type: String,
    pub endpoint: String,
    /// None = no probe declared → gradient stays «never deep-checked».
    pub probe: Option<DeclaredProbe>,
}

/// Reads every `*.json` manifest in the given directories into a
/// deterministic (name-sorted) probe plan.
pub fn plan(dirs: &[String]) -> Result<Vec<PlanItem>> {
    let mut files = Vec::new();
    for dir in dirs {
        let dir = Path::new(dir);
        for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                files.push(path);
            }
        }
    }
    files.sort();

    let mut items = Vec::new();
    for file in files {
        let raw = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        let doc: Value =
            serde_json::from_str(&raw).with_context(|| format!("parsing {}", file.display()))?;
        let slug = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let interfaces = doc
            .get("interfaces")
            .and_then(Value::as_array)
            .with_context(|| format!("{}: no interfaces array", file.display()))?;
        for (index, interface) in interfaces.iter().enumerate() {
            let endpoint = interface
                .get("endpoint")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let probe = interface.get("probe").and_then(|p| {
                let kind = ProbeKind::parse(p.get("kind")?.as_str()?)?;
                let expect = Expect::parse(p.get("expect")?.as_str()?)?;
                let url = p
                    .get("target")
                    .and_then(Value::as_str)
                    .unwrap_or(&endpoint)
                    .to_string();
                Some(DeclaredProbe { kind, expect, url })
            });
            items.push(PlanItem {
                entry: slug.clone(),
                interface_index: index,
                interface_type: interface
                    .get("@type")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
                    .to_string(),
                endpoint,
                probe,
            });
        }
    }
    Ok(items)
}
