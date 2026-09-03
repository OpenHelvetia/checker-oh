//! The check gradient and its history (E14 Ziff. 3): «nie tief
//! geprüft» ≠ «geprüft, bestanden» — absence of a check is a visible
//! state of its own, never conflated with success.
//!
//! History is APPEND-ONLY JSONL (one record per probe execution);
//! corrections are new records, never edits — the same discipline as
//! the L1.3 bitemporal core this feeds later. Quarantine/grace
//! states (signature drift, E09-WP6b) join when L0.7's signing path
//! is built — they need card signatures to exist first.

use std::path::Path;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

/// One probe execution, as appended to history.jsonl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub entry: String,
    pub interface_index: usize,
    pub kind: String,
    pub url: String,
    pub passed: bool,
    /// HTTP status if an answer arrived.
    pub status: Option<u16>,
    pub latency_ms: u64,
    pub detail: String,
    /// RFC 3339 UTC, stamped at execution.
    pub measured_at: String,
}

/// The visible gradient per interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gradient {
    /// No probe declared, or declared but never executed.
    NeverChecked,
    Passed {
        measured_at: String,
    },
    Failed {
        measured_at: String,
    },
}

impl Gradient {
    pub fn label(&self) -> &'static str {
        match self {
            Self::NeverChecked => "never checked",
            Self::Passed { .. } => "passed",
            Self::Failed { .. } => "failed",
        }
    }
}

pub const HISTORY_FILE: &str = "history.jsonl";

/// Appends records to the state directory's history (creates it).
pub fn append(state_dir: &Path, records: &[Record]) -> Result<()> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating {}", state_dir.display()))?;
    let mut out = String::new();
    for record in records {
        out.push_str(&serde_json::to_string(record).context("serializing record")?);
        out.push('\n');
    }
    let path = state_dir.join(HISTORY_FILE);
    let mut existing = std::fs::read_to_string(&path).unwrap_or_default();
    existing.push_str(&out);
    std::fs::write(&path, existing).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Loads the full history; a missing file is an empty history.
pub fn load(state_dir: &Path) -> Result<Vec<Record>> {
    let path = state_dir.join(HISTORY_FILE);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(_) => return Ok(Vec::new()),
    };
    let mut records = Vec::new();
    for (number, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        records.push(
            serde_json::from_str(line)
                .with_context(|| format!("{}:{}: malformed record", path.display(), number + 1))?,
        );
    }
    Ok(records)
}

/// Gradient for one interface: the LATEST record wins (records are
/// appended in execution order; ties resolved by position).
pub fn for_interface(history: &[Record], entry: &str, interface_index: usize) -> Gradient {
    let latest = history
        .iter()
        .rfind(|r| r.entry == entry && r.interface_index == interface_index);
    match latest {
        None => Gradient::NeverChecked,
        Some(r) if r.passed => Gradient::Passed {
            measured_at: r.measured_at.clone(),
        },
        Some(r) => Gradient::Failed {
            measured_at: r.measured_at.clone(),
        },
    }
}
