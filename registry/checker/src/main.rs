//! CLI for the checker core (L1.2).
//!
//! Usage:
//!   oh-check <manifest-dir>... [--state <dir>] [--run]
//!            [--badges <dir>] [--timeout-ms <n>]
//!            [--probe-origin <origin>]
//!
//! Without `--run`: prints the probe plan and each interface's
//! current gradient (from `--state` history if given) — no network.
//! With `--run`: executes every declared probe, appends to the
//! append-only history and (with `--badges`) writes one shields.io
//! endpoint JSON per entry.
//!
//! AUTHORIZATION BOUNDARY (E21 spirit / E13 consent ladder): `--run`
//! fires real requests. Use against own infrastructure and local
//! test servers freely; against third-party endpoints only under
//! the declared conditions.

use std::path::PathBuf;
use std::process::ExitCode;

use oh_check::{badge, gradient, model, probes, time};

const USAGE: &str = "usage: oh-check <manifest-dir>... [--state <dir>] [--run] \
[--badges <dir>] [--timeout-ms <n>] [--probe-origin <origin>]\n       oh-check \
--facades <origin>... [--require-served] [--timeout-ms <n>]";

/// The daily facade check (AQ): the platform's OWN origins, probed
/// with the real prober and judged against the runbook §3 content-type
/// plan.
///
/// **The two outcomes that are NOT the same thing.** An origin that
/// does not answer at all is «not served yet» — the site goes live on
/// allocation day, and before that a red job would only be noise. An
/// origin that answers with the wrong content type is a defect. So the
/// first prints a loud WAITING banner naming what it waits for, and
/// the second fails.
///
/// `--require-served` collapses the distinction: unreachable becomes a
/// failure. That flag is what the daily schedule gains once the
/// origins exist, and it is the reason this cannot quietly stay green
/// forever — the wire suite's false green taught that a skip nobody
/// can switch off is a lie.
fn facades(origins: &[String], require_served: bool, timeout_ms: u64) -> ExitCode {
    let mut unreachable = Vec::new();
    let mut defects = Vec::new();
    let mut served = 0usize;

    for origin in origins {
        println!("== {origin}");
        for item in probes::FACADE_SET {
            let outcome = probes::facade(origin, item, timeout_ms);
            let mark = match outcome.state {
                probes::FacadeState::Absent => "WAITING",
                probes::FacadeState::Correct => "ok",
                probes::FacadeState::Defect => "FAIL",
            };
            println!("  {mark:<8} {} — {}", item.path, outcome.detail);
            match outcome.state {
                probes::FacadeState::Absent => unreachable.push(outcome.url),
                probes::FacadeState::Correct => served += 1,
                probes::FacadeState::Defect => {
                    defects.push(format!("{}: {}", outcome.url, outcome.detail))
                }
            }
        }
    }

    println!(
        "\nfacades: {served} correct, {} defect(s), {} not deployed yet",
        defects.len(),
        unreachable.len()
    );
    if !defects.is_empty() {
        eprintln!("FACADE DEFECTS — the origin answers and the answer is wrong:");
        for defect in &defects {
            eprintln!("  {defect}");
        }
        return ExitCode::FAILURE;
    }
    if !unreachable.is_empty() {
        if require_served {
            eprintln!(
                "FACADES NOT SERVED and --require-served was given: {} URL(s) are absent",
                unreachable.len()
            );
            return ExitCode::FAILURE;
        }
        eprintln!(
            "WAITING, out loud: {} facade URL(s) are not deployed yet. The site goes live on \
             allocation day (how-to/launch-runbook.md §2); until the origins are served this \
             check has nothing to measure. Add --require-served to the daily schedule the day \
             they exist — a check that cannot fail is not a check.",
            unreachable.len()
        );
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> anyhow::Result<ExitCode> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    // The facade mode is its own thing: no manifests, no state, no
    // badges — the platform's own origins and the runbook's plan.
    if let Some(pos) = args.iter().position(|a| a == "--facades") {
        args.remove(pos);
        let require_served = args
            .iter()
            .position(|a| a == "--require-served")
            .map(|at| {
                args.remove(at);
                true
            })
            .unwrap_or(false);
        let timeout_ms: u64 = match args.iter().position(|a| a == "--timeout-ms") {
            Some(at) => {
                let value = args.remove(at + 1);
                args.remove(at);
                value
                    .parse()
                    .map_err(|_| anyhow::anyhow!("--timeout-ms takes milliseconds"))?
            }
            None => 8000,
        };
        if args.is_empty() {
            anyhow::bail!("--facades needs at least one origin");
        }
        return Ok(facades(&args, require_served, timeout_ms));
    }

    let mut take_value = |flag: &str| -> anyhow::Result<Option<String>> {
        if let Some(pos) = args.iter().position(|a| a == flag) {
            if pos + 1 >= args.len() {
                anyhow::bail!("{USAGE}");
            }
            let value = args.remove(pos + 1);
            args.remove(pos);
            Ok(Some(value))
        } else {
            Ok(None)
        }
    };

    // Local-instance probing (BF). Replaces the ORIGIN of every probe
    // URL, so a manifest that declares the public endpoint can be
    // probed against a local one without editing the manifest — which
    // the schema forbids anyway (`^https://`), and which would be the
    // wrong fix: an entry's declaration is the entry's declaration.
    //
    // WHY THIS IS NOT A WAY TO LIE. The record carries `url` — the URL
    // that was ACTUALLY probed — and every surface that shows a check
    // shows that URL beside it. A result obtained against 127.0.0.1
    // therefore says so wherever it is displayed; it cannot be passed
    // off as evidence about the public endpoint.
    let probe_origin = take_value("--probe-origin")?;
    let state_dir = take_value("--state")?.map(PathBuf::from);
    let badges_dir = take_value("--badges")?.map(PathBuf::from);
    let timeout_ms: u64 = take_value("--timeout-ms")?
        .map(|v| v.parse())
        .transpose()
        .map_err(|_| anyhow::anyhow!("--timeout-ms takes milliseconds"))?
        .unwrap_or(8000);
    let execute = if let Some(pos) = args.iter().position(|a| a == "--run") {
        args.remove(pos);
        true
    } else {
        false
    };
    if args.is_empty() {
        eprintln!("{USAGE}");
        return Ok(ExitCode::from(2));
    }

    let mut plan = model::plan(&args)?;
    if let Some(origin) = &probe_origin {
        let origin = origin.trim_end_matches('/');
        for item in &mut plan {
            if let Some(probe) = &mut item.probe {
                probe.url = rewrite_origin(&probe.url, origin);
            }
        }
    }
    let plan = plan;
    let mut history = match &state_dir {
        Some(dir) => gradient::load(dir)?,
        None => Vec::new(),
    };

    if execute {
        let mut records = Vec::new();
        for item in &plan {
            let Some(probe) = &item.probe else { continue };
            let outcome = probes::execute(probe, timeout_ms);
            println!(
                "{} #{} {} {} → {} ({} ms; {})",
                item.entry,
                item.interface_index,
                probe.kind.as_str(),
                probe.url,
                if outcome.passed { "passed" } else { "FAILED" },
                outcome.latency_ms,
                outcome.detail
            );
            records.push(gradient::Record {
                entry: item.entry.clone(),
                interface_index: item.interface_index,
                kind: probe.kind.as_str().to_string(),
                url: probe.url.clone(),
                passed: outcome.passed,
                status: outcome.status,
                latency_ms: outcome.latency_ms,
                detail: outcome.detail,
                measured_at: time::epoch_to_rfc3339(time::now_epoch()),
            });
        }
        if let Some(dir) = &state_dir {
            gradient::append(dir, &records)?;
        }
        history.extend(records);
    } else {
        for item in &plan {
            let g = gradient::for_interface(&history, &item.entry, item.interface_index);
            println!(
                "{} #{} {} — {} — {}",
                item.entry,
                item.interface_index,
                item.interface_type,
                match &item.probe {
                    Some(p) => format!(
                        "{} {} (expect {})",
                        p.kind.as_str(),
                        p.url,
                        p.expect.as_str()
                    ),
                    None => "NO PROBE DECLARED".to_string(),
                },
                g.label()
            );
        }
    }

    if let Some(dir) = &badges_dir {
        std::fs::create_dir_all(dir)?;
        let mut entries: Vec<&str> = plan.iter().map(|i| i.entry.as_str()).collect();
        entries.dedup();
        for entry in entries {
            let gradients: Vec<gradient::Gradient> = plan
                .iter()
                .filter(|i| i.entry == entry)
                .map(|i| gradient::for_interface(&history, entry, i.interface_index))
                .collect();
            let mut out = serde_json::to_string_pretty(&badge::shields_json(entry, &gradients))?;
            out.push('\n');
            std::fs::write(dir.join(format!("{entry}.json")), out)?;
        }
    }

    let failed = plan
        .iter()
        .filter(|i| {
            matches!(
                gradient::for_interface(&history, &i.entry, i.interface_index),
                gradient::Gradient::Failed { .. }
            )
        })
        .count();
    println!(
        "plan: {} interface(s), {} with probes; gradient: {} failed",
        plan.len(),
        plan.iter().filter(|i| i.probe.is_some()).count(),
        failed
    );
    Ok(if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Replaces the scheme+authority of `url` with `origin`, keeping path
/// and query.
///
/// Used only by `--probe-origin`, and deliberately dumb: it does not
/// parse, it splits at the third slash. A URL it cannot understand is
/// returned unchanged rather than mangled — the probe then targets what
/// the manifest declared, which is the safe direction to fail in.
fn rewrite_origin(url: &str, origin: &str) -> String {
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return url.to_string();
    };
    match rest.split_once('/') {
        Some((_authority, path)) => format!("{origin}/{path}"),
        None => origin.to_string(),
    }
}

#[cfg(test)]
mod origin_tests {
    use super::rewrite_origin;

    /// The path survives; the host does not.
    #[test]
    fn the_path_is_kept_and_the_origin_replaced() {
        assert_eq!(
            rewrite_origin(
                "https://mcp.openhelvetia.swiss/mcp",
                "http://127.0.0.1:8781"
            ),
            "http://127.0.0.1:8781/mcp"
        );
        assert_eq!(
            rewrite_origin("https://example.test", "http://127.0.0.1:1"),
            "http://127.0.0.1:1"
        );
    }

    /// Something that is not an http(s) URL is left alone rather than
    /// mangled into a plausible-looking wrong one.
    #[test]
    fn an_unparsable_url_is_returned_unchanged() {
        assert_eq!(
            rewrite_origin("ftp://x/y", "http://127.0.0.1:1"),
            "ftp://x/y"
        );
    }
}
