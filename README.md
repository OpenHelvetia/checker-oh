# checker-oh

> **Kurz auf Deutsch.** `oh-check` prüft, ob ein Verzeichniseintrag hält, was sein Manifest deklariert: Es feuert genau die kleine, unschädliche Probe, die das Manifest selbst nennt, hängt jedes Ergebnis an eine nur wachsende Historie an und leitet daraus die drei Zustände ab, die die Website zeigt — nie geprüft, bestanden, gescheitert. Anleitung unten auf Englisch.

**checker-oh** is the verification tool of the association [OpenHelvetia](https://openhelvetia.swiss). A manifest in the directory declares, per interface, a probe: the minimal harmless call that proves the interface is alive (`kind → expect`). `oh-check` reads those probes, fires exactly them, and appends one line per run to an append-only history. From that history the website reads three states — never checked, passed, failed — and renders a badge. Corrections are new lines, never edits to old ones.

---

## Contents

1. [Before you start](#1-before-you-start)
2. [Get it running in five minutes](#2-get-it-running-in-five-minutes)
3. [What a probe is, and the five kinds](#3-what-a-probe-is-and-the-five-kinds)
4. [Command-line flags](#4-command-line-flags)
5. [The history and the states](#5-the-history-and-the-states)
6. [What is in this repository](#6-what-is-in-this-repository)
7. [How it is verified](#7-how-it-is-verified)
8. [When something does not work](#8-when-something-does-not-work)
9. [Where this repository comes from](#where-this-repository-comes-from)
10. [Contributing, security, licence](#contributing-security-licence)

---

## 1. Before you start

| Need | Why | How to get it |
|---|---|---|
| **Rust, stable** (rustc and cargo) | everything here is built from source | <https://rustup.rs> — one command, then open a new terminal and run `cargo --version` |
| **Git** | to clone this repository | macOS: `xcode-select --install`; Linux: your package manager; Windows: <https://git-scm.com> |

The tests need no network. Linux and macOS are what the association builds on; Windows works in principle, use WSL if in doubt.

## 2. Get it running in five minutes

**Clone**

```bash
git clone https://github.com/OpenHelvetia/checker-oh.git
cd checker-oh
```

**Run the tests** (offline; the HTTP cases start local servers on 127.0.0.1 inside the test)

```bash
cargo test --locked --manifest-path registry/checker/Cargo.toml
```

**Read the probes of the shipped manifests without firing them** — a dry listing of what would be checked:

```bash
cargo run --locked --manifest-path registry/checker/Cargo.toml -- registry/standard/test-corpus registry/entries
```

What you should see: one line per interface, naming the entry, the interface type and its declared probe.

**Fire the probes** — this talks to the declared endpoints on the network, one harmless call each, and writes the history:

```bash
cargo run --locked --manifest-path registry/checker/Cargo.toml -- registry/entries --run --state ./state --badges ./badges
```

`./state` receives the append-only history, `./badges` one badge document per entry.

## 3. What a probe is, and the five kinds

A probe is declared in the manifest, next to the interface, as `kind` and `expect` (and an optional `target` when the probe URL differs from the endpoint). The checker never invents a call; it fires the one that was declared.

| Kind | What is sent | Passes when |
|---|---|---|
| `sparql-ask` | a SPARQL `ASK` query | the endpoint answers a boolean result document |
| `http-get` | a GET | the expected evidence arrives: `ok` (2xx), or `response` (any HTTP answer proves liveness, bot walls included) |
| `http-head` | a HEAD | as above |
| `mcp-initialize` | an MCP `initialize` handshake | the server answers the handshake |
| `mcp-discover` | an MCP `server/discover` (the stateless era of the protocol) | the server answers the discovery |

Two MCP kinds exist because MCP has two eras, and a call in the wrong era proves nothing.

## 4. Command-line flags

`oh-check <manifest-dir>... [--state <dir>] [--run] [--badges <dir>] [--timeout-ms <n>] [--probe-origin <origin>]`

| Flag | Meaning |
|---|---|
| `<manifest-dir>...` | one or more folders of manifests to read |
| `--run` | actually fire the probes; without it the checker only lists them |
| `--state <dir>` | where the append-only history lives (one JSONL file per entry) |
| `--badges <dir>` | write one badge document per entry (shields.io endpoint format) |
| `--timeout-ms <n>` | per-probe timeout |
| `--probe-origin <origin>` | the origin the checker announces in its User-Agent, so an operator can see who is probing |

## 5. The history and the states

The history is append-only JSONL: one line per run with instant, probe, address and outcome; the youngest line wins; nothing is ever rewritten. From it follow three states per interface — **never checked** (no line yet), **passed**, **failed** — and per entry the badge aggregates them into four messages: failed, passed, partially checked, never checked. A listing state machine sits on top for signature drift: listed, re-verification due, grace, quarantine — grace escalates after 14 days, and there is deliberately no state «removed»: delisting is a registry act, never automatic.

## 6. What is in this repository

| Path | What |
|---|---|
| `registry/checker/` | the tool: sources and tests (the HTTP cases against a local server) |
| `registry/standard/card/sign/` | the signing crate the checker's signature-drift logic depends on |
| `registry/standard/test-corpus/`, `examples/` | 19 real-world manifests and two examples the tests read |
| `registry/entries/` | the directory's real entries |
| `LICENSE`, `NOTICE` | Apache-2.0 and the attributions |

## 7. How it is verified

41 tests, all offline: the HTTP probe kinds run against a real local server on 127.0.0.1 started by the test; the SPARQL and MCP kinds against recorded answers; the history's append-only rule, the three states and the four badge messages are each pinned. In the corpus's commit gate not a single network request runs.

## 8. When something does not work

| You see | What it means | What to do |
|---|---|---|
| `error: package … requires rustc 1.xx` | your Rust is too old | `rustup update stable` |
| a listing but no state files | you did not pass `--run` | add `--run` and `--state <dir>` |
| every probe `failed` in `--run` | no network, or the endpoints refuse the probe | check connectivity; a refusal is a recorded failure, not a crash |
| an entry shows «never checked» on the website | no history line exists for it yet | that is the honest state until a run is recorded |

## Where this repository comes from

The association develops all its modules in one corpus, on its own GitLab, where every change runs through a gate (formatting, Clippy without warnings, all tests, seal and drift checks). This repository is **assembled from that corpus** by the publication lane (`tools/publish-module.sh` there): it takes the crates and exactly the files their builds and tests need, runs the tests in the assembled tree, and pushes here. Each publication is one commit whose message names the corpus commit.

This copy was published from corpus commit `9a70151` on 2026-09-03.

## Contributing, security, licence

- **Issues** here are welcome: a wrong result, a missing case, an unclear sentence in this README. Please include the command you ran and what came back.
- **Changes** go through the corpus and arrive here with the next publication; a pull request here is read and carried over by hand.
- **Security reports**, in confidence: security@openhelvetia.swiss. The association answers within a working week.
- **Licence:** Apache-2.0 (`LICENSE`, attribution in `NOTICE`).
