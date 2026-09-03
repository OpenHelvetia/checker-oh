# Registry entries

<!-- language: English -->

**Admission routes (E21, revised 2026-09-03).** A data source enters
the directory on one of three routes: self-publication, entry takeover,
or documented consent.

**The association's own infrastructure is always an entry** (E21
Nachtrag 02.09.2026): its manifests are listed by the association itself,
route no. 1, as soon as they pass the four-stage chain — not
conditional on a publicly answering endpoint. What the directory says
about them is measured: «never checked» until the first recorded probe,
then passed or failed with instant, probe and address.

Listed today:

- `openhelvetia-fedlex-mcp.json` — the MCP interface to Fedlex behind the
  platform gateway (entry no. 1, prepared 26.08.2026, listed 02.09.2026)
- `openhelvetia-lindas-mcp.json` — the MCP interface to LINDAS behind the
  same gateway (entry no. 2, prepared 30.08.2026, listed 02.09.2026)

Every file placed here runs the full validation chain (oh-validate
stages 1–4, pre-commit gate) and the same canonical-form rules as the
test corpus — wherever a manifest lives, the same rules apply
(DIRECTORY.md §4). The field-by-field grounds and the gated tool tables
of the two own entries stay in `registry/standard/own-entry-draft/README.md`.
