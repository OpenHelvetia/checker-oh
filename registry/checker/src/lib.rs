//! `oh-check` — the checker core (masterplan L1.2): declared
//! liveness probes over the manifest corpus, the check gradient
//! («nie tief geprüft» ≠ «geprüft, bestanden», E14 Ziff. 3),
//! append-only history, and badge emission.
//!
//! The signature-drift states (grace/quarantine, E09-WP6b/f) are
//! built in `drift` on top of the L0.7 signing path: JCS hash
//! comparison of served card vs registry record, revocation via the
//! served JWKS, re-verification events for newly signed cards — a
//! state GRADIENT with no delisted state by design. Daily scheduled
//! runs ride on the CI build-out; until then the CLI is manual.
//!
//! **Seam, named and deliberately not wired: the auth flow (L2.6).**
//! `docs/reference/mcp-auth-gaps.md` verifies the two MCP
//! authorization gaps and names three probes that belong here once the
//! daily runs are scheduled and an authorization server exists:
//!
//! 1. the gateway's protected-resource metadata is reachable and its
//!    `resource` is the canonical identifier;
//! 2. the authorization server it names serves metadata whose `issuer`
//!    is identical to the issuer used to build the well-known URL —
//!    **this is the probe that would notice an AS migration**, which
//!    the MCP revision leaves without a detection trigger;
//! 3. no `registration_endpoint` is advertised, because Dynamic Client
//!    Registration is deprecated and its reappearance would be a
//!    decision nobody took.
//!
//! They would use the existing L0.8 probe vocabulary (`http-get`
//! expecting `response`); whether an auth-specific probe kind is worth
//! adding is a decision for the day they are wired, not before.
//!
//! **Seam, named by somebody else: skills conformance (L4.4).** The
//! AH slice built the skill profile and its conformance suite and
//! then handed THIS crate the half it could not do itself —
//! «declared versus observed in the daily checks». A skill profile
//! declares what a skill may do (`egress`, the signing mode, the
//! workload identity it will be bound to); nothing yet compares those
//! declarations against what a listed skill is observed to do, and
//! that comparison is a checker act, not a profile act.
//!
//! It is written down here because the AM reflection loop found it
//! written down only on the OTHER side: the report that delegated the
//! work said so, and the item that received it did not know. A seam
//! that only the sender can see is not a seam, it is a dropped
//! handover. The open itself lives in `docs/project/named-opens.md`,
//! which is the collection point for exactly this class.
//!
//! Nothing in this crate implements it, and that is deliberate: the
//! observation needs the daily runs (above) and a listed skill to
//! observe, and neither exists yet.

pub mod badge;
pub mod drift;
pub mod gradient;
pub mod model;
pub mod probes;
pub mod sectxt;
pub mod time;
