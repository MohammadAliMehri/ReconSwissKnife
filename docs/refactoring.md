# Refactoring roadmap — regex and active review

## Current state (3.2.1)

The single-file Python artifact is generated from modular development sources. Pure extraction and evidence helpers live under `recon/core/`; remaining store, Burp, task and UI integration is in `recon/burp/extension.py`. The provider/AI modules have been removed.

Completed foundations: deterministic bundler, source/artifact equivalence, isolated installation checks, explicit list/card navigation, coalesced refresh, selected-row preservation, regex parameter evidence, PII checksums, bounded selected scans, scope rechecks and generation-based cancellation of selected scans/access comparisons.

## Next: message identity and storage

- Extract storage behind a tested interface with immutable snapshots and stable message/finding IDs.
- Retain separate request/session variants for the same URL; preserve owner/comparison provenance without showing raw credentials in summaries.
- Bound endpoints, message buffers, legacy findings and deduplication sets; document eviction.
- Extend generation-safe cancellation to legacy JS fetch, OPTIONS/HEAD and method-test jobs.

## Next: dedicated scan profiles

- Separate active transport, task lifecycle and rule evaluation from Swing and callbacks.
- Keep IDOR decisions tied to explicit expected ownership/role rules and supplied identities. Add normalized protected-field comparisons while preserving raw evidence.
- Expand XSS analysis to context-specific reflection locations and browser-verification handoff, with fixtures for encoded, JSON, script and attribute contexts.
- Add user-defined business-logic test cases with prerequisites, expected outcomes and state assertions. Require explicit execution for state-changing requests.
- Extend PII rules through a versioned catalog with validators, positive/negative fixtures and response-location evidence.

## Next: incremental views and compatibility

- Replace full table reconstruction with batched row deltas keyed by stable IDs.
- Preserve sort, selection, scroll and filters during updates.
- Test category navigation and evidence actions under current Burp light/dark themes and narrow viewports.
- Add CI for pure-core, real Jython/Swing, loopback scan fixtures and the generated artifact. Keep single-file Burp installation.

## Release acceptance

Run `tools/verify.py`, then load the generated Python file in a current Burp instance. Check passive extraction, all result categories, compression status, authenticated access comparison, scoped scanning, cancellation and Repeater evidence against a disposable local application. A status code, regex hit or reflected marker alone must never be labeled a confirmed exploit.
