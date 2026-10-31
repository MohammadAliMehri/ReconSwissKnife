# 3.2.1 — Persian / Iranian regex catalog and repository cleanup

- Add Persian/Arabic-Indic digit normalization, encoded Persian evidence and locale-aware PII rules.
- Add grouped Sheba, known-prefix/Luhn Iranian cards, landlines and context-labeled postal codes.
- Add Persian parameter-name decoding and IDOR/XSS/logic/PII hints.
- Decode byte-preserving Burp text using response charset/UTF-8 before extraction.
- Preserve original matched values and avoid duplicate generic card/phone rows for identical locale matches.
- Organize docs/images, remove superseded constants/helpers, add contributor instructions and cache cleanup tooling.

# 3.2.0 — Regex, IDOR/XSS review and PII

- Remove provider/AI code, settings and review actions.
- Fix inaccessible result categories with an explicit scrollable list/card navigator and direct Leaks/PII buttons.
- Refresh after each analyzed message; hide static endpoint noise by default.
- Add observed/candidate parameter extraction, path identifiers and access-control/XSS/business-logic focus hints.
- Add scoped selected-GET scans with reflection/escaping, fresh-baseline error differentials and CORS checks.
- Add two-session owner-baseline comparisons with operator-supplied expected access rules.
- Add dedicated PII results, checksum-validated card/IBAN matches, response-header scanning and bounded gzip/deflate decoding.
- Report unsupported compression and skipped out-of-scope activity; scan already-captured JavaScript directly.
- Preserve authentication, request identity encoding, enforce scope at send time and invalidate selected scans on cancellation/clear.
- Add disposable-target tests for access comparison, scanner boundaries, compression and visible PII results.

# Unreleased — Foundation refactoring

- Maintain pure helper modules separately from Burp/Swing code under `recon/`.
- Extract AI context formatting from the Burp message adapter without changing its output.
- Generate `ReconSwissKnife_v3.py` from a declared module order; keep single-file installation and the 3.1.0 runtime version.
- Add baseline-equivalence fixtures, build-tool checks, dual-entry-point regression execution and an isolated artifact smoke test.
- Document source ownership and the remaining refactoring stages.

# 3.1.0 — Investigation workflow redesign

- Replace the large dashboard with compact task controls, an always-visible summary and optional metrics.
- Add left-side result categories, a resizable selection inspector, explicit evidence/AI/Repeater actions and empty states.
- Add visible/total result counts, literal search with reset, full-value tooltips and readable column widths.
- Preserve selected rows on refresh and coalesce repeated Swing update requests.
- Deduplicate method/header observations across repeated traffic/history scans.
- Organize AI review into provider, outbound context and hypothesis steps; show context size and gate sending on a complete approved review.
- Fix literal Unicode escape labels and bump the Python extension to 3.1.0.
- Add UI regression checks, synthetic offscreen Swing previews and a staged refactoring roadmap.

# 3.0.0 — Python / Jython edition

- Remove the Java rewrite; retain the original single-file Burp extension.
- Add an AI review workspace with editable redacted context, local/hosted OpenAI-compatible providers, explicit send approval, schema/evidence validation and cancellation.
- Add context-menu actions for AI review and sending original requests to Repeater.
- Match scope filters by hostname and subdomain; require Burp scope for active requests.
- Replace status-code bypass claims with unverified observations and confirm risky-method fuzzing.
- Preserve original authentication for same-URL probes/fuzzing and original PUT/PATCH bodies.
- Parse cookie attributes, use context-aware header checks, resolve relative JS URLs, and expand AI/GitHub token patterns.
- Bound active task queues, space request starts, report network/queue failures, and permit retries of rejected fetch/probe jobs.
- Separate live capture from explicit history rescan; retain the original recon tables and native popups.
- Add Jython regression tests with real Swing and a local mock AI provider.
