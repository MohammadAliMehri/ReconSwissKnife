# Refactoring plan after 3.1.0

## Goal and constraints

Keep `ReconSwissKnife_v3.py` installable as one Python extension in Burp with Jython 2.7. Preserve existing passive rules, Iranian-specific detectors, JavaScript analysis, native popups, AI approval, and request/response provenance. Refactoring must preserve observable behavior before adding new detection rules. A Java migration is outside this plan.

3.1.0 delivers the UI redesign, shared table/selection helpers, stable selection during refresh, coalesced Swing refresh requests, and deduplicated method/header observations. It remains a single source file; the phases below are planned work.

## Completed foundation refactoring

- Extracted pure helpers to `recon/core/` and `recon/ai/`; the Burp message adapter delegates context formatting to the pure core.
- Moved remaining implementation to `recon/burp/extension.py` as the development entry point.
- Added `tools/bundle.py` to deterministically generate the standalone installation artifact with an explicit dependency order and a stale-artifact check.
- Captured 36 pre-extraction baseline cases and added tests for module/artifact parity, pure CPython/Jython operation, bundler constraints, and isolated single-file installation.
- Added `tools/verify.py` to run both entry points through the existing regression suite.

This completes the suggested first refactoring change below. The lifecycle characterization, detector/store extraction, structured finding contract, storage limits and incremental views remain staged future work. No claim is made that all phases or manual Burp acceptance are complete.

## Phase 1 — Characterize boundaries (3.1.x)

- Add fixtures for request/response parsing, all existing detection rules, relative script URLs, and multi-host scope changes. Include benign responses and false positives.
- Cover lifecycle races: clear while work is queued, unload during an AI request, scope removal before a queued request, and failed/rejected tasks becoming retryable.
- Expand the synthetic Swing renderer to narrow widths and light/dark Burp themes; test selection after sorting/filtering and keyboard-only navigation.
- Define a structured finding contract: ID, category, severity, confidence, evidence location, source message, verification state, and timestamps. Map old rows without changing their meaning.

Exit: a documented behavior matrix and passing Jython tests protect the existing workflow. A current Burp smoke test confirms capture, history import, native viewers, Repeater, probing and cancellation.

## Phase 2 — Separate analysis from Burp and Swing (3.2.0)

Proposed development modules:

```
recon/
  core/       # URL normalization, redaction, detectors, finding schema
  storage/    # Thread-safe store, identity, deduplication, snapshots
  burp/       # Callback adapter, message persistence, scope, Repeater
  network/    # Queued tasks, rate limits, cancellation, result events
  ai/         # Provider transport, protocol validation, reviewed context
  ui/         # Theme, table models, selection, inspector, AI workflow
```

- Start with pure functions; give analyzers explicit inputs and return findings rather than mutating Swing/store objects.
- Inject a small Burp adapter, clock, transport and logger. Detectors must not import Swing or send requests.
- Retain original message references through explicit message IDs. Keep secrets out of logging and provider configuration persistence.
- Add a deterministic bundling step producing the single installation file. Test both module sources and the bundled artifact; never maintain two independent implementations. Generate sections in a declared dependency order and verify artifact imports in Jython.

Exit: equivalent findings on the fixture corpus, one installable file, and no runtime module-path setup for users.

## Phase 3 — Bound storage and make lifecycle explicit (3.2.x)

- Introduce configurable limits for messages, findings, body snapshots and deduplication state. Document eviction and preserve evidence needed by visible findings.
- Use stable IDs based on canonical URLs, method and relevant evidence; retain separate observations for different sessions when their behavior differs.
- Replace scattered sets and mutable lists with store methods returning immutable snapshots or row deltas.
- Track each job as queued/running/completed/failed/cancelled. Add a workspace generation ID so clearing cannot repopulate the workspace with stale results.
- Apply scope checks immediately before sending, share per-host rate limits, and prevent active responses from creating uncontrolled follow-up work.

Exit: stress tests demonstrate bounded memory and queues; no stale results after clear/unload; cancellation and retry have reproducible semantics.

## Phase 4 — Update views incrementally (3.3.0)

- Replace full table rebuilds with batched insert/update/remove events on the Swing EDT.
- Keep selection, sort order, scroll position and filters by stable finding/message ID.
- Introduce an investigation controller for selection and actions; views render state and dispatch commands.
- Improve the inspector with evidence locations, severity/confidence explanations and verification notes. Keep full native request/response viewers one action away.
- Add structured AI results linked to source messages; preserve strict separation between model hypotheses and verified findings.

Exit: replay a fixed large traffic fixture while sorting, filtering and selecting; record UI update latency and allocations against 3.1.0 before choosing a performance target.

## Phase 5 — Release hardening

- Build and test on a documented Jython/JDK/Burp compatibility matrix.
- Add CI for core tests, adapter tests, local-provider protocol/error tests and bundled-artifact import.
- Document provider settings, limitations, data sharing and migration. Keep user keys out of fixtures, screenshots and releases.
- Run manual acceptance with a disposable local application and a local compatible model. Publish only the tested Python artifact and its checksum after review.

## First refactoring change (implemented)

Extract redaction, URL validation and AI schema validation into pure development modules, add equivalence fixtures, and introduce the single-file bundler. This is small enough to review without simultaneously rewriting storage, networking and the UI.
