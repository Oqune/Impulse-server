# Defense readiness audit and remediation

Date: 2026-10-13 (Europe/Moscow). Owner authorization: full audit, lighter-model subagents, emulator testing, independently reviewed fixes, documentation, atomic commits and GitHub push. Preserve existing functionality and source school/video materials.

## Scope and invariants

Audit current Android and Rust repositories, project instructions/skills/documentation, written school project and video claims. Do not change Wire v3, cryptographic algorithms/parameters, or publish personal media/secret files. Existing findings are leads, not current test evidence. Production readiness is an evidence-based conclusion, not a promised label.

## Plan and resource budget

1. Baseline git branches, revisions, versions, release rules and toolchain (45 minutes).
2. Three read-only lighter-model audits: Android, Rust, and claims/docs (1–2 hours alongside baseline gates).
3. Build/test/lint/clippy; two Android emulator clients plus actual local relay where available.
4. Functional, negative, reconnect/offline, lifecycle and bounded stress/soak scenarios (2–3 hours including focused remediation).
5. Each confirmed fix gets a focused SPEC, regression evidence and root-agent diff review. No subagent commits/pushes.
6. Repeat affected gates; create separate change register and readiness/claims reports including DOCX in school-project (1–2 hours).
7. Commit and push only reviewed, passing changes. Determine patch releases from actual code changes and verified artifacts; follow bilingual architecture/link release-note rules.

At most three subagents, no overlapping writes. Reserve at least 25% of remaining account capacity for root review and delivery. Check usage at phase boundaries, narrow redundant scans before required validation, persist checkpoints. Duration and capacity are estimates, not guarantees. Long retention, real-device coverage and independent cryptographic assessment must remain explicitly unverified unless actually performed.

## Scenario matrix

- Fresh launch/onboarding, settings, navigation, visual regressions.
- Actual QUIC connection, valid/invalid auth, pin trust/mismatch, key exchange.
- Direct and shared messages between two clients, persistence/signature verification.
- Disconnect/reconnect, offline sync, duplicate/replay, process/server restart, background/foreground.
- Malformed/truncated/oversized frames, auth timeout/rate caps, bounded multi-client load.
- Local database/pinning instrumentation tests; release-build and architecture limits.

Each result records revision, environment, command/scenario, timestamp, actual outcome, artifact reference and limits. Untested scenarios cannot be marked PASS.

## Acceptance

Client assembleDebug, testDebugUnitTest and lintDebug; server build, test and clippy with warnings denied. Independently inspect every changed diff. Existing source materials retained; all changes separately documented. No known unresolved critical defect may be hidden by a production-ready claim. Release links and version identifiers must describe artifacts that actually exist.

## Baseline

Client 1dd288a on docs/verified-capabilities, version 3.2.0/code 23. Server 0c19471 on docs/verified-capabilities, version 3.1.0. Both clean. One available AVD Impulse_API_36, no connected device at start. Account window use at baseline: 1% five-hour and 3% weekly.
