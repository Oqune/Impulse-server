# Impulse defense readiness audit

Audit date: 13–14 October 2026, Europe/Moscow. Android device logs use UTC. Owner requested a full quality audit, lighter-model delegation, independent review, preservation of existing functionality/materials, separate documentation, signed atomic commits and GitHub push. Scope was narrowed at the explicit overnight pause and resumed after the account window reset.

## Verdict

The project remains a research prototype. Production readiness and suitability for critical infrastructure are not established. Functional results below apply to the tested build, devices and local network only. Findings in older reports, including historical production-ready wording, are not current evidence; this report is the current assessment without rewriting those historical sources.

No original school DOCX or authored video file was rewritten. A separate Russian DOCX in `school-project` compares claims against implementation and actual tests. Original file SHA-256 values are retained in the local preservation manifest and checked by the report builder. Project-local SKILL.md files were not found; global personal skills were preserved. Canonical project instructions, registry and policy mirrors were aligned with the actual code.

## Environment and revisions

- Independent repositories: Client baseline `1dd288a`, Server baseline `0c19471`; branch `fix/defense-readiness-audit`.
- Candidates Client 3.2.1 / versionCode 24 and Server 3.1.1, Wire v3. Candidate manifests are not proof of released tags/assets.
- Windows host, JDK 21, Rust 1.98.1. A separate locked Windows source build with Rust 1.88.0 passed; this is the declared dependency floor.
- Three Android API 36 x86_64 emulators. Original AVD data preserved; two audit-owned AVDs used for credential and signed-release verification.
- Actual local relay on UDP 4433, reachable through emulator host bridge `10.0.2.2`; certificate pinning, password authentication and cryptographic operations used real production APIs. Local test credentials/configuration, keys, video, logs, signing intermediates and binaries are not committed.
- Android uses Kotlin 2.4 / AGP 8.13 with official R8 9.1.29 override. The earlier R8 metadata warnings were diagnosed, not ignored; final mapping confirms the selected compiler.

## Evidence matrix

| Gate or scenario | Current evidence | Limits |
| --- | --- | --- |
| Rust locked build / release / all-target Clippy | PASS on final server source | Windows linker emits a non-failing import-library notice |
| Rust tests | 141 passed, 2 explicitly ignored | Ignored cases are existing client-side-only checks; helper simulations are not live routing tests |
| Rust 1.88 locked source build | PASS | Windows target only |
| Server protocol rejection, auth deadline, Sync paging/timeouts, permit cleanup | PASS; real QUIC heartbeat survives beyond 30 seconds, 5 MiB Sync split into bounded frames | Dual-listener shutdown fan-out tested at watch receiver level; no live dual-socket shutdown claim |
| Android full build/unit/lint/release | PASS on accepted guard build; 152 JVM tests, 0 failures, 0 skips | Lint has 0 errors, 100 warnings and 3 hints; predominantly dependency/style/packaging warnings |
| Android Room migration / journal / rollback / reopen / pin storage | 16 device tests PASS | Isolated test databases; legacy message content is not automatically replay-backfilled |
| Android wrong password, wrong pin, valid control | PASS against final server | Wrong-pin test uses a correct password and asserts no opened session; proves tested native QUIC path rejects mismatch |
| Two-client group + DM + receiver offline/reconnect/history | Earlier 10-message run PASS | 100-message delivery and ordered persisted history tested; callback ordering is not guaranteed across Sync/live interleaving. Corrected bounded soak still in progress |
| Signed minified APK | Installed and launched with real QUIC tunnel ONLINE; APK v2 signature verified | Final guard signed minified APK upgraded and tested; physical ARM devices untested |
| Biometric lock / rotation / foreground connection gate | PASS on final signed minified APK: real credential unlock, rotation without reprompt, observed launcher Home/resume with reprompt, Home during prompt then reprompt | No claim of forcing every possible callback interleaving; temporary test PIN cleared |
| Backup crypto / envelope / protocol / QR parsing / APK language switching | JVM suites exercised; actual release settings/navigation and English/Russian switching exercised | Camera scanning, real external backup storage and all UI branches are not comprehensively automated |

An initial active-session soak failed at 300 seconds: the pinned socket library applied its timeout to the entire callback/read loop. The patch removes that lifetime limit and cancels setup at the existing 15s deadline; the actual non-responsive endpoint test reached ERROR after 15.154s. A second flood check exposed an unsupported strict listener-order assumption under Sync/live interleaving. The fixture now checks exactly 100 unique deliveries and persisted chronological history, the UI source; the failed run is retained.

Raw command logs and screenshots remain local in `output/readiness-2026-10-13`. Opt-in device fixtures explicitly skip without real relay arguments. A build-only or skipped scenario is not counted as a runtime PASS.

## Independently reviewed corrections

Root reviewed all agent changes. A server regression that applied the auth deadline to authenticated connections was caught and corrected; real traffic beyond that deadline now has a regression test. Android queue tests initially failed compilation because generic types were not inferable; explicit fixture types corrected that before acceptance. A device suite attempted while the audit AVD user was credential-locked failed before tests; unlocking the owned device and repeating passed, so that failed run is retained as environment evidence rather than a PASS. R8 repository lookup initially failed at mirrors; official R8 Maven artifacts resolved successfully.

The lighter reviewer checked the durable replay transaction, additive migration, cancellation, buffer accounting, lock ordering, biometric lifecycle and lint findings. Root identified a stale successful biometric callback risk and required the STARTED check. Independent routing review found that outbox frames could reacquire a different global transport after a connection switch; generation/server/transport binding was added before final acceptance.

## Remaining production and demonstration limits

1. First-peer identity still uses TOFU. Self-attestation does not prove a human identity without out-of-band fingerprint verification. The relay sees network and outer packet metadata; Zero-Metadata is not claimed.
2. Current signature implementation is legacy Bouncy Castle Dilithium3, not verified ML-DSA-65/FIPS 204 conformance. No independent cryptographic audit or certification was performed. A dependency/build setting is not proof that hybrid PQ TLS was negotiated.
3. Delivery has no end-to-end ACK. Successful stream write does not prove recipient delivery. Outbox SharedPreferences.apply has a process-kill persistence window; exact-once delivery is not guaranteed.
4. Replay protection is local to one client store. Legacy envelopes without nonce bypass the durable journal; migrated historical rows have no automatic replay markers and may be accepted once. Capacity fails closed; new nonce messages can be unavailable at the journal limit.
5. Retained relay history is volatile and bounded by both count and bytes; 72-hour TTL is not a retention guarantee under pressure or server restart. Server sequence numbers and client cursor recovery across relay restarts require separate operational validation; this audit does not promise durable relay recovery.
6. Offline certificate rotation beyond overlap requires trusted rescan. No accelerated end-to-end certificate rotation or 72-hour/7-day soak was performed.
7. Actual runtime coverage is Windows amd64 server and API 36 x86_64 Android. ARM hardware, Linux services, WAN/VPN/mDNS/IPv6-specific topology, camera scanning, accessibility, localization bundles and sustained hostile load remain separately unverified.
8. The local demo must use a controlled LAN and verified certificate/peer fingerprints. Demonstrate group and DM, recipient disconnect and reconnect. Do not repeat unsupported latency/RAM/FPS or critical-infrastructure claims from older school text.

## Publication

Release notes are separate bilingual files with architecture and direct-link tables. Links are explicitly candidates until corresponding assets exist. Workflow drafts require committed reviewed notes; unsigned Android build artifacts cannot be published as signed APKs. Cross-platform packaging must pass before publication. GitHub PR/CI, final revision hashes, bounded soak results and release asset status are recorded at completion.
