# Separate audit change register

All changes preserve Wire v3 opcodes/layout and cryptographic minimums. No source school document or personal video is replaced. Each implementation change has a focused SPEC in its component repository. Historical reports remain historical; `2026-10-14-defense-readiness.md` is the current verdict.

| Area | Problem and correction | Specification and verification |
| --- | --- | --- |
| Server session lifecycle | Handler errors now fail closed; stream-open/auth deadlines absolute; authenticated sessions retain idle behavior; both listeners receive shutdown | relay-resource-lifecycle-hardening; real QUIC rejection and >30s heartbeat tests |
| Server retained resources | Aggregate storage 64 MiB/10k/72h; bounded Sync snapshot pages and permit lifetime; operation/write deadlines; key cache 16/64 KiB/session | relay-resource-lifecycle-hardening; count/byte/page/deadline/drop regressions |
| Server auth configuration | Parse/validate PHC before startup; advertise exact supported tuple, generic failure without hash disclosure | auth-parameter-consistency; non-default HMAC/challenge tests |
| Android authentication | Strict Argon2id floor and ceiling, malformed/duplicate/unknown tag rejection | auth-outbox-instrumentation-hardening; JVM parser and actual derivation tests |
| Android outbound reliability | Retain failed encrypted frames, idempotent restore, per-server persistence and atomic flush ownership | auth-outbox-instrumentation-hardening and outbox-flush-atomic-guard; retry/restore regressions |
| Android stored history | Require valid sender signature and signed routing, reject missing keys/tampered metadata | history-signature-verification; actual Bouncy Castle signature tests |
| Android replay | Additive Room6 journal, global sender+SHA256 nonce, atomic message+marker, expiry and fail-closed capacity; preserve existing rows/history clear markers | persistent-replay-journal SPEC; device migration/reopen/rollback/cap/duplicate tests |
| Android receive pressure | Suspend callback and serial DATA/Sync/key exchange; bounded unknown-key queue and cancellation | inbound-backpressure; queue accounting tests and actual paired flood |
| Android connection identity | Bind callbacks/auth/outbox and message sends to origin transport/server/generation | connection-generation-guards; independent diff review and final live/lifecycle checks |
| Android session lifetime | The pinned library timeout enclosed the entire read-loop callback and cut active sessions at 300 seconds; remove that lifetime deadline and make the 15s setup deadline cancel the setup coroutine | webtransport-session-lifetime; failed initial soak retained, real non-responsive endpoint rejected at 15.154s, corrected bounded soak required |
| Android lifecycle | Retained rotation unlock, real background relock, connect only after unlock, reject late callback while stopped | biometric-background-relock; actual device credential/UI flow |
| Supported runtime / labels | x86_64 emulator QUIC allowed by native ABI; x86 rejects safely; Dilithium3 labels and accurate reset text | supported-emulator-transport and ui-capability-labels; ABI JVM and actual signed release UI |
| Build contract | R8 9.1.29 from official Maven for Kotlin2.4; Rust1.88 dependency floor; candidates3.2.1/code24 and3.1.1, stale RPM version aligned | kotlin24-r8-override, rust-toolchain-contract, audit-patch-release; selected mapping/signature/MSRV/full gates |
| Documentation / release | Actual architecture/privacy/KDF/versions in instructions and registry; reviewed bilingual notes and draft workflow; signed-asset-only release job | project-docs-alignment and audit-patch-release; root mirror/hash/diff and published asset review |

Project-local skills were searched for and none found. Global personal skills were not edited. Original school DOCX/video hash preservation and a separate school report document discrepancies without silently rewriting submitted material. No personal video, passwords, PHC from local configuration, keystore, certificate key or local test logs are committed.
