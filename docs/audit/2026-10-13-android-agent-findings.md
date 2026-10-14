# Android client audit — 2026-10-13

Scope: static read-only audit of `client/` for transport/authentication/pinning, key/signature handling, replay and offline delivery, local persistence, lifecycle, UI claims, and available test paths. Reviewed `client/AGENTS.md`, `client/docs/policies/ai_engineering.md`, `client/docs/policies/policies.md`, and `client/docs/VISION.md`. No builds or tests were run; no implementation files were changed during the audit. Findings below are based on current source, not prior audit claims.

## Severity summary

- **P0: none established by source review.**
- **P1: 3 items** — unbounded server-supplied KDF work, silent outbox loss, and unauthenticated first-contact peer identity (the last is a trust-model limit that the UI should expose clearly).
- **P2: 4 items** — replay cache lifetime/bounds, biometric unlock surviving backgrounding, history read path does not re-verify signatures, and Android instrumentation scenarios contain invalid setup/assertions.
- **Design/test limitations:** emulator transport rejection prevents QUIC E2E tests on AVDs; planned file, voice, and automatic discovery features are absent by design/roadmap, not broken existing functions.

## P1 findings

### P1 — Server-supplied Argon2 parameters have no upper bound

**Location:** [Protocol.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/transport/Protocol.kt:453), [Protocol.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/transport/Protocol.kt:254)

**Trigger:** A server that is trusted by the certificate pin (or compromised server) sends an AuthChallenge whose `m`, `t`, or `p` is an extremely large valid integer. Parsing only clamps each value upward to the OWASP floor (`m>=47104`, `t>=3`, `p>=1`); `buildAuth` passes those values to BouncyCastle Argon2 directly.

**Effect:** Authentication can allocate excessive memory or consume CPU on the main process, potentially causing an OOM/process crash or an extended unresponsive login. Transport pinning authenticates the server endpoint but does not make its resource claims safe. This is a client-side stability and fail-closed issue.

**Minimal fix:** Validate the full tuple against an explicit, documented admission range before storing it, reject the challenge/auth attempt if outside it, and retain the OWASP lower bound. The proposed ceiling from the coordinating review is `m=262144 KiB, t=10, p=4`; review whether that is appropriate for low-memory Android hardware. Do not clamp maliciously oversized values down silently if server/client derivation must match.

**Regression test:** Unit-test accepted defaults and floor values, accepted maximum tuple, and rejection above each ceiling / invalid encoding. Assert rejection occurs before Argon2 runs.

### P1 — Offline outbox discards messages after three send errors

**Location:** [ChatController.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/ChatController.kt:662), [ChatController.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/ChatController.kt:675)

**Trigger:** A send from `READY` fails once and is queued; `flushOutbox()` starts immediately. If the connection remains unable to send, three retry failures cause the entry to be removed from the in-memory queue and persisted outbox. A later reconnect cannot restore that entry.

**Effect:** A message that the app labels as queued can be silently lost after a short transient outage. The retry count is bounded but there is no delivery acknowledgement, dead-letter status, or durable error presented to the user. This contradicts the offline/reconnect reliability behavior implied by the outbox.

**Minimal fix:** Preserve the frame and return from the flush loop on transport failure; retry on the next READY/reconnect event. Keep durable queued state until a successful stream write or an explicit user action. If delivery acknowledgement is absent from Wire v3, avoid claiming the server has durably accepted the message; this fix must not alter the wire protocol.

**Regression test:** Exercise a queue entry against a fake send seam that fails beyond three attempts, assert it remains in memory/disk and is attempted after reconnect, then assert successful retry removes it. Include an interrupted flush/disconnect case.

### P1 — New peer identity is silently TOFU-trusted through the relay

**Location:** [Protocol.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/transport/Protocol.kt:404), [ChatController.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/ChatController.kt:1394), [ChatScreen.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/ui/screens/ChatScreen.kt:131)

**Trigger:** First message/key exchange from a peer whose DSA key is not cached. The client accepts a self-signature over `(KEM public key || DSA public key)` and caches that key without a user verification step. Only later key replacement must also be signed by the already-known key.

**Effect:** The signature proves key possession but does not bind the key to the human/contact name. A malicious or compromised relay can substitute an attacker's self-signed key on first contact; subsequent messages then verify correctly under that substituted key. The chat UI shows a generic PQ-E2EE shield and a short fingerprint, with no explicit “unverified first contact” state or compare/confirm step. This is a first-use trust limitation, not a failure of the server certificate pin or ML-DSA primitive.

**Minimal fix:** Treat this as a trust-model/product decision: distinguish TOFU/unverified keys from verified identities in UI and make the fingerprint comparison/verification path explicit before showing a verified badge. If peer QR verification is outside v3 scope, document the limitation and avoid implying human identity authentication.

**Test:** UI/state test for a newly seen self-signed key showing “unverified/TOFU”; test that a key change under a pinned peer key is rejected unless signed by the old key.

## P2 findings

### P2 — Replay cache is process-local and evicts after 2,000 nonces

**Location:** [ChatController.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/ChatController.kt:142), [ChatController.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/ChatController.kt:907)

**Trigger:** Restart the app/controller (cache starts empty), or receive enough distinct messages to evict an old nonce; then the relay replays a previously valid encrypted/signed envelope with a new relay-assigned message ID. The signed nonce and timestamp remain valid, and the signature is valid.

**Effect:** The replay can be accepted again and rendered as a new row. The per-message ID deduplication helps only when the relay reuses the same server ID; nonce deduplication is neither durable nor complete.

**Minimal fix:** Persist a bounded replay ledger per server/sender for the accepted-message retention window, or use a monotonic sender counter/epoch design in a future protocol spec. Keep Wire v3 unchanged in this work; use server IDs as an additional dedupe key. The bounded ledger needs an explicit eviction/clock policy.

**Test:** Recreate the controller or evict the first nonce, replay an identical envelope under a fresh relay ID, and verify it is rejected if durable replay protection is a v3 requirement.

### P2 — Biometric lock does not re-lock after backgrounding

**Location:** [MainActivity.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/MainActivity.kt:55), [MainActivity.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/MainActivity.kt:115)

**Trigger:** Enable biometric lock, unlock once, send the app to background, then return while the same Activity/Compose state remains alive.

**Effect:** `isUnlocked` remains `true`; the main screen returns without another biometric prompt. Current code therefore enforces the lock only on a newly created/restored UI state, not every foreground return. Whether that is a defect depends on the intended lock policy; if “lock on launch” is the sole requirement this is a limitation, but it weakens the common “app lock” expectation.

**Minimal fix:** Decide the intended re-lock timeout, then clear volatile unlock state on stop/background or via a lifecycle-aware lock controller. Avoid saveable persistence for authentication state if process/task restoration must require re-authentication.

**Test:** Instrumented lifecycle test: authenticate, background/stop, resume, expect lock screen until a fresh biometric succeeds.

### P2 — Restored DB rows decrypt without re-verifying ML-DSA signatures

**Location:** [ChatViewModel.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/ui/ChatViewModel.kt:72), [ChatController.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/ChatController.kt:1164), [ChatController.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/ChatController.kt:885)

**Trigger:** On app start or conversation observation, the database flow calls `decryptEntity`; it checks recipient KEM decryption and parses the envelope but does not resolve the sender DSA key or verify the envelope signature. The live and sync ingestion path does verify before persisting, but restored rows bypass that function.

**Effect:** The normal ingestion path is fail-closed, but the stated client policy (“messages from local DB are shown only after successful ML-DSA verification”) is not enforced at the read boundary. Local DB integrity is not the same as sender authenticity; retaining an explicit verified state would make the guarantee auditable and handle imported/migrated/corrupted rows consistently.

**Minimal fix:** Reuse a single verified-decode path for both ingestion and history, or persist a versioned verification marker that is invalidated on key changes and rechecked. Keep failed rows hidden and fail closed.

**Test:** Insert a decryptable envelope with an invalid signature through a controlled test fixture and verify the history observer omits it; valid signature remains visible.

### P2 — Two Android instrumentation tests have invalid setup/data

**Location:** [MessageDaoTest.kt](/D:/Data/Projects/ImpulseProject/client/app/src/androidTest/java/com/example/impulse/data/db/MessageDaoTest.kt:31), [MessageDaoTest.kt](/D:/Data/Projects/ImpulseProject/client/app/src/androidTest/java/com/example/impulse/data/db/MessageDaoTest.kt:82), [TrustedCertManagerTest.kt](/D:/Data/Projects/ImpulseProject/client/app/src/androidTest/java/com/example/impulse/security/TrustedCertManagerTest.kt:30), [TrustedCertManager.kt](/D:/Data/Projects/ImpulseProject/client/app/src/main/java/com/example/impulse/security/TrustedCertManager.kt:63)

**Trigger/effect:** `MessageDaoTest` inserts into a local in-memory DAO, then calls `repo.purgeExpired()` on `MessageRepository(context)`, which obtains the production singleton database instead of the test DAO; the expected deletion count is therefore unrelated to the inserted rows. `TrustedCertManager` requires exactly 64 hex characters, but the test fixtures use short values such as `ABCDEF0123456789`, `AAAA`, and `XYZ`, so `trustHash` rejects them and assertions expecting storage fail.

**Minimal fix:** Keep the production repository API unchanged unless required. Test DAO purge directly against the in-memory DAO, or create a narrow repository constructor for DAO injection only if justified. Use deterministic valid 64-hex fixtures and unique server IDs/cleanup so tests remain isolated. Review the optimistic-dedup test name and assert only the declared `(server_id, server_msg_id)` DAO uniqueness contract; negative temporary IDs and positive server IDs are distinct rows under the actual schema.

**Test:** Run the two instrumented tests repeatedly on a device/API 36 image after correcting setup. No run was performed during this audit.

## Transport and protocol observations

- QUIC/WebTransport is configured with leaf certificate SHA-256 pins; invalid or missing pins fail closed before session creation (`WebTransportClient.kt:207-213,486-498`). Initial trust requires QR/manual hash and rotation only occurs after a pinned channel (`TrustedCertManager.kt:62-77,94-115`). No certificate-validation bypass was found in reviewed paths.
- Live and synced messages pass ML-DSA verification in `processVerifiedMessage` before persistence (`ChatController.kt:872-895,940-951`). Signed metadata includes sender/content/time/nonce/DM conversation target. This is a good wire-v3 invariant.
- The server-provided Argon2 tuple is the exception to strict resource validation; see P1.
- Room stores relay ciphertext rather than plaintext body. Message body confidentiality is therefore provided by per-recipient E2EE payloads; row metadata (`sender`, server ID, timestamp, conversation discriminator, own flag) remains queryable in SQLite. This is an at-rest metadata exposure/design boundary, not evidence that plaintext bodies are written.
- App scope deliberately disconnects in `MainActivity.onStop` (privacy/no-background policy). Message delivery while backgrounded is therefore absent by design. `NetworkMonitor` reconnects only errored live controllers and is not a background service.
- No Android source path sends raw message plaintext to the server; payload is per-recipient KEM-wrapped and AES-GCM-encrypted before `OP_DATA` (`ChatController.kt:472-523,552-596`).

## Testability and product surface

- **Existing JVM tests:** 15 files under `client/app/src/test`, covering wire parsing, key exchange trust logic, crypto, QR parsing, cache/config, and utilities. No build/test was run in this audit.
- **Existing androidTest:** only `MessageDaoTest` and `TrustedCertManagerTest`; both need the fixes described above.
- **Emulators:** Android SDK has one AVD (`Impulse_API_36`) and one running emulator (`emulator-5554`). `WebTransportClient.startSession()` explicitly returns `ERROR` for emulator builds (`WebTransportClient.kt:196-201`; predicate in `EmulatorDetector.kt:11-18`). Therefore even two emulator instances cannot exercise the app's QUIC transport. Room/Keystore UI instrumentation remains possible on the current AVD; real transport integration requires physical devices or an explicitly approved test seam.
- **UI map:** three primary tabs in `MainScreen.kt:107-111`: Home/network status and server connection; Chats → server list → group + direct-message conversation picker → chat; Settings → server profiles/connection, app settings, user profile, appearance/language, biometric lock, screenshot protection, and QR certificate enrollment/rotation. There is a nested QR scan overlay and chat/conversation overlays with BackHandler support.
- **Absent roadmap functions:** E2EE file/media transfer, local voice notes, and automatic mDNS/ZeroConf discovery are listed in `client/docs/VISION.md:92-95` and no corresponding feature implementation was found. Endpoint parsing accepts mDNS hostnames, but there is no discovery service. Treat these as not-yet-implemented roadmap items rather than regressions.
- **Notifications:** manifest requests `POST_NOTIFICATIONS`, but no notification scheduling/delivery path was found. Given the explicit foreground-only session policy, this is currently an unused permission/feature gap, not a transport bug.

## Audit disposition

The highest-priority fixes are to bound Argon2 challenge parameters and preserve queued messages across transient send failures. The first-contact peer identity limitation must be reflected in trust UX/documentation before a defense-ready claim. Replay protection and history signature revalidation need an explicit v3 threat-model decision. This report is static analysis only; device execution, Gradle gates, and server/client interoperability remain unverified.
