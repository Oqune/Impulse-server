# SPEC: Relay resource and lifecycle hardening

Status: Approved for implementation by project owner, 2026-10-13
Scope: Rust server only. Preserve all current application features and the Wire v3 format/opcodes. No protocol or cryptographic changes.

## Goals

Make session termination fail closed, make relay memory use bounded across message storage and key exchange replay, keep each SyncResponse within the Android client's stream accumulator limit while delivering backlog without requiring a client change, and ensure one shutdown notification terminates every server accept loop.

Also bound unauthenticated session admission: opening the required client-initiated bidirectional stream has a handshake timeout, and the auth challenge starts an absolute 30-second deadline that is not extended by traffic. The deadline applies only until the session authenticates; authenticated sessions continue to use the existing 300-second idle timeout.

## Compatibility and fixed limits

- Preserve the configured payload ceiling of 1,000,000 bytes, count limit of 10,000 stored messages, message TTL, auth and relay behavior, and every Wire v3 frame layout.
- Cap retained message payload bytes at **64 MiB**. Both count and byte caps apply; oldest entries are evicted first when either limit would be exceeded.
- Cap each encoded `SyncResponse` frame at **4 MiB including opcode, count, per-message IDs/timestamps and length prefixes**. The Android `WebTransportClient` accumulator is 8 MiB (`WebTransportClient.kt::handleInboundChunk`), so 4 MiB leaves room for transport chunking and client-side frame assembly. The Android `Protocol.frameLength` and `parseSyncResponse` permit per-frame payloads up to 1,000,000 bytes and counts up to 10,000.
- Divide a Sync snapshot into multiple `0x34` frames, each at most 4 MiB and fewer than 500 records. The Android app auto-requests another Sync when one response contains at least 500 messages; keeping each frame below 500 avoids a duplicate follow-up racing the server's remaining chunks. Continue from the last emitted ID until the request's captured high-water mark, or the bounded storage snapshot, is exhausted. This keeps the existing cursor meaning and delivers the complete bounded backlog without a client change. Empty sync emits one empty `SyncResponse`.
- Retain no more than 16 key exchange packets and 64 KiB total per sender session. A packet that does not fit the cache budget is still relayed opaquely to live peers, but not retained for replay. The 1,024-session limit gives a maximum retained key-exchange payload budget of 64 MiB plus collection overhead.
- Use a 1-item direct-response channel so bounded SyncResponse frames apply backpressure instead of accumulating many large frames per session.
- Permit at most 16 concurrent Sync handlers and 16 global Sync frame buffers. Each frame-buffer permit must be acquired before cloning a store page and must travel with the encoded response until the writer flushes it or a disconnect/error drops it. A frame can transiently coexist with its retained page (approximately 8 MiB per permit, plus task/container overhead), bounding this application-level outbound working set near 128 MiB independently of the 1,024-session ceiling; no page may be allocated while waiting for a frame permit. This does not bound WebTransport/QUIC internals or total process memory.
- Bound writing/flushing a Sync frame to 30 seconds; if a peer stops consuming and blocks flow control, close that session so the frame permit is returned rather than held indefinitely.
- Bound the full Sync operation to 30 seconds from packet processing start, including waiting for operation/frame admission, page construction, and response-channel backpressure. On expiry close the session and release queued frame permits; the client can resume from its last processed message ID after reconnect. Very large or slow syncs may therefore require reconnect/resume.
- Bound processing of every packet on an authenticated session to 30 seconds, including waiting to enqueue direct responses (for example, a Heartbeat response) when the writer is stalled. On expiry close the session and run the ordinary session cleanup. Keep the unauthenticated absolute nonce deadline unchanged; apply this per-packet bound only after authentication. Log only session ID, opcode, and elapsed limit.

## Required behavior

1. Any `process_packet` error ends the session reader loop. Existing task cancellation and session-state cleanup must release the session permit and remove auth/key-exchange state. A malformed/unauthorized packet must not leave a connection alive until idle timeout.
2. One `Notify` signal must cancel all accept loops. Keep the existing `Arc<Notify>` entry point for Ctrl+C and TUI callers; internally one listener may translate that single notification into a cloneable broadcast/watch cancellation state.
3. Message insertion enforces both 10,000 records and 64 MiB retained payload bytes. Byte accounting remains correct under concurrent inserts, eviction, TTL sweep, and cloning for reads.
4. Sync emits bounded frames and makes monotonic cursor progress without skipping records in the captured snapshot. The encoder cannot create a frame above 4 MiB.
5. Key-exchange replay storage enforces both count and byte ceilings, evicts old retained frames deterministically when needed, and is removed on disconnect. Live relay remains opaque and unchanged.
6. A session that does not open its bidirectional stream within the handshake timeout is closed. After challenge issuance, all reads and packet processing must fit within the absolute `NONCE_MAX_AGE` deadline; unauthenticated traffic, including Heartbeat, never refreshes it. The deadline is checked only on the transition to authenticated; subsequent packets are governed by the 300-second idle timeout as before.

## Tests and acceptance

- Unit tests for message byte cap, count cap, TTL accounting, bounded sync page size, cursor continuity, and key-exchange count/byte caps and eviction.
- Session regression test proving a rejected packet terminates the loop and invokes cleanup; where practical cover it over live loopback WebTransport, alongside existing pin/auth/relay/sync smoke coverage.
- Unit and loopback coverage for the absolute authentication deadline, rejection of pre-auth Heartbeat, and continued authenticated heartbeat traffic beyond the 30-second auth window.
- Shutdown regression test proving one notification wakes all coordinated accept loops, including a real dual-stack loopback test where supported.
- Sync frame-budget regression proves the permit remains held while a response is queued and is returned when the response is dropped, including failed channel delivery.
- A stalled Sync writer regression proves the write deadline closes the operation and returns its frame permit.
- A saturated direct-response channel regression runs the actual authenticated Heartbeat handler and proves the common packet-processing deadline expires and cancels the blocked send. The session lifecycle regression verifies that the reader's exit path releases session state.
- Existing server tests and clippy must pass. No build/test result is asserted in this SPEC; owner will run the final test gate after the implementation.

## Out of scope

Certificate selection/rotation, authentication cryptography, payload inspection, routing semantics, any client source changes, wire format, dependency changes, package version, commit, and push.
