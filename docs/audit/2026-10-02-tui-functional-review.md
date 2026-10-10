# Rust host functional review — 2026-10-02

## Changes and evidence

- Central cobalt/graphite RGB palette; semantic green/amber/red and distinct severity text remain.
- Fixed reversed interpretation of bottom-relative scrolling. Home uses measured maximum, so Down after Home moves immediately. New rows do not shift a history viewport while its rows remain retained; filter changes return to live.
- Wrapped rows counted by ratatui's own paragraph engine (`unstable-rendered-line-info` feature, dependency versions unchanged). Long-message tails remain accessible. Visible scrollbar and LIVE/HISTORY/PAUSED log title.
- Search indices use severity-filtered records and are translated to wrapped row offsets. Query edits reset the match cursor.
- Full server information panel gets nine rows; previous six-row allocation hid TTL/payload/peak information.
- Terminal modes have an RAII cleanup guard covering early setup/render/input errors. TUI startup timeout is an error; runtime TUI failures request relay shutdown. Log ingress queue is bounded to 2000 records and remains nonblocking (overflow is dropped).

Automated rendering checks cover 1×1, 80×20, 90×24, 124×24, 125×24 and 150×40; empty/tiny viewports, wrapped tail, one-row scroll, Home/End, history while appending and search/filter cycling. An optional SVG snapshot exports the actual ratatui buffer with demonstration data.

New live loopback test runs production RelayServer over real WebTransport/QUIC. Uses an ephemeral test certificate and its actual SHA-256 pin; mismatched pin is rejected. Covers two authenticated streams, challenge/HMAC flow, heartbeat echo, byte-identical opaque payload broadcast, Sync, disconnect session cleanup, reconnect and replay. Test key files are deleted individually after use; existing config/certificates are not read or replaced.

## Scope limits

These checks are not a guarantee that every platform/device function is correct. Android E2EE, physical camera QR scanning, OS clipboard, real mouse events, terminal colour/font differences, WAN migration, long-duration certificate rotation and a 72-hour retention soak were not exercised. Existing integration suites include packet/store simulations; two client-attestation tests are intentionally ignored because attestation belongs on the client. Pause retains its existing semantics: incoming TUI records are not collected while paused; file logging is separate. The log viewer uses ratatui's u16 scroll range. History anchors across buffer eviction or terminal-width reflow are not preserved exactly. These limitations are reported rather than hidden.

Wire opcodes/formats, cryptographic parameters and client dynamic colour implementation are unchanged.

Validation: `cargo build --locked`, `cargo test --locked` (126 passed, 2 intentionally ignored), `cargo clippy --locked --all-targets -- -D warnings` passed. Targeted dashboard rendering was rerun after layout/palette adjustment. Windows linker emits its informational “library/object created” diagnostic during link; clippy is clean. This is a functional review, not a complete cryptographic audit.
