# Server Restructure + Bug Fixes + TUI Redesign — Design

> Status: approved by user (sections 1–4) on 2026-08-02.
> Implements user request: "проведи полный анализ сервера, разбей весь код структурно правильно, объедини по папкам, доведи до идеала, предложи изменения в TUI".

## Goal

Restructure the crate into domain folders, fix the real bugs found by analysis, redesign the TUI (controls, live stats, appearance, performance), and ship it as **v2.6.0** with CI running tests.

## Scope

- Structural refactor: split `server.rs` (1244 lines) and `tui.rs` (785), reorganize `tests.rs` (2122 lines), move framing into `protocol/`, move auth crypto into `crypto/`.
- Bug fixes (see §2), all with regression tests where testable.
- TUI redesign (see §3): working controls, live statistics, cleaner layout, event-driven rendering.
- CI: add `cargo test` to the release workflow; add `checks` to `flake.nix`.
- Version bump to 2.6.0 and release.
- Documentation refresh (lib.rs overview, module docs, README TUI section, stale comments).

## Non-Goals

- **No wire-protocol changes.** Opcodes, packet shapes, and the Argon2/HMAC handshake stay byte-compatible. All existing client behavior is preserved.
- **No new dependencies.** The redesign uses ratatui/crossterm already in Cargo.toml. No crate additions (except none needed).
- No new user-facing server features beyond the TUI (no API/CLI surface changes except fixes already approved).

---

## 1. Module Structure

### Target tree

```
src/
  lib.rs                # facade: pub mod declarations; run() orchestration
  main.rs               # binary: command dispatch, signals, terminal/panic cleanup
  relay/                # from server.rs
    mod.rs              # RelayServer (fields), new(), run(), accept_loop(), rate limiting
    session.rs          # Session struct; handle_wt_session, run_session, reader/writer tasks
    auth.rs             # nonce, auth challenge, verify_auth (Argon2 + HMAC), brute-force
    housekeeping.rs     # spawn_housekeeping: cert rotation, message sweep, stats tick
  protocol/             # from protocol.rs + framing from server.rs
    mod.rs              # Opcode, ProtocolError, PacketReader/Writer, encoders, RelayedMessage
    framing.rs          # try_read_packet + TryReadResult (moved from server.rs)
    limits.rs           # MAX_PAYLOAD_BYTES, MAX_STREAM_BUFFER, MAX_PACKET_LEN (single source)
  storage/
    mod.rs              # MessageStore, StoredMessage, TTL/ring-buffer
  cert/
    mod.rs              # Cert, CertManager, DynamicCertResolver, permissions (unix 0600 / win)
  config/
    mod.rs              # AppConfig, ServerSettings, validate, config_file_loaded
    cli.rs              # CliArgs, SetupCommand, resolve_command (clap)
    file.rs             # load_config, resolve_config_path, load_file_config
  cli/                  # from setup.rs (interactive bootstrap = CLI layer)
    mod.rs              # run_first_run_wizard, run_init_wizard, prompt_password, LICENSE_TEXT
    write.rs            # write_config_file
  crypto/               # from config.rs (auth primitives)
    mod.rs              # sha256_hex, argon2_hash, argon2_verify
  ui/                   # from tui.rs
    mod.rs              # spawn_tui, run_tui, TuiHandle (private fields), event loop
    draw.rs             # all draw_* functions + layout
    view.rs             # CertView, ServerInfo, LogRecord, ServerStats
  logging/
    mod.rs              # init_tracing, TuiLogLayer, BracketTimer, rolling file layer
tests/                  # integration tests (outside the crate)
  common/mod.rs         # shared test helpers (derived from tests.rs trio)
  handshake.rs  relay.rs  config.rs  storage.rs
```

### Key structural decisions

1. **Reverse dependency removed.** `protocol.rs:209` `debug_assert!(... <= crate::server::MAX_PAYLOAD_BYTES)` is eliminated: the limits move to `protocol/limits.rs` and `relay` imports them. `framing.rs` depends only on `protocol`.
2. **Session state encapsulated.** A new `Session` struct in `relay/session.rs` owns `session_key`, `remote_ip`, `authenticated`, `direct_tx`. Today `run_session` (server.rs:489-804) threads `&mut bool`/`&Sender` through arguments.
3. **Dead `sessions` registry becomes useful.** Today `sessions: DashMap<u64, mpsc::Sender>` (server.rs:120) stores a value that is never read — only insert/len/remove/clear. It becomes `DashMap<u64, SessionMeta>` where `SessionMeta { ip, authenticated, connected_at }` feeds the TUI session table. Active-session count is `len()`.
4. **`auth.rs` owns the handshake.** The Argon2 key derivation (server.rs:843-866) and verify flow (server.rs:817-968) become `verify_auth(...)`; the triplicated test helper (`derive_argon2_key`/`build_client_auth`/`server_verify_auth` at tests.rs:294/467/1456 etc.) is replaced by one shared `tests/common` helper or a `pub(crate)` wire-test util.
5. **Framing is one implementation.** `try_read_packet`/`TryReadResult` (server.rs:1183-1244) move to `protocol/framing.rs` and become `pub` (needed by `tests/`). The opcode→min-length table and the duplicated `u32::from_le_bytes` decode are replaced by the `PacketReader` primitives. `Opcode::display_name()` replaces `opcode_name` (server.rs:31-44).
6. **Visibility pass.** `TuiHandle` fields become private (methods `push_log`/`set_cert`/`set_info`/`set_stats` only); `run_tui` → `pub(crate)`; `push_with_timestamp` stays `pub(crate)` with a `#[doc(hidden)]` integration-test route or a `#[cfg(test)]` constructor; `CERT_OVERLAP` and `current_host`/`current_port` get tightened.
7. **Dead code removed:** `encode_key_exchange_tagged` (protocol.rs:279), the unreachable `IGNORE` arm (server.rs:1090-1096), the redundant `io::Error` `From<ProtocolError>` impl if unused.

### Test organization

- **Inline unit tests** (`#[cfg(test)] mod`) live in their module: protocol codec, storage push/since/sweep, cert fingerprint, config resolve/validate, cli wizards, ui `compute_scroll`/`fmt_duration`, crypto helpers.
- **Integration tests** move to `tests/` for cross-module flows (handshake, relay multi-client, key-exchange relay, E2E lifecycle, concurrent storage pushes).
- `tests.rs` header (stale, tests.rs:1-9), the missing `#[cfg(test)]` on `setup_tests` (tests.rs:2069), and the stale `server.rs:770-774` reference (tests.rs:466) are all fixed during the move.
- The two naming conventions (`snake_case` vs `test_` prefix) are unified to one (`snake_case`).

---

## 2. Bug Fixes (with regression tests)

| # | Bug (current location) | Fix | Test |
|---|------------------------|-----|------|
| 1 | Orphaned tasks: `tokio::select!` drops the losing `JoinHandle` which **detaches** the task (server.rs:782-788); reader keeps running, session-registry entry lingers, semaphore permit released early | In `relay/session.rs` both reader/writer tasks hold an `AbortHandle`; on the other's exit, `abort()` the peer; registry entry removed only after both complete | e2e: client drops mid-session → session count returns to 0 |
| 2 | `MessageStore` id-ordering race: `alloc_id` = `fetch_add` outside the lock, then `order.push_back` under lock (storage.rs:61-63, 82-94) → concurrent pushes can yield `[6,5]` | Allocate the id inside the same mutex as `order.push_back` | tokio test: concurrent `push()` → strictly monotonic ids, `since()` ordered |
| 3 | `argon2_hash` ends with `.expect("Argon2 hash should not fail")` (config.rs:308); with `panic = "abort"` (Cargo.toml:84) a failure kills the process | `argon2_hash(...) -> anyhow::Result<String>`; propagate with `?` at call sites (main.rs `--hash-password`, cli wizards) | existing hash tests adapt to `?`; build stays clean |
| 4 | TUI scroll is dead: `auto_scroll` initialized `true` and never set `false` (tui.rs:50, 59), so `scroll_offset` is ignored (tui.rs:583-596) | Extract pure `compute_scroll(total, usable, offset, auto) -> (scroll_y, auto)` handling wrapped rows; manual scroll disengages `auto_scroll`, `End`/bottom re-engages | unit tests for compute_scroll (pin/unpin, clamping, wrapped lines) |
| 5 | Terminal left in raw/mouse mode: no `DisableMouseCapture` on exit (tui.rs:284-286, main.rs:57-61); `panic=abort` can leave the terminal broken | Emit `DisableMouseCapture` + `LeaveAlternateScreen` + `disable_raw_mode` on exit and in a `std::panic::set_hook` registered in main.rs | manual smoke test (not unit-testable) |
| 6 | Duplicated `create_dir_all("logs")` (lib.rs:45, logging.rs:89) and two different RUST_LOG defaults (lib.rs:60 `"debug"`, logging.rs:84 `"info"`) | Single `const DEFAULT_LOG_FILTER = "debug"` in `logging/`; single place creates `logs/` | — |
| 7 | Dead/unreachable code: `encode_key_exchange_tagged`, `IGNORE` arm, `sessions` DashMap value, `opcode_name`/`hex_dump` duplicates | Removed; replaced by `Opcode::display_name()`; `hex_dump` retained only if reachable at TRACE | existing protocol/relay tests keep passing |

Also during refactor: `MessageStore::push` stops cloning the payload into the ring (hot path), and all limit constants consolidate into `protocol/limits.rs`.

---

## 3. TUI Redesign

### Layout (full mode, ≥ ~90 cols × ~26 rows)

```
┌─ Server ──────────────────────┐  ┌─ Sessions ───────────────────────────────┐
│ 0.0.0.0:4433  [::]:4433       │  │ #   IP           AUTH   AGE     BUF      │
│ WebTransport/QUIC · TLS 1.3   │  │ 12  192.168.1.5   ✓     03:12   12.4 KB  │
│ v2.5.1 · MIT © oqune          │  │ 13  10.0.0.8      ·     00:31   0 B      │
│ Uptime 2d 04:12:09            │  │                                         │
└───────────────────────────────┘  └─────────────────────────────────────────┘
┌─ TOFU QR ─────────┐  ┌─ Certificate ──────────────────────────────────────┐
│  ████ ████ ...    │  │ SHA-256  AB:CD:EF:01:…:56                         │
│  (29×15, cached)  │  │ Valid    12d 03h 22m 11s                          │
└───────────────────┘  │ Issued   2026-07-20 14:03:12                      │
                       │ Rotation ~2d · previous cert active               │
┌─ Logs ───────────────────────────────────────────────────────────────────┐
│ [12:03:44.112] INF relay::session auth ok session=12                     │
│ [12:03:45.003] INF relay::relay 3 msgs · 1.2 KB relayed                  │
│ …                                                                        │
└──────────────────────────────────────────────────────────────────────────┘
┌─ Status ─────────────────────────────────────────────────────────────────┐
│ ● LIVE   S 13/1024   Msgs 42/10k   ↑ 1.2 MB/s   Auth 10✓ 1✗   Buf 3.4 MB│
│ [1]ERR [2]WRN [3]INF [4]DBG [5]TRC    ·    3/2000    ·    Shift+C copy    │
└──────────────────────────────────────────────────────────────────────────┘
```

Responsive tiers: **compact** (<90 cols or <24 rows) = logs + status bar only; **full** = everything above. The QR panel collapses to a hint ("QR: enlarge terminal / press f") when it cannot render at full size — never a truncated, unscannable pattern (current tui.rs:640-650 truncates it).

### Controls

| Key | Action |
|-----|--------|
| `q` / `Ctrl+C` | quit (cleanup + shutdown notify) |
| `↑↓` / `PgUp PgDn` / `Home End` | scroll logs (fixes dead scroll; `End`/bottom re-pins to live) |
| `1` `2` `3` `4` `5` | toggle filters — **ERR WRN INF DBG TRC** (severity descending; was TRC→ERR) |
| `Space` | pause/resume log streaming |
| `/` | search: input line, substring match highlighted, `Enter` next match |
| `c` | clear scrollback |
| `Tab` | cycle left panel: full → QR-only → hidden |
| `f` | focus QR full-screen (and back) |
| `Shift+C` | copy buffered logs to clipboard (kept) |
| Mouse wheel | scroll logs (capture already enabled; now handled) |

### Live statistics (new `ServerStats` in `ui/view.rs`)

Atomics shared with the relay: `sessions`, `peak_sessions`, `messages`, `relayed_msgs`, `relayed_bytes`, `auth_ok`, `auth_fail`, `rate_limited`, `buffered_bytes`, `uptime_start` (`Instant`). Increment sites:
- `relayed_msgs`/`relayed_bytes`: after `data_tx.send` returns (server.rs:1032) and in the writer task's `write_all` (server.rs:528-603).
- `auth_ok`/`auth_fail`: at verify success/failure (server.rs:911-937).
- `rate_limited`: on `check_rate_limit` rejection (server.rs:379-385).
- `peak_sessions`: in housekeeping tick and on session insert (server.rs:510, 1177).
- throughput `↑` is derived from `relayed_bytes` over a rolling 5 s window in the 1 s TUI tick.

Sessions table: `SessionMeta` snapshot read per draw (capped at 100 rows). `buffered_bytes` already exists (server.rs:145, 647-679) and is surfaced as aggregate.

### Performance

- **Event-driven redraw**: draw only when (a) ≥1 log drained, (b) an input event handled, (c) the 1 s stats/clock tick fired, or (d) terminal resize. Poll at ~16 ms. Idle CPU drops from ~10 fps constant repaint (tui.rs:235-244) to near zero.
- **QR cache**: the `qrcode::QrCode` is rebuilt only when `fingerprint_raw` changes (cert rotation), not every frame (tui.rs:638).
- **Line cache**: log `Line`s are formatted once at insert (from `LogRecord`), not rebuilt per frame (tui.rs:560-578).
- **Visible-window render**: only the lines in the viewport are rendered, not all buffered lines.
- **Scrollback**: `MAX_LOG_LINES` 500 → 2000 (const).

### Appearance

- Single `Theme` const (colors for headers, borders, focus, level labels, QR frame) — removes scattered `Color` literals (tui.rs:35-43, 471-557).
- Shared `fmt_duration` helper replaces the duplicated d/h/m/s decomposition (tui.rs:483-489 vs 663-669).
- Info panel shows dual-stack listen addrs, SAN count, uptime; no wasted blank line (tui.rs:524).
- Status bar replaces the help bar; clock, scroll position (`n/N`), active filters, copy hint in one place.
- Consistent fingerprint display (short hash in Info, full grouped in Certificate).

---

## 4. CI, Version, Documentation

1. **CI**: add `cargo test --locked` to `.github/workflows/server-build.yml` (runs on push/PR; currently only `cargo build --release`). Add `checks` to `flake.nix`.
2. **Version**: bump to **2.6.0** in `Cargo.toml` (package + `[package.metadata.generate-rpm]`), `Cargo.lock`, `flake.nix`.
3. **Docs**: refresh `lib.rs` overview (all 8 modules, opcodes 0x01–0x0C, describe the Argon2/HMAC auth chain); module doc headers; README/README.ru.md TUI section (new keys, status bar, stats); delete stale comments (tests.rs:466, tui.rs:97-98).
4. **Release**: tag `v2.6.0` → workflow → verify 10 assets (`ImpulseServer-2.6.0-<os>-<arch>.<ext>`), spot-check tar.gz (binary + LICENSE) and deb (`/etc/impulse-server/config.toml` empty hash).

---

## Implementation Order

1. Extract `protocol/limits.rs` + `protocol/framing.rs`; fix `protocol→relay` reverse dep.
2. Extract `crypto/` from `config.rs`; make `argon2_hash` fallible.
3. Split `server.rs` → `relay/` (mod, session, auth, housekeeping); fix orphaned-task and `sessions`-registry issues; wire `SessionMeta` + stat increments.
4. Move `setup.rs` → `cli/`; `config.rs` → `config/` (mod, cli, file).
5. Move `tui.rs` → `ui/`; redesign (layout, controls, stats, perf); extract pure helpers.
6. Reorganize tests: inline module units + `tests/` integration; unify naming; fix `#[cfg(test)]`.
7. Docs, CI, version bump → release 2.6.0.

## Verification

- `cargo test --locked` passes on Windows: existing 69 tests (moved) + new regression tests; output pristine (no warnings).
- `cargo build --release` clean.
- Manual TUI smoke: scroll works, filters `1-5`, `/` search, `Space` pause, `Tab`/`f` panel toggles, mouse wheel, QR renders fully (no truncation), stats update live, exit restores terminal.
- Manual CLI smoke: `--license`, `--init --force`, `--force` alone rejected, `--config packaging/config.toml` loud-error.
- Release v2.6.0 verified (10 assets, tar.gz = binary + LICENSE, deb empty-hash config).
