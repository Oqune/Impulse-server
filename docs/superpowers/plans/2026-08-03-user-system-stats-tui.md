# User System + Per-User Stats + 3-Column TUI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a RAM-only user registry keyed by the client's KEM public-key hash, show per-user online/offline status and stats in the TUI, restructure the TUI into three columns, and fix the stale-UI bugs (disconnect doesn't refresh sessions, frozen `age`).

**Architecture:** The relay parses the KEM public key out of the existing `0x0C KeyExchangeKemDsa` packet (no wire-protocol change), derives `fingerprint = sha256(kem)[..32]` (identical to the client's `SecureKeyManager.fingerprintForBytes`), and records per-user stats in a new `relay::users::UserRegistry` (`DashMap` + alias counter). `SessionMeta`/`Session` gain a `user` field; `cleanup_session_state` releases the user on disconnect; the DATA handler counts `msgs_sent`. View models (`ui::view`) gain `UserRow` and `SessionRow` carries `connected_at` + user alias; `TuiHandle.set_users` mirrors `set_sessions`; `ui::draw` renders a responsive three-column layout (info | users+sessions | logs) with live online/age computed per frame.

**Tech Stack:** Rust (edition 2024), tokio, dashmap 6, sha2 0.10 (already a dependency), hex 0.4 (already a dependency), ratatui 0.30, crossterm 0.29. No new dependencies.

## Global Constraints

- Repo root: `D:\Data\Projects\ImpulseProject\server`. All commands run there (set `workdir`).
- `cargo` resolves to `C:\Users\Misha\.cargo\bin\cargo.exe`; use the full path if `cargo` is not on PATH.
- No wire-protocol changes — `0x0C` packet shape stays byte-identical; the server only *parses* the already-relayed key. No client changes. No persistence. No new dependencies.
- `active_sessions` must bump ONLY on the `session.user` `None→Some` transition (guards re-sent `0x0C` from double-counting). Every `0x0C` refreshes `last_seen`.
- Sessions that disconnect before sending `0x0C` contribute no user record.
- Server blindness: never log or persist decrypted payloads or private keys; only key hashes + message counts are surfaced.
- Every task ends green: `cargo build --locked` clean and `cargo test --locked` green (existing 83 tests + new), then a commit. Do not commit before the user approves this plan.

---

### Task 1: Sessions/Users view models + live session age

**Files:**
- Modify: `src/ui/view.rs` (add `UserRow`, rework `SessionRow`, add `live_total_online`, tests)
- Modify: `src/relay/mod.rs:388-399` (`session_rows` builds the new `SessionRow`)
- Modify: `src/ui/draw.rs:325-357` (`draw_sessions` computes age live, renders user tag)
- Test: `src/ui/view.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: nothing new.
- Produces (used by later tasks):
  - `ui::view::UserRow { alias: String, fingerprint: String, online: bool, total_online: Duration, msgs_sent: u64, connected_at: Option<Instant> }`
  - `ui::view::SessionRow { key: u64, ip: IpAddr, authenticated: bool, user: Option<String>, connected_at: Instant }` (`age` removed)
  - `ui::view::live_total_online(total: Duration, connected_at: Option<Instant>, now: Instant) -> Duration`
  - `relay::RelayServer::session_rows()` now returns rows with `user: None` and a live `connected_at`.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `src/ui/view.rs` (next to the existing `compute_scroll` / `fmt_duration` tests):

```rust
    use std::time::{Duration, Instant};

    #[test]
    fn live_total_online_adds_active_delta() {
        let now = Instant::now();
        let start = now - Duration::from_secs(120);
        assert_eq!(
            live_total_online(Duration::from_secs(10), Some(start), now),
            Duration::from_secs(130)
        );
    }

    #[test]
    fn live_total_online_offline_is_accumulated_only() {
        let now = Instant::now();
        assert_eq!(
            live_total_online(Duration::from_secs(45), None, now),
            Duration::from_secs(45)
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --locked view::tests`
Expected: compile error — `cannot find function live_total_online` (and the `UserRow` type / `connected_at` / `user` fields do not exist yet).

- [ ] **Step 3: Implement the view models and fix call sites**

In `src/ui/view.rs`, change the time import to:

```rust
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
```

Replace the `SessionRow` struct (currently lines 99-106) with:

```rust
/// Snapshot of a live session for the sessions table. `connected_at` is the
/// session's start time; the TUI computes `now - connected_at` per frame so
/// the age never goes stale between 60 s housekeeping pushes (spec §3 fix 2).
#[derive(Clone, Debug)]
pub struct SessionRow {
    pub key: u64,
    pub ip: std::net::IpAddr,
    pub authenticated: bool,
    /// Alias (`U{n}`) of the bound user, if the session sent `0x0C`.
    pub user: Option<String>,
    pub connected_at: Instant,
}

/// Snapshot of a known user for the users panel (see `relay::users`).
#[derive(Clone, Debug)]
pub struct UserRow {
    /// Display alias, `U{n}`, assigned in first-seen order.
    pub alias: String,
    /// `sha256(kem_public_key)[..32]` — the client-visible id.
    pub fingerprint: String,
    /// Whether the user currently has at least one connected session.
    pub online: bool,
    /// Accumulated online time across all sessions (server lifetime).
    pub total_online: Duration,
    /// DATA packets authored by this user.
    pub msgs_sent: u64,
    /// Start of the earliest currently-active session, when online. Lets the
    /// TUI recompute live online time each draw without a new snapshot.
    pub connected_at: Option<Instant>,
}
```

Add after `fmt_duration` (still in `src/ui/view.rs`):

```rust
/// Online time as of `now`: accumulated total plus the live delta of the
/// earliest active session (exact for the common single-session case).
pub fn live_total_online(
    total: Duration,
    connected_at: Option<Instant>,
    now: Instant,
) -> Duration {
    match connected_at {
        Some(c) => total + now.saturating_duration_since(c),
        None => total,
    }
}
```

In `src/relay/mod.rs`, replace `session_rows` (lines 388-399) with:

```rust
    /// Snapshot the live-session registry as rows for the TUI sessions panel.
    fn session_rows(&self) -> Vec<crate::ui::view::SessionRow> {
        self.sessions
            .iter()
            .map(|entry| crate::ui::view::SessionRow {
                key: *entry.key(),
                ip: entry.value().ip,
                authenticated: entry.value().authenticated,
                // User binding lands in a later task; always None for now.
                user: None,
                connected_at: entry.value().connected_at,
            })
            .collect()
    }
```

In `src/ui/draw.rs`, replace `draw_sessions` (lines 325-357) with:

```rust
fn draw_sessions(f: &mut ratatui::Frame, area: Rect, sessions: &[SessionRow]) {
    let now = std::time::Instant::now();
    let mut lines: Vec<Line> = Vec::new();
    for row in sessions.iter().take(100) {
        let auth = if row.authenticated {
            Span::styled("✓", Style::default().fg(THEME.ok))
        } else {
            Span::styled("·", Style::default().fg(THEME.dim))
        };
        // Age is computed live per frame so it never freezes between the 60 s
        // housekeeping pushes (spec §3 fix 2).
        let age = fmt_duration(now.saturating_duration_since(row.connected_at).as_secs());
        let user_tag = match &row.user {
            Some(alias) => Span::styled(format!("{alias} "), Style::default().fg(THEME.header)),
            None => Span::raw(""),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{:4}  ", row.key), Style::default().fg(THEME.dim)),
            Span::styled(format!("{:<16}", row.ip.to_string()), Style::default().fg(THEME.value)),
            Span::raw("  "),
            auth,
            user_tag,
            Span::styled(format!("  {:>8}", age), Style::default().fg(THEME.dim)),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "no sessions",
            Style::default().fg(THEME.dim),
        )));
    }
    let block = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(" Sessions ")
                .border_style(Style::default().fg(THEME.border)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(block, area);
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --locked view::tests && cargo build --locked`
Expected: all `view::tests` pass; crate builds clean.

- [ ] **Step 5: Commit**

```bash
git add src/ui/view.rs src/ui/draw.rs src/relay/mod.rs
git commit -m "refactor(ui): SessionRow carries connected_at + user; add UserRow"
```

---

### Task 2: `relay::users` — fingerprint parser + user registry

**Files:**
- Create: `src/relay/users.rs`
- Modify: `src/relay/mod.rs:11-14` (register the module: add `pub mod users;`)
- Test: unit tests inside `src/relay/users.rs`

**Interfaces:**
- Consumes: `ui::view::UserRow` (from Task 1).
- Produces (used by later tasks):
  - `relay::users::fingerprint_of_keyexchange(packet: &[u8]) -> Option<String>` — returns `sha256(kem)[..32]` lowercase hex, or `None` for malformed/non-`0x0C` frames.
  - `relay::users::UserRegistry` with methods:
    - `bind_session(&self, fingerprint: &str) -> String` — insert-if-absent (alias = next counter), refresh `last_seen`, `active_sessions += 1`, push `now` into the active-session list; returns `"U{n}"`. Call ONLY on the first `0x0C` of a session.
    - `touch(&self, fingerprint: &str)` — refresh `last_seen` only (re-sent `0x0C`).
    - `release_session(&self, fingerprint: &str)` — close the earliest active session: `total_online += now - started`, `active_sessions -= 1`, `last_seen = now`.
    - `record_message(&self, fingerprint: &str)` — `msgs_sent += 1`.
    - `alias_of(&self, fingerprint: &str) -> Option<String>` — `"U{n}"` if known.
    - `rows(&self) -> Vec<UserRow>` — snapshot of every user ever seen, sorted by alias number.

- [ ] **Step 1: Write the failing test**

Create `src/relay/users.rs` with a stub signature plus the test module (the tests name the missing items):

```rust
//! Ephemeral user registry: public-key-hash identities + per-user stats.

pub fn fingerprint_of_keyexchange(_packet: &[u8]) -> Option<String> {
    todo!("implement in this task")
}

#[cfg(test)]
mod tests {
    use super::{UserRegistry, fingerprint_of_keyexchange};

    fn kem_packet(kem: &[u8], dsa: &[u8]) -> Vec<u8> {
        let inner = 4 + kem.len() + 4 + dsa.len();
        let mut p = Vec::with_capacity(1 + 4 + inner);
        p.push(0x0C);
        p.extend_from_slice(&(inner as u32).to_le_bytes());
        p.extend_from_slice(&(kem.len() as u32).to_le_bytes());
        p.extend_from_slice(kem);
        p.extend_from_slice(&(dsa.len() as u32).to_le_bytes());
        p.extend_from_slice(dsa);
        p
    }

    #[test]
    fn fingerprint_matches_sha256_of_kem() {
        // SHA-256("abc") hex, truncated to 32 chars — exactly what the client's
        // SecureKeyManager.fingerprintForBytes produces for the same KEM bytes.
        let packet = kem_packet(b"abc", b"def");
        assert_eq!(
            fingerprint_of_keyexchange(&packet).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223"
        );
    }

    #[test]
    fn fingerprint_rejects_malformed_frames() {
        assert_eq!(fingerprint_of_keyexchange(&[]), None);
        assert_eq!(fingerprint_of_keyexchange(&[0x0C]), None);
        let good = kem_packet(b"abc", b"def");
        assert_eq!(fingerprint_of_keyexchange(&good[..good.len() - 1]), None);
        let mut wrong = good.clone();
        wrong[0] = 0x05;
        assert_eq!(fingerprint_of_keyexchange(&wrong), None);
    }

    #[test]
    fn fingerprint_rejects_oversized_kem_len() {
        let mut p = vec![0x0C];
        p.extend_from_slice(&8u32.to_le_bytes()); // inner_len = 8
        p.extend_from_slice(&u32::MAX.to_le_bytes()); // kem_len = u32::MAX
        p.extend_from_slice(b"abcd");
        assert_eq!(fingerprint_of_keyexchange(&p), None);
    }

    #[test]
    fn bind_assigns_aliases_in_first_seen_order() {
        let r = UserRegistry::new();
        assert_eq!(r.bind_session("aaaa"), "U1");
        assert_eq!(r.bind_session("bbbb"), "U2");
        assert_eq!(r.bind_session("cccc"), "U3");
        let rows = r.rows();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].alias, "U1");
        assert_eq!(rows[1].alias, "U2");
        assert_eq!(rows[2].alias, "U3");
    }

    #[test]
    fn bind_reuses_alias_and_tracks_multiple_sessions() {
        let r = UserRegistry::new();
        assert_eq!(r.bind_session("aaaa"), "U1");
        assert_eq!(r.bind_session("aaaa"), "U1");
        assert_eq!(r.rows().len(), 1);
        assert!(r.rows()[0].online);
        r.release_session("aaaa");
        assert!(r.rows()[0].online); // still one session open
        r.release_session("aaaa");
        let row = &r.rows()[0];
        assert!(!row.online);
        assert!(row.total_online >= std::time::Duration::ZERO);
        assert_eq!(row.connected_at, None);
    }

    #[test]
    fn record_message_increments_counter() {
        let r = UserRegistry::new();
        r.record_message("aaaa"); // unknown user -> no-op
        r.bind_session("aaaa");
        r.record_message("aaaa");
        r.record_message("aaaa");
        assert_eq!(r.rows()[0].msgs_sent, 2);
    }

    #[test]
    fn touch_refreshes_without_bumping_sessions() {
        let r = UserRegistry::new();
        r.bind_session("aaaa");
        r.touch("aaaa");
        assert!(r.rows()[0].online);
        r.release_session("aaaa");
        assert!(!r.rows()[0].online);
    }

    #[test]
    fn alias_of_resolves_known_fingerprints_only() {
        let r = UserRegistry::new();
        assert_eq!(r.alias_of("nope"), None);
        r.bind_session("aaaa");
        assert_eq!(r.alias_of("aaaa"), Some("U1".to_string()));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --locked users::tests`
Expected: fails to compile — `UserRegistry` is not defined (and the stub `fingerprint_of_keyexchange` panics via `todo!`).

- [ ] **Step 3: Implement the module**

Replace the entire stub content of `src/relay/users.rs` with:

```rust
//! Ephemeral user registry: public-key-hash identities + per-user stats.
//!
//! Users are identified by `sha256(kem_public_key)` (lowercase hex, first 32
//! chars) — identical to the client's `SecureKeyManager.fingerprintForBytes`,
//! so the admin alias matches the id the client shows and the `recipientId`
//! inside per-recipient blobs. RAM-only: stats live for the server's lifetime.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::protocol::Opcode;
use crate::ui::view::UserRow;

/// Lowercase-hex SHA-256 of a KEM public key, truncated to 32 chars. This is
/// the server-side user identifier and the key of the [`UserRegistry`].
///
/// Parses the exact client wire format for `0x0C KeyExchangeKemDsa`:
/// `[0x0C] [u32 inner_len] [u32 kem_len] [kem] [u32 dsa_len] [dsa]`.
/// Returns `None` for non-`0x0C` or malformed frames.
pub fn fingerprint_of_keyexchange(packet: &[u8]) -> Option<String> {
    use sha2::{Digest, Sha256};

    if packet.len() < 13 || packet[0] != Opcode::KeyExchangeKemDsa.as_u8() {
        return None;
    }
    let inner_len = u32::from_le_bytes(packet[1..5].try_into().ok()?) as usize;
    let kem_len = u32::from_le_bytes(packet[5..9].try_into().ok()?) as usize;
    // Frame shape must be exactly [opcode][u32 inner_len][inner] where inner
    // starts with the KEM blob.
    if inner_len.checked_add(5)? != packet.len() {
        return None;
    }
    let kem_end = 9usize.checked_add(kem_len)?;
    if kem_end.checked_add(4)? > packet.len() {
        return None;
    }
    let kem = &packet[9..kem_end];
    let digest = Sha256::digest(kem);
    // Same lowercase-hex formatting as Cert::fingerprint_of (cert/mod.rs:68).
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    Some(hex[..32].to_string())
}

/// Per-user stats, keyed by fingerprint. Lives for the server's lifetime.
#[derive(Debug)]
pub struct UserStats {
    pub fingerprint: String,
    /// 1-based alias number (displayed as `U{alias}`), assigned in first-seen order.
    pub alias: u64,
    pub first_seen: Instant,
    pub last_seen: Instant,
    /// Accumulated online time across all sessions (server lifetime).
    pub total_online: Duration,
    /// Currently connected sessions for this user.
    pub active_sessions: usize,
    /// DATA packets authored by this user.
    pub msgs_sent: u64,
    /// Connected-at instants of this user's currently active sessions.
    active_connected_at: Vec<Instant>,
}

/// RAM-only user registry shared by the relay.
#[derive(Debug, Default)]
pub struct UserRegistry {
    users: DashMap<String, UserStats>,
    next_alias: AtomicU64,
}

impl UserRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `fingerprint` and open a new session for it. New users get the
    /// next alias; existing users keep theirs. Bumps `active_sessions` — callers
    /// must invoke this only on the first `0x0C` of a session (`session.user`
    /// was `None`), so a re-sent `0x0C` cannot double-count.
    pub fn bind_session(&self, fingerprint: &str) -> String {
        let now = Instant::now();
        let mut entry = self.users.entry(fingerprint.to_string()).or_insert_with(|| {
            let alias = self.next_alias.fetch_add(1, Ordering::Relaxed) + 1;
            UserStats {
                fingerprint: fingerprint.to_string(),
                alias,
                first_seen: now,
                last_seen: now,
                total_online: Duration::ZERO,
                active_sessions: 0,
                msgs_sent: 0,
                active_connected_at: Vec::new(),
            }
        });
        entry.last_seen = now;
        entry.active_sessions += 1;
        entry.active_connected_at.push(now);
        format!("U{}", entry.alias)
    }

    /// Refresh `last_seen` for a re-sent `0x0C` without touching active counts.
    pub fn touch(&self, fingerprint: &str) {
        if let Some(mut entry) = self.users.get_mut(fingerprint) {
            entry.last_seen = Instant::now();
        }
    }

    /// Close the earliest active session for `fingerprint`: accumulate its
    /// online time and drop `active_sessions`. No-op if the user is unknown.
    pub fn release_session(&self, fingerprint: &str) {
        let now = Instant::now();
        if let Some(mut entry) = self.users.get_mut(fingerprint) {
            if let Some(connected) = entry.active_connected_at.pop() {
                entry.total_online += now.saturating_duration_since(connected);
                entry.active_sessions = entry.active_sessions.saturating_sub(1);
            }
            entry.last_seen = now;
        }
    }

    /// Count a DATA packet authored by `fingerprint` (metadata only).
    pub fn record_message(&self, fingerprint: &str) {
        if let Some(mut entry) = self.users.get_mut(fingerprint) {
            entry.msgs_sent += 1;
        }
    }

    /// Alias string for a fingerprint (`U{n}`), if known.
    pub fn alias_of(&self, fingerprint: &str) -> Option<String> {
        self.users.get(fingerprint).map(|e| format!("U{}", e.alias))
    }

    /// Snapshot all users ever seen, sorted by alias number.
    pub fn rows(&self) -> Vec<UserRow> {
        let now = Instant::now();
        let mut entries: Vec<_> = self.users.iter().collect();
        entries.sort_by_key(|e| e.alias);
        entries
            .into_iter()
            .map(|e| UserRow {
                alias: format!("U{}", e.alias),
                fingerprint: e.fingerprint.clone(),
                online: e.active_sessions > 0,
                total_online: e.total_online,
                msgs_sent: e.msgs_sent,
                connected_at: e.active_connected_at.iter().copied().min(),
            })
            .collect()
    }
}
```

In `src/relay/mod.rs`, add the module declaration to the `pub mod` block (lines 11-14):

```rust
pub mod auth;
pub mod housekeeping;
pub mod session;
pub mod stats;
pub mod users;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --locked users::tests && cargo build --locked`
Expected: all `users::tests` pass; crate builds clean.

- [ ] **Step 5: Commit**

```bash
git add src/relay/users.rs src/relay/mod.rs
git commit -m "feat(relay): user registry keyed by KEM public-key hash"
```

---

### Task 3: Plumb user rows from the relay to the TUI

**Files:**
- Modify: `src/ui/mod.rs` (`TuiHandle` gains `users`, `set_users`, `spawn_tui`, `run_tui`)
- Modify: `src/ui/draw.rs:117-127` (`draw` gains a `users` parameter)
- Test: existing suite (this is plumbing; verification is build + regression)

**Interfaces:**
- Consumes: `ui::view::UserRow` (Task 1).
- Produces (used by Task 4): `TuiHandle::set_users(rows: Vec<UserRow>)`, and `draw(...)` now takes `users: &[UserRow]` after `sessions`.

- [ ] **Step 1: Implement `TuiHandle::set_users` and plumbing**

In `src/ui/mod.rs`:

Add the import (extend the existing `use crate::ui::view::{...}` line 22):

```rust
use crate::ui::view::{CertView, LogRecord, ServerInfo, SessionRow, UserRow};
```

Add a field to `TuiHandle` (after the `sessions` field, line 106):

```rust
    sessions: Arc<Mutex<Vec<SessionRow>>>,
    users: Arc<Mutex<Vec<UserRow>>>,
```

Add the method to `impl TuiHandle` (right after `set_sessions`):

```rust
    pub fn set_users(&self, rows: Vec<UserRow>) {
        *self.users.lock().unwrap_or_else(|e| e.into_inner()) = rows;
    }
```

In `run_tui` (line 141), add the `users` parameter after `sessions`:

```rust
pub(crate) fn run_tui(
    log_rx: crossbeam_channel::Receiver<LogRecord>,
    cert: Arc<Mutex<CertView>>,
    info: Arc<Mutex<ServerInfo>>,
    stats: Arc<ServerStats>,
    sessions: Arc<Mutex<Vec<SessionRow>>>,
    users: Arc<Mutex<Vec<UserRow>>>,
    shutdown: Arc<tokio::sync::Notify>,
    init_tx: crossbeam_channel::Sender<anyhow::Result<()>>,
) -> anyhow::Result<()> {
```

Inside the draw block (after `let sessions = ...` line 235), read and pass users:

```rust
            let sessions = sessions.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let users = users.lock().unwrap_or_else(|e| e.into_inner()).clone();
            draw(
                &mut terminal,
                &logs,
                &cert,
                &info,
                &stats,
                &sessions,
                &users,
                &state,
                has_clipboard,
                throughput,
            )?;
```

In `spawn_tui` (line 363): create the `users` Arc, clone it, pass it through:

```rust
pub fn spawn_tui(initial: CertView, shutdown: Arc<tokio::sync::Notify>) -> anyhow::Result<TuiHandle> {
    let (log_tx, log_rx) = crossbeam_channel::unbounded::<LogRecord>();
    let cert = Arc::new(Mutex::new(initial));
    let info = Arc::new(Mutex::new(ServerInfo::default()));
    let stats = Arc::new(ServerStats::new());
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let users = Arc::new(Mutex::new(Vec::new()));

    let cert_clone = cert.clone();
    let info_clone = info.clone();
    let stats_clone = stats.clone();
    let sessions_clone = sessions.clone();
    let users_clone = users.clone();
    let shutdown_clone = shutdown.clone();

    let (init_tx, init_rx) = crossbeam_channel::bounded::<anyhow::Result<()>>(1);
    std::thread::spawn(move || {
        let init_tx2 = init_tx.clone();
        if let Err(e) = run_tui(log_rx, cert_clone, info_clone, stats_clone, sessions_clone, users_clone, shutdown_clone, init_tx) {
            let _ = init_tx2.send(Err(e));
        }
    });
    // ... init_rx handling unchanged ...

    Ok(TuiHandle {
        log_tx,
        cert,
        info,
        stats,
        sessions,
        users,
        shutdown,
    })
}
```

In `src/ui/draw.rs`, change the `draw` signature (line 117) to add the `users` parameter after `sessions`, and add `UserRow` to the imports:

```rust
use crate::ui::view::{CertView, LogRecord, ServerInfo, SessionRow, UserRow, ServerStats};
```

```rust
pub(crate) fn draw(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    logs: &[LogRecord],
    cert: &CertView,
    info: &ServerInfo,
    stats: &ServerStats,
    sessions: &[SessionRow],
    users: &[UserRow],
    state: &TuiState,
    has_clipboard: bool,
    throughput: u64,
) -> anyhow::Result<()> {
    // The Users panel consumes this in a later task.
    let _ = users;
    terminal.draw(|f| {
```

- [ ] **Step 2: Build and run the existing tests**

Run: `cargo build --locked && cargo test --locked`
Expected: clean build; all existing tests green (still 83).

- [ ] **Step 3: Commit**

```bash
git add src/ui/mod.rs src/ui/draw.rs
git commit -m "refactor(ui): plumb user rows from relay to the TUI"
```

---

### Task 4: Relay wiring — bind sessions to users, count msgs, release on disconnect

**Files:**
- Modify: `src/relay/mod.rs` (add `users: Arc<UserRegistry>` field + init, `user_rows()`, map aliases in `session_rows`)
- Modify: `src/relay/session.rs` (`SessionMeta.user`, `Session.user`, `cleanup_session_state` release, disconnect pushes, tests)
- Modify: `src/relay/auth.rs` (bind on first `0x0C`, `touch` on re-sent `0x0C`, `msgs_sent` on DATA)
- Modify: `src/relay/housekeeping.rs` (60 s `set_users` safety net)
- Test: `src/relay/session.rs` `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `relay::users::{UserRegistry, fingerprint_of_keyexchange}` (Task 2), `TuiHandle::set_users` (Task 3).
- Produces: `RelayServer.user_rows() -> Vec<UserRow>`; `SessionMeta { ip, authenticated, connected_at, user: Option<String> }`; `Session.user: Option<String>` (fingerprint); `cleanup_session_state(..., users: &UserRegistry, ...)`.

- [ ] **Step 1: Write the failing test**

In `src/relay/session.rs`, inside `mod tests`, add this test (it names the new `users` parameter and `SessionMeta.user` field):

```rust
    use crate::relay::users::UserRegistry;

    #[test]
    fn cleanup_releases_user_registry_session() {
        let users = UserRegistry::new();
        let sessions: DashMap<u64, SessionMeta> = DashMap::new();
        let stats = ServerStats::new();
        let auth_nonces = DashMap::new();
        let auth_attempts = DashMap::new();
        let key_exchange_store = DashMap::new();

        // Session connects, authenticates, and binds to user "deadbeef" (as
        // the 0x0C handler does via bind_session).
        let fp = "deadbeefcafebabe0123456789abcdef".to_string();
        sessions.insert(
            9,
            SessionMeta {
                ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
                authenticated: true,
                connected_at: Instant::now(),
                user: Some(fp.clone()),
            },
        );
        users.bind_session(&fp);
        assert!(users.rows()[0].online);

        // Disconnect: the user's session must be released, not leaked.
        cleanup_session_state(
            &sessions,
            &stats,
            &users,
            &auth_nonces,
            &auth_attempts,
            &key_exchange_store,
            9,
        );
        assert_eq!(sessions.len(), 0);
        let row = &users.rows()[0];
        assert!(!row.online);
        assert!(row.total_online >= Duration::from_millis(1));
        assert_eq!(row.connected_at, None);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --locked session::tests::cleanup_releases_user_registry_session`
Expected: compile errors — `SessionMeta` has no field `user`, and `cleanup_session_state` takes 6 args, not 7.

- [ ] **Step 3: Implement the relay wiring**

In `src/relay/session.rs`:

Add `user` to `SessionMeta` (lines 25-30) and to `Session` (lines 33-38):

```rust
/// Lightweight snapshot of a live session, stored in the relay's session
/// registry and displayed by the TUI.
#[derive(Clone, Debug)]
pub struct SessionMeta {
    pub ip: IpAddr,
    pub authenticated: bool,
    pub connected_at: Instant,
    /// Fingerprint of the bound user, once the session's first `0x0C` arrives.
    pub user: Option<String>,
}
```

```rust
/// Mutable per-session state owned by the reader task.
#[derive(Debug)]
pub struct Session {
    pub key: u64,
    pub ip: IpAddr,
    pub authenticated: bool,
    /// Fingerprint of the bound user (set once, on the first `0x0C`).
    pub user: Option<String>,
}

impl Session {
    pub fn new(key: u64, ip: IpAddr) -> Self {
        Self { key, ip, authenticated: false, user: None }
    }
}
```

In `run_session`, after the connect-registry block (lines 203-206), add a users push:

```rust
        self.sessions.insert(session_key, meta);
        self.stats.bump_sessions();
        self.tui.set_stats(self.sessions.len());
        self.tui.set_sessions(self.session_rows());
        self.tui.set_users(self.user_rows());
```

Replace the disconnect block (lines 471-480):

```rust
        cleanup_session_state(
            &self.sessions,
            &self.stats,
            &self.users,
            &self.auth_nonces,
            &self.auth_attempts,
            &self.key_exchange_store,
            session_key,
        );
        self.tui.set_stats(self.sessions.len());
        self.tui.set_sessions(self.session_rows());
        self.tui.set_users(self.user_rows());
```

Replace `cleanup_session_state` (lines 486-499) with a version that releases the user (extract the meta via `remove` so we read the fingerprint before the entry disappears):

```rust
/// Remove all state belonging to a finished session. Kept separate so the
/// disconnect cleanup invariant can be regression-tested without a live QUIC
/// endpoint.
fn cleanup_session_state(
    sessions: &DashMap<u64, SessionMeta>,
    stats: &ServerStats,
    users: &UserRegistry,
    auth_nonces: &DashMap<u64, (Vec<u8>, Instant)>,
    auth_attempts: &DashMap<u64, AtomicU32>,
    key_exchange_store: &DashMap<u64, Vec<Vec<u8>>>,
    session_key: u64,
) {
    if let Some((_, meta)) = sessions.remove(&session_key) {
        if let Some(fp) = meta.user {
            users.release_session(&fp);
        }
    }
    stats.drop_session();
    auth_nonces.remove(&session_key);
    auth_attempts.remove(&session_key);
    key_exchange_store.remove(&session_key);
}
```

Add the import at the top of `src/relay/session.rs` (next to the existing `crate::relay` import, line 21):

```rust
use crate::relay::users::UserRegistry;
```

Update the two existing tests in `src/relay/session.rs` `mod tests`:

- `session_meta_carries_auth_flag` (lines 511-521): add `user: None,` to the `SessionMeta` literal.
- `session_cleanup_releases_registry_entry_and_session_counter` (lines 570-605): add a `users` registry, pass it as the third arg to `cleanup_session_state` (it can stay unbound for that test):

```rust
        let sessions: DashMap<u64, SessionMeta> = DashMap::new();
        let stats = ServerStats::new();
        let users = UserRegistry::new();
        let auth_nonces = DashMap::new();
        let auth_attempts = DashMap::new();
        let key_exchange_store = DashMap::new();
        // ... insert with `user: None,` ...
        cleanup_session_state(
            &sessions,
            &stats,
            &users,
            &auth_nonces,
            &auth_attempts,
            &key_exchange_store,
            7,
        );
```

In `src/relay/mod.rs`:

Register the import (next to `use crate::relay::stats` — actually in the `use crate::ui` area, add a `use` for the registry). Add the `users` field to `RelayServer` (after `key_exchange_store`, line 118):

```rust
    /// Stored key exchange packets per session, replayed to newly authenticated peers.
    key_exchange_store: Arc<DashMap<u64, Vec<Vec<u8>>>>,
    /// Ephemeral user registry (spec: user system) keyed by public-key hash.
    users: Arc<users::UserRegistry>,
```

In `RelayServer::new`, initialize it (next to `key_exchange_store` in the struct literal, line 186):

```rust
            key_exchange_store: Arc::new(DashMap::new()),
            users: Arc::new(users::UserRegistry::new()),
```

Replace `session_rows` (lines 388-399) to map fingerprints to aliases, and add `user_rows`:

```rust
    /// Snapshot the live-session registry as rows for the TUI sessions panel.
    fn session_rows(&self) -> Vec<crate::ui::view::SessionRow> {
        self.sessions
            .iter()
            .map(|entry| {
                let user = entry
                    .value()
                    .user
                    .as_deref()
                    .and_then(|fp| self.users.alias_of(fp));
                crate::ui::view::SessionRow {
                    key: *entry.key(),
                    ip: entry.value().ip,
                    authenticated: entry.value().authenticated,
                    user,
                    connected_at: entry.value().connected_at,
                }
            })
            .collect()
    }

    /// Snapshot the user registry as rows for the TUI users panel.
    fn user_rows(&self) -> Vec<crate::ui::view::UserRow> {
        self.users.rows()
    }
```

In `src/relay/auth.rs`:

In the `Opcode::KeyExchangeKemDsa` arm, after the existing relay/store code (after line 307, before `Ok(())`), add the user binding:

```rust
            // Derive the user identity from the KEM public key (no wire change).
            // First 0x0C of a session binds it to the user; a re-sent 0x0C
            // (peer key request) only refreshes last_seen.
            if session.user.is_none() {
                if let Some(fp) = crate::relay::users::fingerprint_of_keyexchange(packet_data) {
                    let alias = relay.users.bind_session(&fp);
                    session.user = Some(fp);
                    relay.tui.set_users(relay.user_rows());
                    debug!(
                        "[KEYEX] Session {} bound to user {}",
                        session_key, alias
                    );
                }
            } else if let Some(fp) = &session.user {
                relay.users.touch(fp);
                relay.tui.set_users(relay.user_rows());
            }
```

In the `Opcode::Data` arm, inside the `Ok(n) =>` branch (after `relayed_bytes`, line 257), add:

```rust
                Ok(n) => {
                    debug!("[DATA] Session {} broadcast OK to {} receivers", session_key, n);
                    relay.stats.relayed_msgs.fetch_add(1, Ordering::Relaxed);
                    relay.stats.relayed_bytes.fetch_add(payload.len(), Ordering::Relaxed);
                    // Attribute authorship to the bound user (metadata only).
                    if let Some(fp) = &session.user {
                        relay.users.record_message(fp);
                        relay.tui.set_users(relay.user_rows());
                    }
                }
```

In `src/relay/housekeeping.rs`, after `self.tui.set_sessions(self.session_rows());` (line 95), add:

```rust
                self.tui.set_sessions(self.session_rows());
                self.tui.set_users(self.user_rows());
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --locked && cargo build --locked`
Expected: all tests green (83 existing + new ones in `session::tests`); clean build.

- [ ] **Step 5: Commit**

```bash
git add src/relay/mod.rs src/relay/session.rs src/relay/auth.rs src/relay/housekeeping.rs
git commit -m "feat(relay): bind sessions to users, count msgs_sent, release on disconnect"
```

---

### Task 5: `ui::draw` — three-column layout + Users panel

**Files:**
- Modify: `src/ui/draw.rs` (layout constants, `layout_tier` helper, `draw_users`, column helpers, tests)
- Test: unit tests inside `src/ui/draw.rs`

**Interfaces:**
- Consumes: `ui::view::{UserRow, live_total_online}`, `sessions: &[SessionRow]` with `user`/`connected_at` (Task 1), `users: &[UserRow]` (Task 3).
- Produces: `ui::draw::layout_tier(width: u16, height: u16) -> LayoutTier` (`Compact | TwoColumn | ThreeColumn`) and `pub const` thresholds used by `draw`.

- [ ] **Step 1: Write the failing test**

In `src/ui/draw.rs`, inside the existing `mod tests`, add:

```rust
    #[test]
    fn layout_tier_thresholds() {
        // Compact below 90 cols or below 24 rows.
        assert_eq!(layout_tier(89, 30), LayoutTier::Compact);
        assert_eq!(layout_tier(120, 23), LayoutTier::Compact);
        // Two columns in the 90..124 band.
        assert_eq!(layout_tier(90, 24), LayoutTier::TwoColumn);
        assert_eq!(layout_tier(124, 24), LayoutTier::TwoColumn);
        // Three columns at >= 125.
        assert_eq!(layout_tier(125, 24), LayoutTier::ThreeColumn);
        assert_eq!(layout_tier(300, 40), LayoutTier::ThreeColumn);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --locked draw::tests::layout_tier_thresholds`
Expected: compile error — `layout_tier` and `LayoutTier` are not defined.

- [ ] **Step 3: Implement the layout**

In `src/ui/draw.rs`:

Add the `UserRow` + `live_total_online` import (extend line 22-23):

```rust
use crate::ui::view::{CertView, LogRecord, ServerInfo, SessionRow, UserRow, ServerStats};
use crate::ui::view::{compute_scroll, fmt_duration, live_total_online};
```

Update the module doc comment (lines 1-8) to describe the responsive tiers:

```rust
//! TUI rendering: layout, panels, log viewport, QR, status bar.
//!
//! Responsive layout (spec: three-column redesign):
//!   >=125 cols × >=24 rows: Server|QR|Cert | Users + Sessions | Logs
//!   90..124 cols × >=24 rows: Server|QR|Cert | Users + Sessions + Logs
//!   otherwise: logs + status bar only
```

Add the constants after `THEME`/`UiTheme` (e.g. after line 57):

```rust
/// Left column width (Server/QR/Cert) in the full layout.
const LEFT_COL_WIDTH: u16 = 42;
/// Middle column width (Users + Sessions) in the three-column layout.
const MIDDLE_COL_WIDTH: u16 = 44;
/// Minimum width for the three-column layout (two-column below this).
const THREE_COL_MIN_WIDTH: u16 = 125;
/// Minimum width for the full (non-compact) layout.
const FULL_MIN_WIDTH: u16 = 90;
/// Minimum height for the full (non-compact) layout.
const FULL_MIN_HEIGHT: u16 = 24;

/// Which column tier to render for a given terminal size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutTier {
    /// Logs + status bar only (< 90 cols or < 24 rows).
    Compact,
    /// Left column + right column (Users + Sessions + Logs).
    TwoColumn,
    /// Left + middle (Users + Sessions) + right (Logs).
    ThreeColumn,
}

/// Pure decision helper so the responsive thresholds are unit-testable.
pub fn layout_tier(width: u16, height: u16) -> LayoutTier {
    if width < FULL_MIN_WIDTH || height < FULL_MIN_HEIGHT {
        LayoutTier::Compact
    } else if width >= THREE_COL_MIN_WIDTH {
        LayoutTier::ThreeColumn
    } else {
        LayoutTier::TwoColumn
    }
}
```

In `draw`, replace the full-layout `else` block (lines 169-201) with tier dispatch using `layout_tier`:

```rust
        if state.panel_mode == PanelMode::Hidden {
            // Left column hidden: logs span full width.
            draw_logs(f, main_area, &filtered, state);
        } else {
            match layout_tier(area.width, area.height) {
                LayoutTier::ThreeColumn => {
                    // Server/QR/Cert | Users + Sessions | Logs
                    let cols = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([
                            Constraint::Length(LEFT_COL_WIDTH),
                            Constraint::Length(MIDDLE_COL_WIDTH),
                            Constraint::Min(30),
                        ])
                        .split(main_area);
                    draw_left_column(f, cols[0], state, info, stats, cert);
                    draw_middle_column(f, cols[1], users, sessions);
                    draw_logs(f, cols[2], &filtered, state);
                }
                LayoutTier::TwoColumn => {
                    // Server/QR/Cert | Users + Sessions + Logs
                    let cols = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([Constraint::Length(LEFT_COL_WIDTH), Constraint::Min(30)])
                        .split(main_area);
                    draw_left_column(f, cols[0], state, info, stats, cert);
                    draw_right_column(f, cols[1], users, sessions, &filtered, state);
                }
                LayoutTier::Compact => {
                    // `full` is false on this path; unreachable here. Kept for
                    // exhaustiveness — compact rendering is handled above.
                    draw_logs(f, main_area, &filtered, state);
                }
            }
        }
```

Also change the `full` computation (line 130) to use the constants:

```rust
        let full = area.width >= FULL_MIN_WIDTH && area.height >= FULL_MIN_HEIGHT;
```

Add the three new helper functions after `draw_cert_info` (before `draw_sessions`):

```rust
/// Left column: Server info (if Full) + QR + Cert. QrOnly → QR only.
fn draw_left_column(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &TuiState,
    info: &ServerInfo,
    stats: &ServerStats,
    cert: &CertView,
) {
    if state.panel_mode == PanelMode::Full {
        let left_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Min(7), Constraint::Min(5)])
            .split(area);
        draw_info(f, left_rows[0], info, stats);
        draw_qr(f, left_rows[1], cert);
        draw_cert_info(f, left_rows[2], cert);
    } else {
        // QrOnly: QR takes the whole left column.
        draw_qr(f, area, cert);
    }
}

/// Middle column (three-column mode): Users on top, Sessions below.
fn draw_middle_column(
    f: &mut ratatui::Frame,
    area: Rect,
    users: &[UserRow],
    sessions: &[SessionRow],
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(5)])
        .split(area);
    draw_users(f, rows[0], users);
    draw_sessions(f, rows[1], sessions);
}

/// Right column (two-column fallback): Users + Sessions + Logs.
fn draw_right_column(
    f: &mut ratatui::Frame,
    area: Rect,
    users: &[UserRow],
    sessions: &[SessionRow],
    filtered: &[&LogRecord],
    state: &TuiState,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Length(8), Constraint::Min(5)])
        .split(area);
    draw_users(f, rows[0], users);
    draw_sessions(f, rows[1], sessions);
    draw_logs(f, rows[2], filtered, state);
}

/// Users panel: every user ever seen, with live online state and totals.
fn draw_users(f: &mut ratatui::Frame, area: Rect, users: &[UserRow]) {
    let now = std::time::Instant::now();
    let mut lines: Vec<Line> = Vec::new();
    for row in users.iter().take(100) {
        let dot = if row.online {
            Span::styled("●", Style::default().fg(THEME.ok))
        } else {
            Span::styled("○", Style::default().fg(THEME.dim))
        };
        // Live online time: accumulated + the delta of the active session,
        // recomputed each frame so it ticks without extra pushes.
        let online = live_total_online(row.total_online, row.connected_at, now);
        let fp8 = row.fingerprint.get(..8).unwrap_or(&row.fingerprint);
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:<4}", row.alias),
                Style::default().fg(THEME.header).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{fp8}  "), Style::default().fg(THEME.dim)),
            dot,
            Span::styled(
                format!(" {:>12} ", fmt_duration(online.as_secs())),
                Style::default().fg(THEME.value),
            ),
            Span::styled(format!("{} msgs", row.msgs_sent), Style::default().fg(THEME.dim)),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "no users yet",
            Style::default().fg(THEME.dim),
        )));
    }
    let block = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(" Users ")
                .border_style(Style::default().fg(THEME.border)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(block, area);
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --locked draw::tests && cargo build --locked`
Expected: `draw::tests::layout_tier_thresholds` passes; clean build.

- [ ] **Step 5: Manual smoke (if a terminal is available) and commit**

Manual: run the server in a terminal ≥ 125 cols wide, connect the two phones, send a message; verify three columns render, Users shows `U1`/`U2` with live `●`/`○` and ticking online time, Sessions rows are tagged with aliases, and the QR renders fully.

```bash
git add src/ui/draw.rs
git commit -m "feat(ui): three-column layout with Users panel and live online time"
```

---

### Task 6: Integration regression — fingerprint matches the real client wire format

**Files:**
- Modify: `tests/relay.rs` (new regression test)
- Test: `tests/relay.rs`

**Interfaces:**
- Consumes: `relay::users::fingerprint_of_keyexchange` (Task 2) and the existing `build_key_exchange` helper in `tests/relay.rs`.

- [ ] **Step 1: Write the regression test**

Append to `tests/relay.rs` (after the `skip_byte_resilience` test at the end of the file):

```rust
#[test]
fn fingerprint_of_keyexchange_matches_client_id() {
    // ML-KEM-768 / ML-DSA-65 public-key sizes, as sent by the Android client
    // in the 0x0C KeyExchangeKemDsa packet right after auth.
    let kem = vec![0x5Au8; 1184];
    let dsa = vec![0x6Bu8; 1952];
    let packet = build_key_exchange(&kem, &dsa);

    let fp = impulse_server::relay::users::fingerprint_of_keyexchange(&packet)
        .expect("valid 0x0C frame yields a fingerprint");
    assert_eq!(fp.len(), 32);
    // Golden value: SHA-256(0x5A repeated 1184 times) hex, truncated to 32 —
    // exactly the client's SecureKeyManager.fingerprintForBytes output.
    assert_eq!(fp, "383e3a1e042cf51407cb723ec48b958e");

    // The frame the server relays to peers is byte-identical to the client's.
    assert_eq!(packet[0], 0x0C);
    assert_eq!(try_read_packet(&packet), TryReadResult::Packet(packet.len()));
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `cargo test --locked --test relay fingerprint_of_keyexchange_matches_client_id`
Expected: PASS (the golden value was precomputed against the module's own SHA-256).

- [ ] **Step 3: Run the full suite and commit**

Run: `cargo test --locked && cargo build --locked`
Expected: all tests green; clean build.

```bash
git add tests/relay.rs
git commit -m "test(relay): fingerprint matches client KEM-derived id"
```

---

### Task 7: Docs — module overview + README TUI section

**Files:**
- Modify: `src/lib.rs` (module overview bullets)
- Modify: `README.md` (TUI section, lines 52-63)

**Interfaces:**
- Consumes: nothing (docs only).

- [ ] **Step 1: Update `src/lib.rs` module overview**

Replace lines 10-12:

```rust
//! * `relay` — WebTransport endpoint, session handling, broadcast relay,
//!   auth handshake (`relay::auth`), and housekeeping (`relay::housekeeping`).
//!   `relay::users` tracks per-user stats keyed by the KEM public-key hash.
//! * `ui` — terminal UI: Server/Users/Sessions panels, TOFU QR, live stats,
//!   log view.
```

- [ ] **Step 2: Update the README TUI section**

Replace the `**Admin:**` bullet (README.md lines 52-63) with:

```markdown
- **Admin:** a **TUI** with a responsive three-column layout:
  - **Left column** (Info + QR + Certificate): server bind address, transport
    (`WebTransport/QUIC TLS1.3 (h3)`), crate version, SAN count, live
    `sessions / MAX_SESSIONS`, stored message count, message TTL, max payload
    size, certificate SHA-256 fingerprint (short), cert expiry countdown, a
    ⚠ rotating indicator during key overlap, and a scannable QR code.
  - **Middle column** (Users on top, Sessions below): every user ever seen —
    `U{n}` alias, first 8 hex of the client public-key fingerprint, ● online /
    ○ offline, live total online time and messages sent — plus the live session
    table, each row tagged with its bound user alias.
  - **Right column** (Logs, widest): live server log stream with level filters
    `1`–`5` (ERR/WRN/INF/DBG/TRC), scroll (`↑↓`/`PgUp`/`PgDn`/`Home`/`End` or
    mouse wheel), search (`/`), `Space` to pause, and `Shift+C` to copy all logs
    to clipboard. `Tab` cycles the left column (full → QR-only → hidden); `f`
    focuses the QR code. Below ~125 columns the middle column folds into the
    right (Users + Sessions + Logs); below ~90 columns only the logs remain.
    The status bar shows live throughput, uptime, active filters and hints.
  `Ctrl+C` / `q` quits and shuts down gracefully.
```

- [ ] **Step 3: Verify and commit**

Run: `cargo build --locked`
Expected: clean build (docs only).

```bash
git add src/lib.rs README.md
git commit -m "docs: user registry + three-column TUI in module docs and README"
```

---

## Self-Review Notes

- **Spec coverage:** identity formula (§1) → Tasks 2+4+6; registry/lifecycle (§1) → Tasks 2+4; TUI tiers (§2) → Task 5; view models (§2) → Task 1; `TuiHandle.set_users` (§2) → Task 3; UI bug fixes (§3, all three) → Tasks 1+4; implementation order (§:Implementation Order) → matches; verification → Task steps 4 + Task 6.2 + Task 5.5 manual smoke.
- **No placeholders:** every code step contains complete code; no `TBD`/`implement later`.
- **Type consistency:** `UserRow`, `SessionRow`, `live_total_online`, `UserRegistry` methods, `fingerprint_of_keyexchange`, `cleanup_session_state` signature, `layout_tier`/`LayoutTier` are defined once and used by exactly the same names in every later task.
- **Deviations from the spec sketch (deliberate):** `UserRow` carries `connected_at: Option<Instant>` (the spec's struct sketch omits it, but §2/§3 require live online time recomputed per draw without pushes); `SessionMeta.user` stores the *fingerprint* (map key) while `SessionRow.user` stores the *alias* (resolved via `alias_of`), matching the spec's field semantics.
