# User System + Per-User Stats + 3-Column TUI — Design

> Status: draft (awaiting user review).
> Implements user request: "нужно сделать систему пользователей, показ онлайн или нет, сессии перемести влево вниз, чуть расширь левую колонку, статистика по пользователям в менеджере, определять по хешам публичных ключей".

## Goal

Add an ephemeral (RAM-only) user registry to the relay server, keyed by the
public-key hash the client already generates, show online/offline status and
per-user statistics in the TUI, restructure the TUI into three columns (info |
users+sessions | logs), and fix the stale-UI bugs found during design. No wire
protocol changes; no client changes required.

## Scope

- User identity derived from the ML-KEM-768 public key sent in the existing
  `0x0C KeyExchangeKemDsa` packet (client sends it right after auth;
  ChatController.kt:913).
- RAM-only `UserRegistry` (`DashMap`), lifetime = server lifetime.
- Per-user stats: alias (`U1`, `U2`, …), fingerprint, `first_seen`, `last_seen`,
  `total_online`, `active_sessions`, `msgs_sent`.
- Session ↔ user binding; live "online" indicator (all users ever seen, ●/○).
- TUI: three-column layout ≥ ~125 cols; two-column fallback below; compact
  (< 90) unchanged. Left column (≈40) = Server + QR + Cert; middle (≈44) =
  Users + Sessions; right = Logs (widest).
- Bug fixes: session list not pushed on disconnect; frozen `age`; stale
  user/session snapshots.

## Non-Goals

- **No wire-protocol changes.** Opcodes and packet shapes stay byte-compatible;
  the server only *parses* the already-relayed public key, it never decrypts.
  Server blindness is preserved: public keys are public, `msgs_sent` is metadata.
- **No client changes.** Identity reuse, proof-of-possession, and 1:1 private
  messages are deferred (private messages are a client-side change only).
- No persistence of the registry (ephemeral by design; stats live for server
  uptime only).
- No new dependencies.

## Future Work (deferred, not in this spec)

- **Client participant list ("список участников")**: clients want to know the
  set of users on the server and their online state. Natural next phase after
  this spec — the server already tracks users, so it can emit online/offline
  presence notifications. Solves the real key-discovery problem: today a sender
  can only encrypt to recipients whose key was cached while both were online
  (0x0C relay); offline delivery itself already works via 72 h `MessageStore`
  + `0x03 Sync`.
- **1:1 private messages**: client-side only — encrypt to a chosen recipient
  (plus self) instead of all cached keys. Server relay logic unchanged.
- **Proof-of-possession** (sign a nonce with the DSA key) to harden identity
  against replay of another device's public key.

---

## 1. User Identity & Registry

### Identity formula

- `fingerprint = lowercase-hex(SHA-256(KEM public key)).take(32)` — identical to
  the client's `SecureKeyManager.fingerprintForBytes` (SecureKeyManager.kt:103),
  so the admin ID matches the ID the client shows and the `recipientId` inside
  per-recipient blobs.
- Derived on the server from the `0x0C` payload:
  `[0x0C] [u32 inner_len] [u32 kem_len] [kem] [u32 dsa_len] [dsa]` — read two
  length prefixes, take the KEM key bytes, hash. Current code only relays the
  raw packet (auth.rs:280-310); parsing is new.
- **Forgery posture (decision A):** the hash prevents *claiming an existing
  user's ID* (preimage resistance) but does not prove key ownership — a
  malicious client could replay another device's public key and appear as that
  user in the admin panel. Impact is limited to stats pollution; content stays
  safe (no private key = cannot decrypt). Proof-of-possession (sign a nonce with
  the DSA key) is explicitly deferred as a follow-up.

### Registry

```
UserStats {
  fingerprint: String,        // key of the map
  alias: u32,                 // 1 → "U1", assigned by first_seen order
  first_seen: Instant,
  last_seen: Instant,
  total_online: Duration,     // accumulated across sessions (server lifetime)
  active_sessions: usize,     // currently connected sessions for this user
  msgs_sent: u64,             // DATA packets authored by this user
}
```

- Stored in `RelayServer.users: Arc<DashMap<String, UserStats>>`.
- `SessionMeta` gains `user: Option<String>` (the fingerprint), set when the
  first `0x0C` is parsed for that session; `None` until then.
- Alias assignment: monotonically increasing counter; `U{alias}` displayed.

### Lifecycle

- **First `0x0C` from a session** (auth.rs, `Opcode::KeyExchangeKemDsa`):
  parse KEM key → fingerprint → `users.entry(fingerprint)` → insert new
  `UserStats` (alias = next counter) or update existing; set `first_seen` on
  insert; set `session.user`. `active_sessions` is bumped **only when
  `session.user` transitions from `None` to `Some`** (guards the re-sent
  `0x0C` on peer key requests from double-counting). Every `0x0C` refreshes
  `last_seen`.
- **Session connect** (session.rs): nothing user-specific until `0x0C` arrives.
- **Session disconnect** (cleanup_session_state): if `session.user` is set,
  `active_sessions -= 1`, `total_online += now - connected_at`, `last_seen = now`.
- **DATA message** (auth.rs, `Opcode::Data`, after successful broadcast):
  `users[session.user].msgs_sent += 1` (metadata; payload untouched).
- Sessions that disconnect before sending `0x0C` contribute no user record.

---

## 2. TUI Redesign (three columns)

### Responsive tiers

| Width | Layout |
|-------|--------|
| `>= ~125` | **Three columns**: left (≈40) Server+QR+Cert · middle (≈44) Users+Sessions · right (rest) Logs |
| `90..124` | **Two columns**: left Server+QR+Cert · right Users+Sessions+Logs (current right-col split, extended) |
| `< 90` or rows `< 24` | Compact: Logs + status bar (unchanged) |

Thresholds are constants; exact middle-column width derived so the logs column
gets the remainder (widest).

### Three-column sketch

```
┌ Server ──────────┐ ┌ Users ─────────────┐ ┌ Logs ────────────────────────────┐
│ Listen: ...      │ │ U1 ab12cd34 ● 0:12 │ │ ...                             │
│ Transport: ...   │ │ U2 09f8e7d6 ○ 0:04 │ │ ...                             │
│ Version: ...     │ ├ Sessions ──────────┤ │ ...                             │
│ Uptime: ...      │ │ 12 192.168.1.5 ✓U1 │ │ ...                             │
│ Sessions 2/1024  │ │ 17 192.168.1.9 ✓U2 │ └─────────────────────────────────┘
│ Msgs 5 · Peak 2  │ └────────────────────┘
├ QR ──────────────┤
│ (full QR)        │
├ Cert ────────────┤
│ fingerprint: ... │
└──────────────────┘
```

- **Users panel** (middle, top): every user ever seen (server lifetime). Row:
  `U{n} · {first 8 hex of fingerprint} · ●/○ · {total_online} · {msgs_sent}`.
  Online = `active_sessions > 0`. Total-online shown live (accumulated +
  currently-active deltas), recomputed each draw.
- **Sessions panel** (middle, bottom): current rows, each tagged with its user
  alias (`U1`); auth marker stays `✓/·` (all live sessions are "online" by
  definition — the auth state is the meaningful distinction).
- **Left column**: unchanged content (Server info, QR, Cert), QR stays full-size
  (user: "логи вообще справа, так что все оставляй, там должно уместиться").
- **Right column**: logs span full remaining width.

### View model changes (`ui/view.rs`)

- New `UserRow { alias: String, fingerprint: String, online: bool, total_online: Duration, msgs_sent: u64 }`.
- `SessionRow`: replace `age: Duration` with `connected_at: Instant`; add
  `user: Option<String>` (alias of the bound user).
- `TuiHandle`: new `set_users(Vec<UserRow>)` mirroring `set_sessions`.

---

## 3. UI Update Bug Fixes

1. **Disconnect does not refresh sessions** (session.rs:479 calls only
   `set_stats`): after `cleanup_session_state`, also push `set_sessions(...)`
   and `set_users(...)`.
2. **Frozen `age`**: `SessionRow.age` was computed at snapshot time (60 s
   housekeeping cadence). Fix: ship `connected_at: Instant`; `draw_sessions`
   computes `now - connected_at` per frame.
3. **Stale users/stats**: `set_users` pushed on connect / first-`0x0C` /
   disconnect / DATA; 60 s housekeeping tick retained as a safety net.
   Online time is derived live in `draw` from `connected_at`, so it ticks
   without extra pushes.

---

## Implementation Order

1. `relay`: parse KEM key from `0x0C` (helper `fingerprint_of_keyexchange(packet)`),
   add `UserStats`/`users` map, `SessionMeta.user`, alias counter.
2. `relay/auth.rs`: bind user on first `0x0C`; count `msgs_sent` on DATA.
3. `relay/session.rs`: cleanup decrements `active_sessions`, accumulates
   `total_online`; push `set_sessions`/`set_users` on disconnect.
4. `ui/view.rs`: `UserRow`, `SessionRow` rework, `TuiHandle.set_users`.
5. `ui/draw.rs`: three-column layout + Users panel + live age/online time.
6. Regression tests: keyexchange fingerprint parsing; registry lifecycle
   (bind/accumulate/cleanup); layout thresholds (pure helpers).
7. Docs: lib.rs module docs, README TUI section.

## Verification

- `cargo test --locked` green (existing 83 + new).
- `cargo build --locked` clean.
- Manual TUI smoke at ≥125 cols: three columns render, Users shows all seen
  users with live ●/○ and ticking online time, Sessions tagged with aliases,
  disconnect removes the row immediately, QR renders fully.
- Manual: two-column fallback at ~100 cols, compact below 90.
- Server blindness spot-check: logs contain no decrypted payloads; only key
  hashes and message counts are exposed.
