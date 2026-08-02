# Server Restructure + Bug Fixes + TUI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure `impulse-server` into domain folders, fix 7 confirmed bugs, redesign the TUI (controls, live stats, event-driven rendering), add CI tests, and ship **v2.6.0**.

**Architecture:** Split monolith files (`server.rs` 1244 lines, `tui.rs` 785, `tests.rs` 2122) into `relay/`, `protocol/`, `config/`, `cli/`, `crypto/`, `ui/`, `storage/`, `cert/`, `logging/` domain modules. Remove a reverse dependency (`protocol → server`), make `argon2_hash` fallible (panic=abort safety), fix the orphaned-task and storage-ordering races, and rebuild the TUI around event-driven rendering with live `ServerStats`.

**Tech Stack:** Rust 2024 edition, tokio 1 (full), wtransport 0.7 (quinn), ratatui 0.30, crossterm 0.29, dashmap 6, crossbeam-channel 0.5, argon2 0.5, hmac 0.12, sha2 0.10, qrcode 0.14, tui-qrcode 0.2, copypasta 0.10, tracing 0.1, clap 4 (derive), toml 0.8, serde 1, anyhow 1.

## Global Constraints

- **No wire-protocol changes.** Opcodes, packet shapes, and the Argon2/HMAC handshake stay byte-compatible. All existing client behavior preserved.
- **No new dependencies.** Use ratatui/crossterm already in Cargo.toml. Do NOT add crates.
- **No new user-facing server features** beyond the TUI; no API/CLI surface changes except the approved fixes.
- **`panic = "abort"`** in release profile (Cargo.toml:84): no `.expect()`/`.unwrap()` on fallible crypto paths; `argon2_hash` returns `anyhow::Result<String>`.
- **Version floor:** this plan ships as `2.6.0` — bump happens in Task 7, not earlier.
- **Reverse dependency:** `protocol` must NOT import anything from `server`/`relay`. `protocol/framing.rs` depends only on `protocol`.
- **Naming:** unify tests to `snake_case` (drop `test_` prefix and `*_tests` module suffix where the spec calls for it).
- **Test command:** `cargo test --locked` must pass on Windows with pristine output (no warnings). Existing 69 tests keep passing after each task.
- **Move-only rule:** `git mv` for pure relocations to preserve history; do not copy+delete unless the file is heavily rewritten.
- **Repository root:** `D:\Data\Projects\ImpulseProject\server`. Shell is PowerShell 7; `cargo` on PATH, `git` via `C:\Program Files\Git\cmd\git.exe`.

---

### Task 1: Extract `protocol/limits.rs` + `protocol/framing.rs`; kill the `protocol→server` reverse dep

**Files:**
- Create: `src/protocol/limits.rs`
- Create: `src/protocol/framing.rs`
- Modify: `src/protocol.rs` (debug_assert now references `limits::MAX_PAYLOAD_BYTES`; add `pub mod` for both children)
- Modify: `src/server.rs` (remove `try_read_packet`/`TryReadResult`, `opcode_name`, `hex_dump`; import limits from `protocol::limits`; add `Opcode::display_name()` usage)
- Test: `src/protocol/framing.rs` (`#[cfg(test)] mod`)

**Interfaces:**
- Consumes: `crate::protocol::PacketWriter`, `Opcode` (already exist).
- Produces: `pub const MAX_PAYLOAD_BYTES: usize` in `protocol/limits.rs` (moved from server.rs:61); `pub const MAX_STREAM_BUFFER: usize` (moved from server.rs:64); `pub const MAX_PACKET_LEN: usize` (defined as `1 + 4 + MAX_PAYLOAD_BYTES`, replacing the local const at server.rs:1215); `pub enum TryReadResult { Packet(usize), Incomplete, UnknownOpcode, OversizedPayload }` (was `pub(crate)` at server.rs:1185); `pub fn try_read_packet(buf: &[u8]) -> TryReadResult` (was `pub(crate)` at server.rs:1198). `Opcode::display_name(&self) -> &'static str` (replaces `opcode_name`).

- [ ] **Step 1: Write the failing test**

In `src/protocol/framing.rs` add a `#[cfg(test)] mod tests` at the bottom:

```rust
#[cfg(test)]
mod tests {
    use super::{TryReadResult, try_read_packet};
    use crate::protocol::{Opcode, PacketWriter};

    fn data_frame(payload_len: usize) -> Vec<u8> {
        let mut w = PacketWriter::with_opcode(Opcode::Data);
        w.write_len_prefixed(&vec![0u8; payload_len]);
        w.into_bytes()
    }

    #[test]
    fn packet_detection_for_each_opcode() {
        assert_eq!(try_read_packet(&[0x99]), TryReadResult::UnknownOpcode);
        assert_eq!(try_read_packet(&[]), TryReadResult::Incomplete);
        // Data: opcode + u32 len + payload
        assert_eq!(try_read_packet(&data_frame(10)), TryReadResult::Packet(1 + 4 + 10));
        // Truncated Data header
        assert_eq!(try_read_packet(&[0x05, 0x00]), TryReadResult::Incomplete);
        // Sync: opcode + u64
        assert_eq!(try_read_packet(&[0x03, 1, 2, 3, 4, 5, 6, 7, 8]), TryReadResult::Packet(9));
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let mut w = PacketWriter::with_opcode(Opcode::Data);
        w.write_u32(u32::MAX);
        assert_eq!(try_read_packet(&w.into_bytes()), TryReadResult::OversizedPayload);
    }

    #[test]
    fn auth_uses_minimum_length_with_hmac() {
        // 0x01 + len-prefixed pwd + 32 raw HMAC
        let mut w = PacketWriter::with_opcode(Opcode::Auth);
        w.write_len_prefixed(b"pw");
        w.write_raw(&[0u8; 32]);
        let bytes = w.into_bytes();
        assert_eq!(try_read_packet(&bytes), TryReadResult::Packet(bytes.len()));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --locked protocol::framing` (add a `pub mod framing;` stub first if needed, or run after Step 3's file creation; the intent here is a RED on `try_read_packet` being unavailable at the new path).

Expected: FAIL — `try_read_packet` not found under `crate::protocol::framing`.

- [ ] **Step 3: Create `src/protocol/limits.rs`**

```rust
//! Packet-size and buffering limits — single source of truth for the wire codec.

/// Max incoming message payload size (bytes) to bound memory.
pub const MAX_PAYLOAD_BYTES: usize = 1_000_000;

/// Max bytes buffered from a single stream before we give up (defensive).
pub const MAX_STREAM_BUFFER: usize = 8 * 1024 * 1024;

/// Largest acceptable full packet: opcode byte + u32 length + payload.
pub const MAX_PACKET_LEN: usize = 1 + 4 + MAX_PAYLOAD_BYTES;
```

- [ ] **Step 4: Create `src/protocol/framing.rs`**

Move `TryReadResult` (server.rs:1183-1195) and `try_read_packet` (server.rs:1197-1244) here verbatim, with two changes: `pub` instead of `pub(crate)`, and `MAX_PACKET_LEN`/`MAX_PAYLOAD_BYTES` referenced as `crate::protocol::limits::*`:

```rust
//! Length-prefixed packet framing over the WebTransport stream.
//!
//! `try_read_packet` inspects a byte buffer and reports whether a complete,
//! well-formed packet is available, how long it is, or why it must be skipped /
//! the session closed. Moved here from `server.rs` so the codec has no
//! dependency on the relay.

use crate::protocol::limits::{MAX_PACKET_LEN, MAX_PAYLOAD_BYTES};

/// Result of [`try_read_packet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryReadResult {
    /// A full packet is available (consumable now). Inner is the packet length.
    Packet(usize),
    /// Buffer is incomplete; wait for more bytes.
    Incomplete,
    /// Leading byte is not a recognized client opcode — skip 1 byte and retry.
    UnknownOpcode,
    /// The declared payload length exceeds [`MAX_PACKET_LEN`] — the session
    /// must be closed because the stream is corrupted beyond recovery.
    OversizedPayload,
}

/// Try to read a complete packet length from the buffer.
pub fn try_read_packet(buf: &[u8]) -> TryReadResult {
    if buf.is_empty() {
        return TryReadResult::Incomplete;
    }
    let opcode = buf[0];
    let min_len = match opcode {
        0x01 => 1 + 4 + 32,  // Auth: opcode + len prefix + fixed 32-byte HMAC
        0x03 => 1 + 8,       // Sync: opcode + u64
        0x05 => 1 + 4,       // Data: opcode + len prefix
        0x06 => 1 + 8,       // Heartbeat: opcode + u64
        0x0C => 1 + 4,       // KeyExchangeKemDsa: opcode + len prefix
        _ => return TryReadResult::UnknownOpcode,
    };
    if buf.len() < min_len {
        return TryReadResult::Incomplete;
    }

    let len = match opcode {
        0x01 => {
            if buf.len() < 5 {
                return TryReadResult::Incomplete;
            }
            let pwd_len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            let total = 1 + 4 + pwd_len + 32;
            if total > MAX_PACKET_LEN {
                return TryReadResult::OversizedPayload;
            }
            return TryReadResult::Packet(total);
        }
        0x05 | 0x0C => {
            if buf.len() < 5 {
                return TryReadResult::Incomplete;
            }
            u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize
        }
        0x03 | 0x06 => {
            return TryReadResult::Packet(9);
        }
        _ => return TryReadResult::UnknownOpcode,
    };
    if len > MAX_PACKET_LEN {
        return TryReadResult::OversizedPayload;
    }
    TryReadResult::Packet(1 + 4 + len)
}
```

- [ ] **Step 5: Wire up `src/protocol.rs`**

At the top, after `use std::io::{self};`, add:

```rust
pub mod framing;
pub mod limits;
```

Change the `debug_assert` in `PacketWriter::write_len_prefixed` (currently protocol.rs:209) to reference the new single source:

```rust
    pub fn write_len_prefixed(&mut self, data: &[u8]) -> &mut Self {
        debug_assert!(data.len() <= limits::MAX_PAYLOAD_BYTES);
        self.write_u32(data.len() as u32);
        self.buf.extend_from_slice(data);
        self
    }
```

Add `display_name()` to `impl Opcode` (after `as_u8`, currently protocol.rs:56-58):

```rust
    /// Human-readable opcode name for logs and the TUI.
    pub fn display_name(self) -> &'static str {
        match self {
            Opcode::Auth => "Auth",
            Opcode::AuthResult => "AuthResult",
            Opcode::Sync => "Sync",
            Opcode::SyncResponse => "SyncResponse",
            Opcode::Data => "Data",
            Opcode::Heartbeat => "Heartbeat",
            Opcode::NewCertHash => "NewCertHash",
            Opcode::AuthChallenge => "AuthChallenge",
            Opcode::KeyExchangeKemDsa => "KeyExchangeKemDsa",
        }
    }
```

Delete the dead `encode_key_exchange_tagged` (protocol.rs:279-294) — grep confirms zero callers (only a stale comment at tests.rs:1211/1249). Remove the `From<ProtocolError> for io::Error` impl too if it is unused after this change (check with `cargo check`).

- [ ] **Step 6: Slim `src/server.rs`**

1. Delete `fn opcode_name` (server.rs:31-44), `fn hex_dump` (server.rs:46-58), the consts `MAX_PAYLOAD_BYTES` (server.rs:61), `MAX_STREAM_BUFFER` (server.rs:64), `TryReadResult` (server.rs:1183-1195), and `try_read_packet` (server.rs:1197-1244). Keep `MAX_TOTAL_BUFFERED_BYTES` (server.rs:69) for now — it stays in the relay (Task 3).
2. Replace the removed consts with an import; add the new imports:

```rust
use crate::protocol::limits::{MAX_PAYLOAD_BYTES, MAX_STREAM_BUFFER};
```

3. Replace every `opcode_name(op)` call with `Opcode::from_u8(op).map(|o| o.display_name()).unwrap_or("UNKNOWN")`. There are 5 such call sites (server.rs:527, 552, 576, 595, 704). Define a small local helper to keep it readable:

```rust
fn op_name(op: u8) -> &'static str {
    Opcode::from_u8(op).map(Opcode::display_name).unwrap_or("UNKNOWN")
}
```

(Keep the helper in `server.rs` until Task 3 moves it; `Opcode` is already imported at server.rs:25.)

4. In the reader task, the TRACE hex logging currently calls `hex_dump` (server.rs:642). Replace with a simpler inline format using the payload length only (it is already logged as a raw chunk; dropping the hex dump removes the dead duplicate):

```rust
                            if tracing::enabled!(tracing::Level::TRACE) {
                                trace!("[READER] Session {} raw chunk: {} bytes", session_key, n);
                            }
```

- [ ] **Step 7: Run the full test suite**

Run: `cargo test --locked`
Expected: all existing tests pass (some may move module paths in later tasks, but nothing here should fail). `try_read_packet` callers in `tests.rs` use `crate::server::try_read_packet` — since `server.rs` still exists and re-exports nothing here, add a thin re-export in `server.rs` so tests keep compiling until Task 3:

```rust
pub use crate::protocol::framing::{TryReadResult, try_read_packet};
```

- [ ] **Step 8: Commit**

```bash
git add src/protocol.rs src/protocol/limits.rs src/protocol/framing.rs src/server.rs
git commit -m "refactor(protocol): extract limits.rs and framing.rs, drop reverse dep on server"
```

---

### Task 2: Extract `crypto/` from `config.rs`; make `argon2_hash` fallible

**Files:**
- Create: `src/crypto/mod.rs`
- Modify: `src/config.rs` (remove `sha256_hex`, `argon2_hash`, `argon2_verify`)
- Modify: `src/lib.rs` (add `pub mod crypto;`)
- Modify: `src/main.rs` (`--hash-password` uses `?`)
- Modify: `src/setup.rs` (both wizards use `?`)
- Modify: `src/tests.rs` (crypto tests move/adapt; see Task 6 for the full relocation — here only keep compiling)
- Test: `src/crypto/mod.rs` (`#[cfg(test)] mod`)

**Interfaces:**
- Consumes: `argon2`, `sha2`, `hex`, `rand` (already in Cargo.toml).
- Produces: `pub fn sha256_hex(input: &str) -> String`; `pub fn argon2_hash(input: &str) -> anyhow::Result<String>`; `pub fn argon2_verify(password: &str, stored_hash: &str) -> bool`. These are the only auth primitives; `relay/auth.rs` and `main.rs`/`setup.rs` use them.

- [ ] **Step 1: Write the failing test**

Create `src/crypto/mod.rs` with a test module at the bottom:

```rust
#[cfg(test)]
mod tests {
    use super::{argon2_hash, argon2_verify, sha256_hex};

    #[test]
    fn sha256_hex_known_vector() {
        assert_eq!(
            sha256_hex("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn argon2_hash_roundtrip_and_verify() {
        let hash = argon2_hash("my_secret_password").expect("hash should succeed");
        assert!(hash.starts_with("$argon2"));
        assert!(argon2_verify("my_secret_password", &hash));
        assert!(!argon2_verify("wrong", &hash));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --locked crypto::`
Expected: FAIL — `crate::crypto` module does not exist.

- [ ] **Step 3: Implement `src/crypto/mod.rs`**

Move the three functions verbatim from `config.rs` (config.rs:287-331) into the new module, with `argon2_hash` returning `Result` instead of `.expect()`:

```rust
//! Authentication cryptography: Argon2id password hashing and verification.
//!
//! Kept separate from config so the relay's auth handshake does not depend on
//! config-file plumbing. `argon2_hash` is fallible — under `panic = "abort"`
//! (Cargo.toml release profile) an `.expect()` on a hash failure would kill the
//! whole process instead of surfacing an error.

/// SHA-256 hex of a string (used in tests).
pub fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Argon2id hash of a string (used by --hash-password).
pub fn argon2_hash(input: &str) -> anyhow::Result<String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use rand::rngs::OsRng;
    let salt = SaltString::generate(&mut OsRng);
    // Use Argon2id explicitly to match argon2_verify which uses Argon2::new(Argon2id, ...).
    // Argon2::default() may use Argon2i which would cause silent verification failures.
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    );
    argon2
        .hash_password(input.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("Argon2 hashing failed: {}", e))
}

/// Verify a password against an Argon2id encoded hash.
pub fn argon2_verify(password: &str, stored_hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let parsed = match PasswordHash::new(stored_hash) {
        Ok(p) => p,
        Err(_) => return false,
    };
    // Use params from the stored hash, not Argon2::default().
    let params = match argon2::Params::try_from(&parsed) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );
    argon2.verify_password(password.as_bytes(), &parsed).is_ok()
}
```

- [ ] **Step 4: Remove the three functions from `src/config.rs` and register the module**

Delete `sha256_hex` (config.rs:287-292), `argon2_hash` (config.rs:294-310), `argon2_verify` (config.rs:312-331). Delete the now-unused imports `use sha2...`, `use hex...` inside those functions (they are `use` inside fn bodies, so only the functions themselves go).

In `src/lib.rs`, add the module after `pub mod config;`:

```rust
pub mod crypto;
```

- [ ] **Step 5: Update call sites to `?`**

`src/main.rs` line 18:

```rust
        SetupCommand::HashPassword(pw) => {
            println!("{}", argon2_hash(&pw)?);
            return Ok(());
        }
```

`src/setup.rs` line 95 (`run_first_run_wizard`) and line 109 (`run_init_wizard`):

```rust
            password_hash: crate::crypto::argon2_hash(&password)?,
```

Update the import in `main.rs` (line 6):

```rust
use impulse_server::crypto::argon2_hash;
```

Remove `argon2_hash` from the `config` import list in `main.rs` (it becomes `use impulse_server::config::{CliArgs, config_file_loaded, load_config, resolve_command, SetupCommand};`).

- [ ] **Step 6: Keep `src/tests.rs` compiling**

The existing tests call `crate::config::argon2_hash(...)` and `crate::config::{argon2_hash, argon2_verify}` and `crate::config::{argon2_hash, sha256_hex}`. Update those import lines and the direct `crate::config::argon2_hash(...)` calls to `crate::crypto::...`, and add `.unwrap()` where a `String` was previously returned. Affected sites: tests.rs:174, 340, 357, 370, 386, 426, 451, 1445, plus `argon2_hash_roundtrip`/`argon2_wrong_password_fails` (tests.rs:237-262) — those two bodies move to `crypto/mod.rs` in Task 6, but for now adapt them in place:

```rust
    #[test]
    fn argon2_hash_roundtrip() {
        let password = "my_secret_password";
        let hash = crate::crypto::argon2_hash(password).unwrap();
        assert!(hash.starts_with("$argon2"));
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        let parsed = PasswordHash::new(&hash).expect("should parse Argon2 hash");
        let result = argon2::Argon2::default().verify_password(password.as_bytes(), &parsed);
        assert!(result.is_ok(), "Argon2 should verify correct password");
    }

    #[test]
    fn argon2_wrong_password_fails() {
        let hash = crate::crypto::argon2_hash("correct_password").unwrap();
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        let parsed = PasswordHash::new(&hash).expect("should parse Argon2 hash");
        let result = argon2::Argon2::default()
            .verify_password("wrong_password".as_bytes(), &parsed);
        assert!(result.is_err(), "Argon2 should reject wrong password");
    }
```

- [ ] **Step 7: Run the full test suite**

Run: `cargo test --locked`
Expected: PASS. Existing auth/handshake tests still verify the same Argon2 behavior.

- [ ] **Step 8: Commit**

```bash
git add src/crypto/mod.rs src/config.rs src/lib.rs src/main.rs src/setup.rs src/tests.rs
git commit -m "refactor(crypto): extract auth primitives, make argon2_hash fallible"
```

---

### Task 3: Split `server.rs` → `relay/` (mod, session, auth, housekeeping); fix orphaned tasks + session registry; add `SessionMeta` + stats

**Files:**
- Create: `src/relay/mod.rs`
- Create: `src/relay/session.rs`
- Create: `src/relay/auth.rs`
- Create: `src/relay/housekeeping.rs`
- Delete: `src/server.rs`
- Modify: `src/lib.rs` (`pub mod relay;` replaces `pub mod server;`)
- Modify: `src/tui.rs` (add `ServerStats` to the handle — see Task 5 for the full redesign; here only what Task 3 needs)
- Modify: `src/tests.rs` (import paths for `try_read_packet`; `e2e_integration_tests` import at tests.rs:1449)
- Test: `src/relay/session.rs` (unit tests for `SessionMeta`/stats), `src/tests.rs` (existing tests keep passing)

**Interfaces:**
- Consumes: `crate::protocol::{Opcode, PacketReader, RelayedMessage, ServerPacketEncoder, encode_auth_challenge}`, `crate::protocol::framing::{try_read_packet, TryReadResult}`, `crate::protocol::limits::*`, `crate::crypto::{argon2_verify, sha256_hex}`, `crate::storage::MessageStore`, `crate::cert::CertManager`.
- Produces:
  - `pub struct RelayServer { ... }` with field `sessions: Arc<DashMap<u64, SessionMeta>>` and `stats: Arc<ServerStats>`.
  - `pub struct SessionMeta { pub ip: std::net::IpAddr, pub authenticated: bool, pub connected_at: Instant }`.
  - `pub struct ServerStats { ... }` — see the full definition below; shared `Arc` between relay and TUI.
  - `impl RelayServer { pub async fn new(config, cert_manager, tui) -> Result<Self>; pub async fn run(self: Arc<Self>, shutdown) -> Result<()>; }`.
  - `pub(crate) async fn process_packet(...)` moves to `relay/auth.rs`.

- [ ] **Step 1: Write the failing test (SessionMeta + stats wiring)**

Add to `src/relay/session.rs` (create the file with the struct first):

```rust
#[cfg(test)]
mod tests {
    use super::SessionMeta;
    use std::net::IpAddr;
    use std::time::Instant;

    #[test]
    fn session_meta_carries_auth_flag() {
        let mut m = SessionMeta {
            ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            authenticated: false,
            connected_at: Instant::now(),
        };
        assert!(!m.authenticated);
        m.authenticated = true;
        assert!(m.authenticated);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --locked relay::session::`
Expected: FAIL — module not found.

- [ ] **Step 3: Create `src/relay/session.rs`**

```rust
//! Per-session state and the session read/write task lifecycle.
//!
//! A `SessionMeta` is the registry value shown in the TUI sessions table.
//! The `Session` struct is created per accepted connection; it owns the
//! auth flag that the reader task flips on success.

use std::net::IpAddr;
use std::time::Instant;

/// Lightweight snapshot of a live session, stored in the relay's session
/// registry and displayed by the TUI.
#[derive(Clone, Debug)]
pub struct SessionMeta {
    pub ip: IpAddr,
    pub authenticated: bool,
    pub connected_at: Instant,
}

/// Mutable per-session state owned by the reader task.
#[derive(Debug)]
pub struct Session {
    pub key: u64,
    pub ip: IpAddr,
    pub authenticated: bool,
}

impl Session {
    pub fn new(key: u64, ip: IpAddr) -> Self {
        Self { key, ip, authenticated: false }
    }
}
```

- [ ] **Step 4: Create `src/relay/stats.rs`**

```rust
//! Live counters shared between the relay and the TUI.
//!
//! All fields are atomics so the relay can increment from many tasks
//! concurrently and the TUI can read a cheap snapshot every second.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

#[derive(Debug, Default)]
pub struct ServerStats {
    /// Active session count (mirrors the session registry length).
    pub sessions: AtomicUsize,
    /// Highest concurrent session count observed.
    pub peak_sessions: AtomicUsize,
    /// Messages accepted into the store.
    pub messages: AtomicUsize,
    /// Relay messages forwarded to at least one receiver.
    pub relayed_msgs: AtomicUsize,
    /// Payload bytes relayed.
    pub relayed_bytes: AtomicUsize,
    /// Successful authentications.
    pub auth_ok: AtomicUsize,
    /// Failed authentication attempts.
    pub auth_fail: AtomicUsize,
    /// Connections rejected by the per-IP rate limiter.
    pub rate_limited: AtomicUsize,
    /// Aggregate buffered bytes across all reader tasks (DoS budget).
    pub buffered_bytes: AtomicUsize,
    /// Process start instant, for the TUI uptime display.
    pub uptime_start: Instant,
}

impl ServerStats {
    pub fn new() -> Self {
        Self {
            uptime_start: Instant::now(),
            ..Default::default()
        }
    }

    pub fn bump_sessions(&self) {
        let n = self.sessions.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak_sessions.fetch_max(n, Ordering::Relaxed);
    }

    pub fn drop_session(&self) {
        self.sessions.fetch_sub(1, Ordering::Relaxed);
    }
}
```

- [ ] **Step 5: Create `src/relay/housekeeping.rs`**

Move `spawn_housekeeping` (server.rs:1100-1180) verbatim, adapting: `this.total_buffered_bytes` → `this.stats.buffered_bytes` (the budget is now tracked via the stats counter; keep `MAX_TOTAL_BUFFERED_BYTES` here or in `limits.rs` — move it to `protocol/limits.rs` as `pub const MAX_TOTAL_BUFFERED_BYTES: usize = 512 * 1024 * 1024;` and import it). Replace `self.tui.set_stats(self.sessions.len(), self.store.len())` with:

```rust
                let (sessions, messages) = (self.sessions.len(), self.store.len());
                self.stats.sessions.store(sessions, Ordering::Relaxed);
                self.stats.messages.store(messages, Ordering::Relaxed);
                self.tui.set_stats(sessions, messages);
```

Also update the nonce-prune block: `this.auth_nonces` and `this.auth_attempts` become plain fields of the relay (see Task 6's registry note) — keep them as `DashMap` fields for now.

- [ ] **Step 6: Create `src/relay/auth.rs`**

Move the auth handshake (server.rs:817-968 `Opcode::Auth` arm), `Sync`/`Data`/`Heartbeat`/`KeyExchangeKemDsa` arms (server.rs:969-1096), and the `IGNORE` arm is deleted (spec Bug 7). Extract the Argon2 key-derivation block (server.rs:843-866) into a helper here:

```rust
//! Authentication handshake for WebTransport sessions.
//!
//! Protocol (byte-compatible with v2.5.x):
//!   Client sends: [0x01] [len:raw_password_bytes] [32 raw bytes: HMAC-SHA-256]
//!   HMAC key   = Argon2id(password) output (32 bytes)
//!   HMAC msg   = server nonce (16 bytes)

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use argon2::password_hash::PasswordHash;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::protocol::{Opcode, PacketReader, ServerPacketEncoder};
use crate::relay::RelayServer;
use crate::relay::session::Session;

type HmacSha256 = Hmac<Sha256>;

/// Derive the 32-byte HMAC key for challenge-response, re-running Argon2 with
/// the exact parameters and salt stored in the config hash.
fn derive_argon2_key(password: &str, stored_hash: &str) -> anyhow::Result<Vec<u8>> {
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|e| anyhow::anyhow!("failed to parse stored hash: {}", e))?;
    if let Some(salt) = parsed.salt {
        let mut raw_salt_buf = [0u8; 64];
        let raw_salt = salt
            .decode_b64(&mut raw_salt_buf)
            .map_err(|e| anyhow::anyhow!("failed to decode Argon2 salt: {}", e))?;
        let params = argon2::Params::try_from(&parsed)
            .map_err(|e| anyhow::anyhow!("failed to parse Argon2 params: {}", e))?;
        let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut output = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), raw_salt, &mut output)
            .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;
        Ok(output.to_vec())
    } else {
        anyhow::bail!("stored Argon2 hash is missing a salt");
    }
}

/// Verify the client's challenge-response against a stored Argon2 hash.
/// Returns `(hash_ok, nonce_valid)`.
pub(crate) async fn verify_auth(
    relay: &Arc<RelayServer>,
    session: &Session,
    password: &str,
    client_response: &[u8],
) -> bool {
    let hash_ok = crate::crypto::argon2_verify(password, &relay.password_hash);
    if !hash_ok {
        relay.stats.auth_fail.fetch_add(1, Ordering::Relaxed);
        warn!("[AUTH] Session {} password verification failed", session.key);
        return false;
    }
    let nonce_valid = match relay.auth_nonces.get(&session.key) {
        Some(entry) => {
            let (nonce, created_at) = entry.value();
            let age = Instant::now().duration_since(*created_at);
            if age > relay.nonce_max_age {
                warn!("[AUTH] Session {} challenge nonce expired", session.key);
                false
            } else if client_response.len() != 32 {
                warn!("[AUTH] Session {} missing/incorrect challenge response", session.key);
                false
            } else {
                match derive_argon2_key(password, &relay.password_hash) {
                    Ok(key) => {
                        let mut mac = match HmacSha256::new_from_slice(&key) {
                            Ok(m) => m,
                            Err(_) => return false,
                        };
                        mac.update(nonce);
                        let ok = mac.verify_slice(client_response).is_ok();
                        if !ok {
                            warn!("[AUTH] Session {} HMAC challenge response mismatch", session.key);
                        }
                        ok
                    }
                    Err(e) => {
                        warn!("[AUTH] Session {} key derivation failed: {}", session.key, e);
                        false
                    }
                }
            }
        }
        None => {
            warn!("[AUTH] Session {} no challenge nonce found", session.key);
            false
        }
    };
    if nonce_valid {
        relay.stats.auth_ok.fetch_add(1, Ordering::Relaxed);
    } else {
        relay.stats.auth_fail.fetch_add(1, Ordering::Relaxed);
    }
    nonce_valid
}
```

- [ ] **Step 7: Create `src/relay/mod.rs`**

Move the `RelayServer` struct (server.rs:109-148), `new` (server.rs:151-226), `run` (server.rs:228-274), `accept_loop` (server.rs:276-370), and `check_rate_limit`/`prune_rate_limiter` (server.rs:372-405) to `relay/mod.rs`. Move `handle_wt_session` (server.rs:411-483) and `run_session` (server.rs:489-804) to `relay/session.rs` per the spec target tree (§1: session.rs = "Session struct; handle_wt_session, run_session, reader/writer tasks"). Adapt as follows:

**Struct changes** (server.rs:109-148): replace `sessions: Arc<DashMap<u64, mpsc::Sender<Vec<u8>>>>` with `sessions: Arc<DashMap<u64, SessionMeta>>`; add `stats: Arc<ServerStats>`; add `nonce_max_age: Duration` field (from const `NONCE_MAX_AGE`); keep all other fields. Move the module doc from server.rs:1-8.

**`new`**: keep everything, then wire stats. The TUI and the relay MUST share the **same** `Arc<ServerStats>` (spec §3 "Atomics shared with the relay") — a separate Arc would make the TUI show only zeros for every counter the relay increments. First, in this task, extend the existing `tui.rs` `TuiHandle` minimally:
- add a field `stats: Arc<crate::relay::stats::ServerStats>`,
- add `pub fn stats_handle(&self) -> Arc<crate::relay::stats::ServerStats> { self.stats.clone() }`,
- change `set_stats(sessions, messages)` to write into that Arc (`self.stats.sessions.store(...); self.stats.messages.store(...)`) instead of storing two private numbers,
- initialize the field in `spawn_tui` (tui.rs:740) with `Arc::new(crate::relay::stats::ServerStats::new())`.

Then `RelayServer::new` takes the shared handle — do NOT create a fresh `ServerStats`:

```rust
        let stats = tui.stats_handle();
        tui.set_stats(0, 0);

        let server = Self {
            config: config.clone(),
            cert_manager,
            store,
            data_tx,
            control_tx,
            keyexchange_tx,
            sessions: Arc::new(DashMap::new()),
            cert_resolver,
            endpoint: Arc::new(tokio::sync::Mutex::new(Some(endpoint))),
            endpoint6: Arc::new(tokio::sync::Mutex::new(endpoint6)),
            session_semaphore,
            ip_connections: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            auth_nonces: Arc::new(DashMap::new()),
            auth_attempts: Arc::new(DashMap::new()),
            tui: tui.clone(),
            password_hash: config.password_hash.clone(),
            next_session_id: Arc::new(AtomicU64::new(0)),
            stats,
            key_exchange_store: Arc::new(DashMap::new()),
            nonce_max_age: NONCE_MAX_AGE,
        };
```

**`accept_loop`**: on rate-limit rejection (server.rs:329), add `self.stats.rate_limited.fetch_add(1, Ordering::Relaxed);`. On session insert (in `run_session`), call `self.stats.bump_sessions();`; on removal call `self.stats.drop_session();`.

**`handle_wt_session`**: unchanged except it now stores nonce/attempts and delegates to `run_session`. Keep as-is.

**`run_session`**: apply the orphaned-task fix (spec Bug 1). The current code at server.rs:782-788 uses `tokio::select!` and drops the losing `JoinHandle`, which **detaches** the task. Replace with abort handles. `JoinHandle`s are futures themselves, so select on `&handle` and `abort()` the loser, then await both so the registry entry + semaphore permit are released only after both tasks have fully stopped:

```rust
        let writer_task = tokio::spawn(async move { /* writer body */ });
        let reader_task = tokio::spawn(async move { /* reader body */ });

        // Wait for the first task to finish, then abort the other so no task
        // is orphaned; the session-registry entry + semaphore permit are
        // released only after both have stopped (Bug 1).
        tokio::select! {
            _ = &writer_task => reader_task.abort(),
            _ = &reader_task => writer_task.abort(),
        }
        let _ = writer_task.await;
        let _ = reader_task.await;
```

**Session registry** (server.rs:509): change `self.sessions.insert(session_key, direct_tx.clone())` to:

```rust
        let meta = SessionMeta {
            ip: remote_ip,
            authenticated: false,
            connected_at: Instant::now(),
        };
        self.sessions.insert(session_key, meta);
        self.stats.bump_sessions();
```

And the removal block (server.rs:794-798) becomes:

```rust
        self.sessions.remove(&session_key);
        self.stats.drop_session();
        self.auth_nonces.remove(&session_key);
        self.auth_attempts.remove(&session_key);
        self.key_exchange_store.remove(&session_key);
        self.tui.set_stats(self.sessions.len(), self.store.len());
```

**`process_packet`** is moved to `relay/auth.rs` as a `pub(crate) async fn process_packet(relay: &Arc<RelayServer>, session: &Session, packet_data: &[u8]) -> anyhow::Result<()>`. It parses the opcode and dispatches to the arms from server.rs:816-1096, with these changes:
- Auth arm: call `verify_auth(relay, session, &password, &client_response)`; on success set `session.authenticated = true`, send `AuthResult`, replay key exchanges; on failure enforce `MAX_AUTH_ATTEMPTS` (moved from server.rs:828-834) and the 500 ms delay (server.rs:934).
- `Sync`/`Data`/`Heartbeat`/`KeyExchangeKemDsa`: guard on `session.authenticated`, send direct responses via `relay`'s direct channel — **note**: the direct `mpsc::Sender<Vec<u8>>` was removed from the registry; `process_packet` must receive the `direct_tx` as a parameter. Signature:

```rust
pub(crate) async fn process_packet(
    relay: &Arc<RelayServer>,
    session: &mut Session,
    direct_tx: &mpsc::Sender<Vec<u8>>,
    packet_data: &[u8],
) -> anyhow::Result<()>
```

- `Data` arm: after a successful broadcast (server.rs:1032-1039), add stats:

```rust
                match subs {
                    Ok(n) => {
                        debug!("[DATA] Session {} broadcast OK to {} receivers", session.key, n);
                        relay.stats.relayed_msgs.fetch_add(1, Ordering::Relaxed);
                        relay.stats.relayed_bytes.fetch_add(payload.len() as u64, Ordering::Relaxed);
                    }
                    Err(_) => debug!("[DATA] Session {} broadcast: no receivers", session.key),
                }
```

- `MAX_PAYLOAD_BYTES` references become `crate::protocol::limits::MAX_PAYLOAD_BYTES`.
- The `IGNORE` arm (server.rs:1090-1096) is deleted (Bug 7).

**Rate limiting** (server.rs:374-405): unchanged except adding the `rate_limited` counter increment on rejection (server.rs:379-386).

**Module header of `relay/mod.rs`:**

```rust
//! WebTransport (QUIC/HTTP3) relay server.
//!
//! Responsibilities:
//!   * Accept WebTransport sessions using the managed self-signed certificate.
//!   * For each session, run a bidirectional loop of length-prefixed binary
//!     [`Opcode`] packets.
//!   * The server never decrypts payloads; it only forwards opaque bytes.
//!   * Periodically sweep expired messages and rotate the certificate.
//!   * Publish live [`ServerStats`] for the TUI.

pub mod auth;
pub mod housekeeping;
pub mod session;
pub mod stats;

pub use session::SessionMeta;
pub use stats::ServerStats;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Semaphore, broadcast, mpsc};
use tracing::{debug, info, trace, warn};
use wtransport::endpoint::endpoint_side;
use wtransport::{Endpoint, ServerConfig};

use crate::cert::CertManager;
use crate::cert::DynamicCertResolver;
use crate::protocol::limits::{MAX_PAYLOAD_BYTES, MAX_STREAM_BUFFER, MAX_TOTAL_BUFFERED_BYTES};
use crate::protocol::{Opcode, PacketReader, RelayedMessage, ServerPacketEncoder, encode_auth_challenge};
use crate::protocol::framing::{TryReadResult, try_read_packet};
use crate::storage::MessageStore;
use crate::tui::TuiHandle;

// consts moved here from server.rs: HOUSEKEEP_INTERVAL, SESSION_IDLE_TIMEOUT,
// MAX_CONCURRENT_SESSIONS, MAX_SYNC_MESSAGES, MAX_CONNECTIONS_PER_IP,
// RATE_LIMIT_WINDOW, HANDSHAKE_TIMEOUT, NONCE_LEN, NONCE_MAX_AGE,
// MAX_AUTH_ATTEMPTS, IP_PRUNE_INTERVAL.
```

Delete `src/server.rs` and update `src/lib.rs`:

```rust
pub mod relay;
```

(replacing `pub mod server;`). Re-export for tests (tests.rs:1449 imports `crate::server::{TryReadResult, try_read_packet}`):

```rust
pub use crate::protocol::framing::{TryReadResult, try_read_packet};
```

Put that in `relay/mod.rs` (line note: tests import `crate::server::...`, so also update `tests.rs:1449` to `crate::relay::...` in Step 9).

- [ ] **Step 8: Run the full test suite**

Run: `cargo test --locked`
Expected: PASS. Fix any path/import fallout (e.g. `crate::server::` → `crate::relay::`, `crate::server::MAX_PAYLOAD_BYTES` → `crate::protocol::limits::MAX_PAYLOAD_BYTES`).

- [ ] **Step 9: Commit**

```bash
git add src/relay src/server.rs src/lib.rs src/tui.rs src/tests.rs src/protocol/limits.rs
git commit -m "refactor(relay): split server.rs into relay/{mod,session,auth,housekeeping,stats}, fix orphaned-task race"
```

---

### Task 4: Move `setup.rs` → `cli/`, split `config.rs` → `config/`

**Files:**
- Create: `src/cli/mod.rs`
- Create: `src/cli/write.rs`
- Create: `src/config/mod.rs`, `src/config/cli.rs`, `src/config/file.rs`
- Delete: `src/setup.rs`, `src/config.rs`
- Modify: `src/lib.rs`, `src/main.rs`, `src/tests.rs`, `src/relay/mod.rs`
- Test: `src/cli/mod.rs`, `src/config/mod.rs` (moved inline tests)

**Interfaces:**
- Consumes: existing `config.rs` and `setup.rs` contents.
- Produces:
  - `config::mod`: `AppConfig`, `ServerSettings`, `config_file_loaded`, `load_config`, `resolve_config_path` (moved), `current_host`/`current_port`/`bracket_host`, `validate`.
  - `config::cli`: `CliArgs`, `SetupCommand`, `resolve_command`.
  - `config::file`: `load_file_config`, `resolve_config_path`.
  - `cli::mod`: `LICENSE_TEXT`, `run_first_run_wizard`, `run_init_wizard`, `prompt_password`.
  - `cli::write`: `write_config_file`.
- [ ] **Step 1: Create `src/config/` files**

Split `config.rs` into three files with `git mv` semantics (copy content, then delete the original):

`src/config/mod.rs`: module doc (config.rs:1-11), `AppConfig`, `ServerSettings`, defaults, `validate`, `load_config`, `bracket_host`, `current_host`, `current_port`, `config_file_loaded`. Re-exports:

```rust
pub mod cli;
pub mod file;

pub use cli::{CliArgs, SetupCommand, resolve_command};
pub use file::{config_file_loaded, load_file_config, resolve_config_path};
```

`src/config/cli.rs`:

```rust
//! Command-line interface definitions (clap) and one-shot command resolution.

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "impulse-server")]
#[command(about = "Secure ephemeral messenger server over WebTransport (QUIC)")]
pub struct CliArgs {
    /* all fields from config.rs:19-81, verbatim */
}

#[derive(Debug, PartialEq, Eq)]
pub enum SetupCommand {
    Run,
    HashPassword(String),
    PrintLicense,
    Init,
}

pub fn resolve_command(cli: &CliArgs) -> anyhow::Result<SetupCommand> {
    /* config.rs:97-116 verbatim */
}
```

`src/config/file.rs`:

```rust
//! Config-file discovery, loading, and parsing.

use crate::config::AppConfig;

pub fn resolve_config_path(path: Option<&str>) -> anyhow::Result<Option<std::path::PathBuf>> {
    /* config.rs:336-357 verbatim */
}

pub fn config_file_loaded(cli_args: &CliArgs) -> bool {
    /* config.rs:362-367 verbatim; import CliArgs from super::cli */
}

pub fn load_file_config(path: Option<&str>) -> anyhow::Result<Option<AppConfig>> {
    /* config.rs:376-396 verbatim */
}
```

- [ ] **Step 2: Create `src/cli/` files**

`src/cli/mod.rs`:

```rust
//! Interactive CLI bootstrap: first-run wizard, `--init` wizard, and
//! password prompting. Split from `setup.rs`.

mod write;

use std::io::{self, Write};
use std::path::Path;

pub use write::write_config_file;

/// MIT license text embedded from the repo-root LICENSE file.
pub const LICENSE_TEXT: &str = include_str!("../../LICENSE");

pub fn prompt_password(prompt: &str) -> anyhow::Result<String> { /* setup.rs:57-73 verbatim */ }

fn prompt_line(prompt: &str, default: &str) -> anyhow::Result<String> { /* setup.rs:76-87 verbatim */ }

pub fn run_first_run_wizard() -> anyhow::Result<()> { /* setup.rs:91-103 verbatim, argon2 via crate::crypto */ }

pub fn run_init_wizard(force: bool) -> anyhow::Result<()> { /* setup.rs:106-133 verbatim, argon2 via crate::crypto */ }

#[cfg(test)]
mod tests {
    /* move setup.rs:135-146 (last_attempt_gets_no_try_again_message) here */
}
```

`src/cli/write.rs`:

```rust
//! Config-file writer (refuses overwrite, 0600 on Unix).

use std::path::Path;

use crate::config::AppConfig;

pub fn write_config_file(path: &Path, cfg: &AppConfig, overwrite: bool) -> anyhow::Result<()> {
    /* setup.rs:17-40 verbatim */
}

#[cfg(test)]
mod tests {
    /* move setup_tests (tests.rs:2069-2122) here: write_config_roundtrips_and_omits_empty_optional_fields,
       write_config_refuses_overwrite_without_flag, write_config_sets_0600_on_unix */
}
```

- [ ] **Step 3: Update `src/lib.rs` and `src/main.rs`**

`lib.rs`: replace `pub mod config;` with `pub mod config;` (unchanged name, still a directory) and `pub mod setup;` with `pub mod cli;`.

`main.rs`:

```rust
use impulse_server::cli::{LICENSE_TEXT, run_first_run_wizard, run_init_wizard};
use impulse_server::config::cli::{CliArgs, resolve_command, SetupCommand};
use impulse_server::config::{config_file_loaded, load_config};
use impulse_server::crypto::argon2_hash;
```

- [ ] **Step 4: Update `src/relay/mod.rs` config path**

`RelayServer.config: crate::config::ServerSettings` stays valid (module path unchanged). If any code referenced `crate::config::argon2_*`, it now lives in `crate::crypto` (already handled in Task 2).

- [ ] **Step 5: Update `src/tests.rs` imports**

- `mod config_tests` (tests.rs:1902): `use crate::config::{CliArgs, SetupCommand, load_config, resolve_command};` → `use crate::config::cli::{CliArgs, SetupCommand, resolve_command}; use crate::config::load_config;`
- `config_file_loaded` import (tests.rs:2039): `use crate::config::config_file_loaded;` stays.
- `mod setup_tests` (tests.rs:2069-2122): `use crate::setup::write_config_file;` → `use crate::cli::write_config_file;`. This whole module moves to `src/cli/write.rs` per Task 6; for now just fix the import and keep the tests in place.

- [ ] **Step 6: Convert flat modules to dirs; fix Bug 6 (logging defaults + single `logs/`)**

Match the spec target-tree form for the remaining single-file modules (`git mv` preserves history):

```bash
git mv src/logging.rs src/logging/mod.rs
git mv src/storage.rs src/storage/mod.rs
git mv src/cert.rs src/cert/mod.rs
```

Then fix Bug 6 in `src/logging/mod.rs`:
- Delete the duplicate `let _ = std::fs::create_dir_all("logs");` (logging.rs:89) — `lib.rs` `run()` already creates `logs/` once (lib.rs:45). Single creation site stays in `lib.rs`.
- Consolidate the two different RUST_LOG fallbacks (`"debug"` at lib.rs:60 vs `"info"` at logging.rs:84) into one const:

```rust
/// Default filter when `RUST_LOG` is unset. Single source for both the TUI
/// layer and the rolling file layer (Bug 6).
pub const DEFAULT_LOG_FILTER: &str = "debug";
```

`init_tracing` uses `std::env::var("RUST_LOG").unwrap_or_else(|_| DEFAULT_LOG_FILTER.to_string())` for the env-filter AND `EnvFilter::new(DEFAULT_LOG_FILTER)` as the parse fallback (logging.rs:84). `lib.rs:60` drops its own `"debug"` literal and imports `DEFAULT_LOG_FILTER` instead. The module doc references `crate::tui` (logging.rs:13, 55) — these still compile here; they are rewired to `crate::ui` in Task 5.

- [ ] **Step 7: Run the full test suite**

Run: `cargo test --locked`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/config src/cli src/logging src/storage src/cert src/lib.rs src/main.rs src/relay/mod.rs src/tests.rs
git rm src/config.rs src/setup.rs src/logging.rs src/storage.rs src/cert.rs
git commit -m "refactor(config,cli): split config.rs into config/{mod,cli,file}, move setup.rs to cli/, convert flat modules to dirs"
```

---

### Task 5: Move `tui.rs` → `ui/` and redesign (layout, controls, stats, performance)

**Files:**
- Create: `src/ui/mod.rs`, `src/ui/draw.rs`, `src/ui/view.rs`
- Delete: `src/tui.rs`
- Modify: `src/lib.rs`, `src/relay/mod.rs`, `src/main.rs`
- Test: `src/ui/view.rs` (`compute_scroll`, `fmt_duration` unit tests)

**Interfaces:**
- Consumes: `crate::relay::{SessionMeta, ServerStats}`, `crate::cert::Cert`, `ratatui`, `crossterm`, `tui-qrcode`, `qrcode`, `copypasta`, `crossbeam_channel`, `tracing::Level`.
- Produces:
  - `pub struct TuiHandle { ... }` with **private** fields and methods `push_log`, `set_cert`, `set_info`, `set_stats`, `set_sessions`.
  - `pub fn spawn_tui(initial: CertView, shutdown) -> Result<TuiHandle>`, `pub(crate) fn run_tui(...)`.
  - `pub struct ServerInfo`, `pub struct CertView`, `pub struct LogRecord`, `pub struct ServerStats` (re-exported from `crate::relay::stats` — see Task 3; here `view.rs` re-exports or defines the display-oriented ones).
  - `pub struct TuiLogLayer` stays in `logging.rs`.
  - Pure helpers: `pub fn compute_scroll(total: usize, usable: u16, scroll_offset: u16, auto: bool) -> (u16, bool)`; `pub fn fmt_duration(secs: u64) -> String`.

- [ ] **Step 1: Write the failing test**

Create `src/ui/view.rs` with a `#[cfg(test)] mod tests`:

```rust
#[cfg(test)]
mod tests {
    use super::{compute_scroll, fmt_duration};

    #[test]
    fn compute_scroll_pins_when_auto() {
        // Auto-scroll: 100 lines, 10 usable rows → pinned at bottom (offset 90).
        let (y, auto) = compute_scroll(100, 10, 0, true);
        assert_eq!(y, 90);
        assert!(auto);
    }

    #[test]
    fn compute_scroll_manual_disengages_auto() {
        let (y, auto) = compute_scroll(100, 10, 5, false);
        assert_eq!(y, 5);
        assert!(!auto);
    }

    #[test]
    fn compute_scroll_clamps_at_top() {
        let (y, _) = compute_scroll(50, 10, u16::MAX, false);
        assert_eq!(y, 40); // 50 - 10 usable
    }

    #[test]
    fn compute_scroll_no_scroll_when_fits() {
        let (y, _) = compute_scroll(5, 10, 0, false);
        assert_eq!(y, 0);
    }

    #[test]
    fn fmt_duration_renders_components() {
        assert_eq!(fmt_duration(90), "1m 30s");
        assert_eq!(fmt_duration(2 * 86400 + 3600 + 120), "2d 1h 2m 0s");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --locked ui::view::`
Expected: FAIL — `crate::ui` does not exist.

- [ ] **Step 3: Create `src/ui/view.rs`**

```rust
//! Data types shared between the TUI and the relay (view models).
//!
//! `ServerInfo`, `CertView`, and `LogRecord` are display-oriented snapshots;
//! `ServerStats` is the shared live counter block produced by the relay.

use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cert::Cert;
pub use crate::relay::stats::ServerStats;

/// Static technical information about the running server (safe to display).
#[derive(Clone, Default)]
pub struct ServerInfo {
    pub address: String,
    pub san_count: usize,
    pub ttl_hours: u64,
    pub max_payload: usize,
    pub max_sessions: usize,
    pub version: String,
}

/// Snapshot of certificate state shown in the certificate panel.
#[derive(Clone, Default)]
pub struct CertView {
    pub fingerprint_grouped: String,
    pub fingerprint_raw: String,
    pub issued_at: u64,
    pub expires_in: u64,
    /// True while a previous cert is still valid (overlap window).
    pub rotating: bool,
}

impl CertView {
    pub fn from_cert(cert: &Cert) -> Self {
        Self {
            fingerprint_grouped: cert.fingerprint_grouped(),
            fingerprint_raw: cert.fingerprint.clone(),
            issued_at: cert
                .not_before
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            expires_in: cert.expires_in(),
            rotating: false,
        }
    }

    /// The QR payload: `impulse-cert:<fp>` — the SHA-256 fingerprint the client
    /// pins via WebTransport `serverCertificateHashes` (TOFU).
    pub fn tofu_qr_string(&self) -> String {
        format!("impulse-cert:{}", self.fingerprint_raw)
    }
}

/// Log record forwarded from the `tracing` subscriber.
#[derive(Clone)]
pub struct LogRecord {
    pub level: tracing::Level,
    pub target: String,
    pub message: String,
    pub timestamp: SystemTime,
}

/// Scroll helper: computes the rendered scroll offset (0 = bottom is the newest
/// line; line 0 is the oldest) and whether live auto-scroll stays engaged.
///
/// `total` = number of lines, `usable` = number of viewport rows available for
/// lines (the caller must already exclude borders), `scroll_offset` = rows
/// scrolled up from the bottom (0 = bottom), `auto` = live auto-scroll engaged.
pub fn compute_scroll(total: usize, usable: u16, scroll_offset: u16, auto: bool) -> (u16, bool) {
    let usable = usable as usize;
    if total <= usable {
        return (0, auto || scroll_offset == 0);
    }
    let max_scroll = (total - usable) as u16;
    if auto {
        return (max_scroll, true);
    }
    let y = scroll_offset.min(max_scroll);
    // Re-engage live when the user scrolls back to the very bottom.
    let re_pinned = y >= max_scroll;
    (y, re_pinned)
}

/// Format seconds as `d h m s` (only components that are nonzero; always seconds).
pub fn fmt_duration(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    match (d, h, m) {
        (0, 0, 0) => format!("{s}s"),
        (0, 0, _) => format!("{m}m {s}s"),
        (0, _, _) => format!("{h}h {m}m {s}s"),
        _ => format!("{d}d {h}h {m}m {s}s"),
    }
}

/// Snapshot of a live session for the sessions table.
#[derive(Clone, Debug)]
pub struct SessionRow {
    pub key: u64,
    pub ip: std::net::IpAddr,
    pub authenticated: bool,
    pub age: Duration,
}
```

Note: `ServerStats` is re-exported from `relay::stats` (Task 3). `view.rs` imports it for type identity; the TUI reads fields via `.load(Ordering::Relaxed)`.

- [ ] **Step 4: Create `src/ui/draw.rs`**

Move all `draw_*` functions, `centered_rect`, `format_timestamp`, `format_unix`, `level_style`, `copy_logs_to_clipboard` from `tui.rs` into `src/ui/draw.rs`, then rewrite to the new layout. The full new `draw.rs`:

```rust
//! TUI rendering: layout, panels, log viewport, QR, status bar.
//!
//! Layout (full, ≥ ~90 cols × ~26 rows):
//!   Server | Sessions     (top-left / top-right)
//!   TOFU QR | Certificate
//!   Logs (full width)
//!   Status bar
//! Compact (<90 cols or <24 rows): logs + status bar only.

use std::io::Stdout;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use copypasta::{ClipboardContext, ClipboardProvider};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use tracing::Level;

use crate::ui::view::{CertView, LogRecord, ServerInfo, SessionRow, ServerStats};
use crate::ui::view::{compute_scroll, fmt_duration};
use crate::ui::{PanelMode, TuiState};

/// Single palette for the whole UI (spec §3 Appearance).
pub const THEME: UiTheme = UiTheme::dark();

pub struct UiTheme {
    pub border: Color,
    pub border_focus: Color,
    pub header: Color,
    pub label: Color,
    pub value: Color,
    pub ok: Color,
    pub warn: Color,
    pub err: Color,
    pub dim: Color,
    pub title: Color,
}

impl UiTheme {
    pub const fn dark() -> Self {
        Self {
            border: Color::Gray,
            border_focus: Color::Cyan,
            header: Color::Cyan,
            label: Color::Gray,
            value: Color::White,
            ok: Color::Green,
            warn: Color::Yellow,
            err: Color::Red,
            dim: Color::DarkGray,
            title: Color::White,
        }
    }
}

pub fn level_style(level: Level) -> (Color, &'static str) {
    match level {
        Level::ERROR => (Color::Red, "ERR"),
        Level::WARN => (Color::Yellow, "WRN"),
        Level::INFO => (Color::Cyan, "INF"),
        Level::DEBUG => (Color::Magenta, "DBG"),
        Level::TRACE => (Color::DarkGray, "TRC"),
    }
}

pub fn format_timestamp(ts: SystemTime) -> String {
    let dur = ts.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    format!(
        "[{:02}:{:02}:{:02}.{:03}]",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60,
        millis
    )
}

pub fn format_unix(secs: u64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs as i64) {
        Ok(dt) => dt
            .format(&time::format_description::well_known::Rfc2822)
            .unwrap_or_else(|_| secs.to_string()),
        Err(_) => secs.to_string(),
    }
}

pub fn copy_logs_to_clipboard(logs: &[LogRecord], clipboard: &mut Option<ClipboardContext>) {
    if let Some(ctx) = clipboard {
        let text: String = logs
            .iter()
            .map(|rec| {
                let ts_str = format_timestamp(rec.timestamp);
                let (_, lvl) = level_style(rec.level);
                format!("{} [{}] {}: {}", ts_str, lvl, rec.target, rec.message)
            })
            .collect::<Vec<_>>()
            .join("\n");
        let _ = ctx.set_contents(text);
    }
}

fn centered_rect(width: u16, height: u16, r: Rect) -> Rect {
    let width = width.min(r.width);
    let height = height.min(r.height);
    Rect {
        x: r.x + (r.width - width) / 2,
        y: r.y + (r.height - height) / 2,
        width,
        height,
    }
}

pub(crate) fn draw(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    logs: &[LogRecord],
    cert: &CertView,
    info: &ServerInfo,
    stats: &ServerStats,
    sessions: &[SessionRow],
    state: &TuiState,
    has_clipboard: bool,
    throughput: u64,
) -> anyhow::Result<()> {
    terminal.draw(|f| {
        let area = f.area();
        let full = area.width >= 90 && area.height >= 24;
        let filtered: Vec<&LogRecord> = logs.iter().filter(|r| state.level_visible(&r.level)).collect();
        let filtered_total = filtered.len();

        // `f` — QR full-screen (spec §3): QR over everything except the status bar.
        if state.qr_focus {
            let v = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(1)])
                .split(area);
            draw_qr(f, v[0], cert);
            draw_status_bar(f, v[1], state, stats, info, has_clipboard, full, filtered_total, throughput);
            return;
        }

        if !full {
            // Compact: logs + status bar.
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(1)])
                .split(area);
            draw_logs(f, rows[0], &filtered, state);
            draw_status_bar(f, rows[1], state, stats, info, has_clipboard, full, filtered_total, throughput);
            return;
        }

        // Full: top panels (Server/QR | Sessions/Cert), then Logs, then status bar.
        // Split the whole area vertically first so the bottom (logs/status) never
        // overlaps the panels.
        let v = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(15), Constraint::Min(3), Constraint::Length(1)])
            .split(area);

        if state.panel_mode == PanelMode::Hidden {
            // Left column hidden: Sessions/Cert span the full top width.
            let right_rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(5), Constraint::Min(5)])
                .split(v[0]);
            draw_sessions(f, right_rows[0], sessions);
            draw_cert_info(f, right_rows[1], cert);
        } else {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(60), Constraint::Min(30)])
                .split(v[0]);

            let left_rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(7), Constraint::Min(5)])
                .split(cols[0]);
            if state.panel_mode == PanelMode::Full {
                draw_info(f, left_rows[0], info, stats);
            }
            draw_qr(f, left_rows[1], cert);

            let right_rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(5), Constraint::Min(5)])
                .split(cols[1]);
            draw_sessions(f, right_rows[0], sessions);
            draw_cert_info(f, right_rows[1], cert);
        }

        draw_logs(f, v[1], &filtered, state);
        draw_status_bar(f, v[2], state, stats, info, has_clipboard, full, filtered_total, throughput);
    })?;
    Ok(())
}

fn draw_info(f: &mut ratatui::Frame, area: Rect, info: &ServerInfo, stats: &ServerStats) {
    let uptime = fmt_duration(stats.uptime_start.elapsed().as_secs());
    let lines = vec![
        Line::from(vec![
            Span::styled("Listen: ", Style::default().fg(THEME.label)),
            Span::styled(info.address.clone(), Style::default().fg(THEME.value).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Transport: ", Style::default().fg(THEME.label)),
            Span::styled("WebTransport/QUIC · TLS 1.3", Style::default().fg(THEME.header)),
        ]),
        Line::from(vec![
            Span::styled("Version: ", Style::default().fg(THEME.label)),
            Span::raw(info.version.clone()),
            Span::styled("  MIT © oqune", Style::default().fg(THEME.dim)),
        ]),
        Line::from(vec![
            Span::styled("Uptime: ", Style::default().fg(THEME.label)),
            Span::raw(uptime),
        ]),
        Line::from(vec![
            Span::styled("Sessions: ", Style::default().fg(THEME.label)),
            Span::styled(
                format!("{}/{}", stats.sessions.load(std::sync::atomic::Ordering::Relaxed), info.max_sessions),
                Style::default().fg(THEME.ok),
            ),
            Span::styled("  Msgs: ", Style::default().fg(THEME.label)),
            Span::raw(format!("{}", stats.messages.load(std::sync::atomic::Ordering::Relaxed))),
        ]),
        Line::from(vec![
            Span::styled("TTL: ", Style::default().fg(THEME.label)),
            Span::raw(format!("{}h", info.ttl_hours)),
            Span::styled("  Payload: ", Style::default().fg(THEME.label)),
            Span::raw(format!("{}KB", info.max_payload / 1024)),
        ]),
        Line::from(vec![
            Span::styled("Peak: ", Style::default().fg(THEME.label)),
            Span::raw(format!("{}", stats.peak_sessions.load(std::sync::atomic::Ordering::Relaxed))),
        ]),
    ];
    let block = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(" Server ")
                .border_style(Style::default().fg(THEME.border)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(block, area);
}

fn draw_sessions(f: &mut ratatui::Frame, area: Rect, sessions: &[SessionRow]) {
    let mut lines: Vec<Line> = Vec::new();
    for row in sessions.iter().take(100) {
        let auth = if row.authenticated {
            Span::styled("✓", Style::default().fg(THEME.ok))
        } else {
            Span::styled("·", Style::default().fg(THEME.dim))
        };
        let buf = "0 B"; // buffered bytes per session is not tracked per-session yet
        lines.push(Line::from(vec![
            Span::styled(format!("{:4}  ", row.key), Style::default().fg(THEME.dim)),
            Span::styled(format!("{:<16}", row.ip.to_string()), Style::default().fg(THEME.value)),
            Span::raw("  "),
            auth,
            Span::styled(format!("  {:>8}", fmt_duration(row.age.as_secs())), Style::default().fg(THEME.dim)),
            Span::styled(format!("  {buf}"), Style::default().fg(THEME.dim)),
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

fn draw_qr(f: &mut ratatui::Frame, area: Rect, cert: &CertView) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .title(" QR — TOFU ")
        .border_style(Style::default().fg(THEME.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let qr_string = cert.tofu_qr_string();
    match qrcode::QrCode::with_error_correction_level(&qr_string, qrcode::EcLevel::L) {
        Ok(qr) => {
            let cols = qr.width() as u16;
            let rows = qr.width().div_ceil(2) as u16;
            // Never render a truncated QR: if it cannot fit, show a hint instead.
            if cols <= inner.width && rows <= inner.height {
                let centered = centered_rect(cols, rows, inner);
                let widget = tui_qrcode::QrCodeWidget::new(qr).quiet_zone(tui_qrcode::QuietZone::Disabled);
                f.render_widget(widget, centered);
            } else {
                let p = Paragraph::new(Line::from(Span::styled(
                    "QR: enlarge terminal / press f",
                    Style::default().fg(THEME.dim),
                )))
                .alignment(Alignment::Center);
                f.render_widget(p, inner);
            }
        }
        Err(_) => {
            let p = Paragraph::new("QR encode error").style(Style::default().fg(THEME.err)).alignment(Alignment::Center);
            f.render_widget(p, inner);
        }
    }
}

fn draw_cert_info(f: &mut ratatui::Frame, area: Rect, cert: &CertView) {
    let mut lines = vec![
        Line::from(vec![Span::styled("Fingerprint:", Style::default().fg(THEME.label))]),
        Line::from(Span::styled(cert.fingerprint_grouped.clone(), Style::default().fg(THEME.ok).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(vec![
            Span::styled("Valid for: ", Style::default().fg(THEME.label)),
            Span::styled(fmt_duration(cert.expires_in), Style::default().fg(THEME.header).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Issued: ", Style::default().fg(THEME.label)),
            Span::raw(format_unix(cert.issued_at)),
        ]),
    ];
    if cert.rotating {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("⚠ Rotating (overlap)", Style::default().fg(THEME.warn))));
    }
    let info = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(" Certificate ")
                .border_style(Style::default().fg(THEME.border)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(info, area);
}

fn draw_logs(f: &mut ratatui::Frame, area: Rect, filtered: &[&LogRecord], state: &TuiState) {
    // Render only the visible window (spec §3 Performance). `filtered` was
    // already computed once in `draw`.
    let usable = area.height.saturating_sub(2) as usize;
    let (scroll_y, _auto) = compute_scroll(filtered.len(), area.height.saturating_sub(2), state.scroll_offset, state.auto_scroll);

    let search = state.search.as_ref().map(|s| s.query.as_str());
    let start = scroll_y as usize;
    let visible = filtered.iter().skip(start).take(usable.max(1)).map(|rec| {
        let (color, lvl) = level_style(rec.level);
        let mut spans = vec![
            Span::styled(format_timestamp(rec.timestamp), Style::default().fg(THEME.dim)),
            Span::styled(format!(" [{}] ", lvl), Style::default().fg(color)),
            Span::styled(format!("{}: ", rec.target), Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)),
        ];
        spans.extend(message_spans(rec, search, Style::default()));
        Line::from(spans)
    }).collect::<Vec<Line>>();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .title(" Logs ")
        .border_style(Style::default().fg(THEME.border));
    let paragraph = Paragraph::new(visible)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

/// Split a log message into spans, highlighting every case-insensitive match of
/// the active search query (spec §3 `/` search).
fn message_spans<'a>(rec: &'a LogRecord, query: Option<&str>, base: Style) -> Vec<Span<'static>> {
    let query = match query {
        Some(q) if !q.is_empty() => q.to_lowercase(),
        _ => return vec![Span::styled(rec.message.clone(), base)],
    };
    let msg = &rec.message;
    let lower = msg.to_lowercase();
    let mut spans = Vec::new();
    let mut rest: &str = msg;
    let mut rest_lower: &str = lower.as_str();
    while let Some(idx) = rest_lower.find(&query) {
        let (pre, tail) = rest.split_at(idx);
        let (matched, after) = tail.split_at(query.len());
        if !pre.is_empty() {
            spans.push(Span::styled(pre.to_string(), base));
        }
        spans.push(Span::styled(
            matched.to_string(),
            Style::default().bg(Color::Yellow).fg(Color::Black),
        ));
        rest = after;
        rest_lower = &rest_lower[idx + query.len()..];
        if rest.is_empty() {
            break;
        }
    }
    if !rest.is_empty() {
        spans.push(Span::styled(rest.to_string(), base));
    }
    spans
}

fn draw_status_bar(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &TuiState,
    stats: &ServerStats,
    info: &ServerInfo,
    has_clipboard: bool,
    full: bool,
    filtered_total: usize,
    throughput: u64,
) {
    let relaxed = std::sync::atomic::Ordering::Relaxed;
    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::styled("● LIVE  ", Style::default().fg(THEME.ok)));
    spans.push(Span::styled(
        format!("S {}/{}  ", stats.sessions.load(relaxed), info.max_sessions),
        Style::default().fg(THEME.value),
    ));
    spans.push(Span::styled(
        format!("Msgs {}  ", stats.messages.load(relaxed)),
        Style::default().fg(THEME.value),
    ));
    spans.push(Span::styled(
        format!("Buf {}  ", fmt_bytes(stats.buffered_bytes.load(relaxed) as u64)),
        Style::default().fg(THEME.value),
    ));
    spans.push(Span::styled(
        format!("↑ {}/s  ", fmt_bytes(throughput)),
        Style::default().fg(THEME.ok),
    ));
    spans.push(Span::styled(
        format!("Auth {}✓ {}✗  ", stats.auth_ok.load(relaxed), stats.auth_fail.load(relaxed)),
        Style::default().fg(THEME.value),
    ));
    if state.paused {
        spans.push(Span::styled("⏸ paused  ", Style::default().fg(THEME.warn)));
    }
    spans.push(Span::styled("│  ", Style::default().fg(THEME.dim)));
    let all_active = state.active_filters.is_empty();
    let filter_keys: &[(Level, &str)] = &[
        (Level::ERROR, "1"),
        (Level::WARN, "2"),
        (Level::INFO, "3"),
        (Level::DEBUG, "4"),
        (Level::TRACE, "5"),
    ];
    for (level, key) in filter_keys {
        let (color, short) = level_style(*level);
        let active = all_active || state.active_filters.contains(level);
        let style = if active {
            Style::default().fg(color).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(THEME.dim)
        };
        spans.push(Span::styled(format!("[{key}:{short}] "), style));
    }
    if !state.auto_scroll {
        spans.push(Span::styled(
            format!("{}/{}  ", state.scroll_offset, filtered_total),
            Style::default().fg(THEME.dim),
        ));
    }
    if has_clipboard {
        spans.push(Span::styled("Shift+C copy", Style::default().fg(THEME.dim)));
    }
    if state.search_active() {
        let q = state.search.as_ref().map(|s| s.query.as_str()).unwrap_or("");
        spans.push(Span::styled(format!(" /{q}▏ (Esc / Enter)"), Style::default().fg(THEME.warn)));
    }

    let bar = Paragraph::new(Line::from(spans));
    f.render_widget(bar, area);
}

fn fmt_bytes(n: u64) -> String {
    if n >= 1024 * 1024 {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}
```

- [ ] **Step 5: Create `src/ui/mod.rs`**

```rust
//! Terminal UI: event loop, scrolling/filter state, and the [`TuiHandle`]
//! used by the relay to feed logs/cert/stats.

pub mod draw;
pub mod view;

use std::collections::HashSet;
use std::io::Stdout;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use copypasta::ClipboardContext;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseEventKind};
use crossterm::terminal::{self};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tracing::Level;

use crate::relay::ServerStats;
use crate::ui::draw::{copy_logs_to_clipboard, draw};
use crate::ui::view::{CertView, LogRecord, ServerInfo, SessionRow};

/// Max number of log lines retained for the TUI (spec §3: 500 → 2000).
const MAX_LOG_LINES: usize = 2000;

/// Left-panel visibility, cycled with `Tab` (spec §3: full → QR-only → hidden).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PanelMode {
    #[default]
    Full,
    QrOnly,
    Hidden,
}

/// Active substring search opened with `/` (spec §3).
#[derive(Default)]
pub struct SearchState {
    pub query: String,
    /// Round-robin index over the match list, advanced by `Enter`.
    pub cursor: usize,
}

/// Scroll + filter + search + panel state for the log viewport.
#[derive(Default)]
pub struct TuiState {
    pub scroll_offset: u16,
    pub auto_scroll: bool,
    pub active_filters: HashSet<Level>,
    pub paused: bool,
    pub panel_mode: PanelMode,
    pub qr_focus: bool,
    pub search: Option<SearchState>,
}

impl TuiState {
    fn new() -> Self {
        Self { auto_scroll: true, ..Self::default() }
    }

    pub fn level_visible(&self, level: &Level) -> bool {
        self.active_filters.is_empty() || self.active_filters.contains(level)
    }

    pub fn toggle_filter(&mut self, level: Level) {
        if !self.active_filters.insert(level) {
            self.active_filters.remove(&level);
        }
    }

    pub fn scroll_up(&mut self, amount: u16) {
        self.auto_scroll = false;
        self.scroll_offset = self.scroll_offset.saturating_add(amount);
    }

    pub fn scroll_down(&mut self, amount: u16) {
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);
        if self.scroll_offset == 0 {
            self.auto_scroll = true;
        }
    }

    pub fn scroll_to_bottom(&mut self) {
        self.scroll_offset = 0;
        self.auto_scroll = true;
    }

    pub fn scroll_to_top(&mut self) {
        self.auto_scroll = false;
        self.scroll_offset = u16::MAX;
    }

    pub fn search_active(&self) -> bool {
        self.search.is_some()
    }
}

/// Handle returned to the caller to feed the TUI. Fields are private; the relay
/// interacts only through these methods.
#[derive(Clone)]
pub struct TuiHandle {
    log_tx: crossbeam_channel::Sender<LogRecord>,
    cert: Arc<Mutex<CertView>>,
    info: Arc<Mutex<ServerInfo>>,
    stats: Arc<ServerStats>,
    sessions: Arc<Mutex<Vec<SessionRow>>>,
    shutdown: Arc<tokio::sync::Notify>,
}

impl TuiHandle {
    pub fn push_log(&self, rec: LogRecord) {
        let _ = self.log_tx.try_send(rec);
    }

    pub fn set_cert(&self, view: CertView) {
        *self.cert.lock().unwrap_or_else(|e| e.into_inner()) = view;
    }

    pub fn set_info(&self, info: ServerInfo) {
        *self.info.lock().unwrap_or_else(|e| e.into_inner()) = info;
    }

    pub fn set_stats(&self, sessions: usize, messages: usize) {
        self.stats.sessions.store(sessions, Ordering::Relaxed);
        self.stats.messages.store(messages, Ordering::Relaxed);
    }

    pub fn set_sessions(&self, rows: Vec<SessionRow>) {
        *self.sessions.lock().unwrap_or_else(|e| e.into_inner()) = rows;
    }

    pub fn stats_handle(&self) -> Arc<ServerStats> {
        self.stats.clone()
    }

    pub fn shutdown(&self) -> &Arc<tokio::sync::Notify> {
        &self.shutdown
    }
}

/// Run the TUI loop on the current thread until the user quits (Ctrl+C / 'q').
pub(crate) fn run_tui(
    log_rx: crossbeam_channel::Receiver<LogRecord>,
    cert: Arc<Mutex<CertView>>,
    info: Arc<Mutex<ServerInfo>>,
    stats: Arc<ServerStats>,
    sessions: Arc<Mutex<Vec<SessionRow>>>,
    shutdown: Arc<tokio::sync::Notify>,
    init_tx: crossbeam_channel::Sender<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let mut stdout: Stdout = std::io::stdout();
    terminal::enable_raw_mode()?;
    crossterm::execute!(
        stdout,
        terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    // Signal "ready" immediately so spawn_tui returns without a startup delay
    // (the final result after quit is sent again below; capacity is 1 so the
    // caller's recv_timeout gets this first message).
    let _ = init_tx.send(Ok(()));

    let mut logs: Vec<LogRecord> = Vec::with_capacity(MAX_LOG_LINES);
    let mut state = TuiState::new();
    let mut last_copy: Option<SystemTime> = None;
    let clipboard_result = ClipboardContext::new();
    let has_clipboard = clipboard_result.is_ok();
    let mut clipboard = clipboard_result.ok();

    let mut last_tick = std::time::Instant::now();
    let mut last_relayed_bytes = 0usize;
    let mut throughput: u64 = 0;
    let mut dirty = true;

    loop {
        // Drain log channel (event-driven redraw: only on new data / input / tick).
        let mut drained = false;
        while let Ok(rec) = log_rx.try_recv() {
            if !state.paused {
                logs.push(rec);
                if logs.len() > MAX_LOG_LINES {
                    let drop = logs.len() - MAX_LOG_LINES;
                    logs.drain(0..drop);
                }
                drained = true;
            }
        }

        if event::poll(Duration::from_millis(16))? {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    let quit = handle_key(
                        &key,
                        &mut state,
                        &mut logs,
                        &mut clipboard,
                        &mut last_copy,
                        has_clipboard,
                        shutdown.clone(),
                    );
                    if quit {
                        break;
                    }
                    dirty = true;
                }
                Event::Mouse(m) => {
                    if m.kind == MouseEventKind::ScrollUp {
                        state.scroll_up(3);
                        dirty = true;
                    } else if m.kind == MouseEventKind::ScrollDown {
                        state.scroll_down(3);
                        dirty = true;
                    }
                }
                Event::Resize(_, _) => dirty = true,
                _ => {}
            }
        }

        // 1-second tick: refresh stats-driven fields (uptime, throughput).
        if last_tick.elapsed() >= Duration::from_secs(1) {
            last_tick = std::time::Instant::now();
            // Throughput = relayed_bytes delta since the previous tick.
            let now = stats.relayed_bytes.load(Ordering::Relaxed);
            throughput = now.saturating_sub(last_relayed_bytes) as u64;
            last_relayed_bytes = now;
            dirty = true;
        }

        if dirty || drained {
            dirty = false;
            let cert = cert.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let info = info.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let sessions = sessions.lock().unwrap_or_else(|e| e.into_inner()).clone();
            draw(
                &mut terminal,
                &logs,
                &cert,
                &info,
                &stats,
                &sessions,
                &state,
                has_clipboard,
                throughput,
            )?;
        }
    }

    // Cleanup: restore the terminal in all paths (Bug 5).
    terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    let _ = init_tx.send(Ok(()));
    Ok(())
}

fn handle_key(
    key: &crossterm::event::KeyEvent,
    state: &mut TuiState,
    logs: &mut Vec<LogRecord>,
    clipboard: &mut Option<ClipboardContext>,
    last_copy: &mut Option<SystemTime>,
    has_clipboard: bool,
    shutdown: Arc<tokio::sync::Notify>,
) -> bool {
    // Ctrl+C — quit from anywhere; `q` quits only outside search input.
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)
        || key.code == KeyCode::Char('q') && !state.search_active()
    {
        shutdown.notify_one();
        return true;
    }
    // Search input mode (`/`): printable keys edit the query, Enter jumps to the
    // next match, Esc closes, Backspace deletes (spec §3).
    if state.search_active() {
        match key.code {
            KeyCode::Esc => state.search = None,
            KeyCode::Backspace => {
                if let Some(s) = state.search.as_mut() {
                    s.query.pop();
                }
            }
            KeyCode::Enter => jump_to_next_match(state, logs),
            KeyCode::Char(c) => {
                if let Some(s) = state.search.as_mut() {
                    s.query.push(c);
                }
            }
            _ => {}
        }
        return false;
    }
    // Shift+C — copy all logs to clipboard
    if has_clipboard && key.code == KeyCode::Char('C') && key.modifiers.contains(KeyModifiers::SHIFT) {
        copy_logs_to_clipboard(logs, clipboard);
        *last_copy = Some(SystemTime::now());
    }
    match key.code {
        KeyCode::Up => state.scroll_up(1),
        KeyCode::Down => state.scroll_down(1),
        KeyCode::PageUp => state.scroll_up(20),
        KeyCode::PageDown => state.scroll_down(20),
        KeyCode::Home => state.scroll_to_top(),
        KeyCode::End => state.scroll_to_bottom(),
        // Filters: severity descending — [1]ERR [2]WRN [3]INF [4]DBG [5]TRC
        KeyCode::Char('1') => state.toggle_filter(Level::ERROR),
        KeyCode::Char('2') => state.toggle_filter(Level::WARN),
        KeyCode::Char('3') => state.toggle_filter(Level::INFO),
        KeyCode::Char('4') => state.toggle_filter(Level::DEBUG),
        KeyCode::Char('5') => state.toggle_filter(Level::TRACE),
        KeyCode::Char(' ') => state.paused = !state.paused,
        KeyCode::Char('c') => logs.clear(),
        KeyCode::Char('f') => state.qr_focus = !state.qr_focus,
        KeyCode::Tab => {
            state.panel_mode = match state.panel_mode {
                PanelMode::Full => PanelMode::QrOnly,
                PanelMode::QrOnly => PanelMode::Hidden,
                PanelMode::Hidden => PanelMode::Full,
            }
        }
        KeyCode::Char('/') => {
            state.search = Some(SearchState::default());
            state.auto_scroll = false;
        }
        _ => {}
    }
    false
}

/// Scroll so the next line matching the query is at the top of the viewport.
/// `scroll_offset` is the number of lines to skip from the oldest line (see
/// `draw_logs`), so the matched line index doubles as the offset; `compute_scroll`
/// clamps it to `total - usable`. If filters are active the indices are
/// approximate — recompute over the filtered slice if precision matters.
fn jump_to_next_match(state: &mut TuiState, logs: &[LogRecord]) {
    let Some(search) = state.search.as_mut() else { return };
    let query = search.query.to_lowercase();
    if query.is_empty() {
        return;
    }
    let matches: Vec<usize> = logs
        .iter()
        .enumerate()
        .filter(|(_, rec)| rec.message.to_lowercase().contains(&query))
        .map(|(i, _)| i)
        .collect();
    if matches.is_empty() {
        return;
    }
    let line = matches[search.cursor % matches.len()];
    search.cursor += 1;
    state.scroll_offset = line as u16;
    state.auto_scroll = false;
}

/// Build the TUI channels and spawn the TUI thread. Returns a [`TuiHandle`].
pub fn spawn_tui(initial: CertView, shutdown: Arc<tokio::sync::Notify>) -> anyhow::Result<TuiHandle> {
    let (log_tx, log_rx) = crossbeam_channel::unbounded::<LogRecord>();
    let cert = Arc::new(Mutex::new(initial));
    let info = Arc::new(Mutex::new(ServerInfo::default()));
    let stats = Arc::new(ServerStats::new());
    let sessions = Arc::new(Mutex::new(Vec::new()));

    let cert_clone = cert.clone();
    let info_clone = info.clone();
    let stats_clone = stats.clone();
    let sessions_clone = sessions.clone();
    let shutdown_clone = shutdown.clone();

    let (init_tx, init_rx) = crossbeam_channel::bounded::<anyhow::Result<()>>(1);
    std::thread::spawn(move || {
        // run_tui sends Ok(()) right after terminal setup, so spawn_tui below
        // returns immediately instead of waiting for the TUI loop to finish.
        let _ = run_tui(log_rx, cert_clone, info_clone, stats_clone, sessions_clone, shutdown_clone, init_tx);
    });

    match init_rx.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(anyhow::anyhow!("TUI failed to start: {}", e)),
        Err(_) => {}
    }

    Ok(TuiHandle {
        log_tx,
        cert,
        info,
        stats,
        sessions,
        shutdown,
    })
}
```

- [ ] **Step 6: Rewire `relay/mod.rs` and `lib.rs` to the new `ui` module**

`lib.rs`: replace `pub mod tui;` with `pub mod ui;`; fix `use crate::tui::CertView;` (lib.rs:31) → `use crate::ui::view::CertView;`.

`logging/mod.rs` (imports that would break when `tui.rs` is deleted):
- `use crate::tui::TuiHandle;` (logging.rs:13) → `use crate::ui::TuiHandle;`.
- `crate::tui::LogRecord` (logging.rs:55) → `crate::ui::view::LogRecord`.

`relay/mod.rs`:
- Import `use crate::ui::TuiHandle;` instead of `use crate::tui::TuiHandle;`.
- All `crate::tui::CertView` / `crate::tui::ServerInfo` / `crate::tui::LogRecord` references become `crate::ui::view::{...}`.
- `ServerStats` type comes from `crate::ui::view::ServerStats` (re-exported from `relay::stats`). To avoid a circular type reference, `relay::stats` owns the definition and `ui::view` re-exports it (`pub use crate::relay::stats::ServerStats;`). Adjust `view.rs` accordingly.
- Replace `self.tui.set_stats(sessions, messages)` calls with the new method (same name, same signature).
- Add session-row publishing: after `self.sessions.insert(...)`, and in the housekeeping tick, build `Vec<SessionRow>` from the registry and call `self.tui.set_sessions(rows)`.

`main.rs` cleanup (Bug 5): after `run()` returns, the terminal is already restored by `run_tui`; keep the defensive `disable_raw_mode`/`LeaveAlternateScreen` but add `DisableMouseCapture`:

```rust
    if let Err(e) = run(app_config, shutdown).await {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableMouseCapture
        );
        eprintln!("Fatal error: {}", e);
        std::process::exit(1);
    }
```

- [ ] **Step 7: Run the full test suite**

Run: `cargo test --locked`
Expected: PASS (existing tests don't touch the TUI, plus the new `ui::view` unit tests).

- [ ] **Step 8: Commit**

```bash
git add src/ui src/tui.rs src/lib.rs src/relay src/main.rs
git commit -m "feat(tui): redesign UI with live stats, event-driven rendering, working scroll/filters, QR hint"
```

---

### Task 6: Reorganize tests — inline module units + `tests/` integration; unify naming; fix `#[cfg(test)]`

**Files:**
- Create: `tests/common/mod.rs`, `tests/handshake.rs`, `tests/relay.rs`, `tests/config.rs`, `tests/storage.rs`
- Modify: `src/protocol/mod.rs` (inline `#[cfg(test)] mod`), `src/storage.rs`, `src/cert.rs`, `src/config/mod.rs`, `src/crypto/mod.rs`, `src/ui/view.rs`, `src/cli/mod.rs`
- Delete: `src/tests.rs`
- Modify: `src/lib.rs` (remove `#[cfg(test)] mod tests;`)
- Test: the new `tests/` integration files

**Interfaces:**
- Consumes: `crate::relay::auth` (verify path), `crate::protocol::framing::{try_read_packet, TryReadResult}`, `crate::protocol::*`, `crate::storage::MessageStore`, `crate::crypto::*`, `crate::config::*`, `crate::cli::*`.
- Produces: `tests/common/mod.rs` with `pub fn derive_argon2_key(password, stored_hash) -> Vec<u8>` and `pub fn build_client_auth(password, nonce, stored_hash) -> Vec<u8>` (single source; replaces the triplicated helpers at tests.rs:294/467/1456).

- [ ] **Step 1: Write the failing test**

Create `tests/common/mod.rs`:

```rust
//! Shared helpers for integration tests (single source for the Argon2+HMAC
//! client-side auth packet builder). Replaces the triplicated helpers that
//! used to live in `src/tests.rs`.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use impulse_server::protocol::{Opcode, PacketReader, PacketWriter};

type HmacSha256 = Hmac<Sha256>;

/// Derive a 32-byte Argon2id raw key from a password using the salt + params
/// stored in an encoded hash. Mirrors `relay::auth::derive_argon2_key`.
pub fn derive_argon2_key(password: &str, stored_hash: &str) -> Vec<u8> {
    use argon2::password_hash::PasswordHash;
    let parsed = PasswordHash::new(stored_hash).expect("should parse stored hash");
    let salt = parsed.salt.expect("stored hash should have a salt");
    let mut raw_salt_buf = [0u8; 64];
    let raw_salt = salt
        .decode_b64(&mut raw_salt_buf)
        .expect("should decode B64 salt");
    let mut output = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), raw_salt, &mut output)
        .expect("Argon2 derivation should not fail");
    output.to_vec()
}

/// Build a client Auth packet: [0x01] [u32 LE pwd_len] [pwd_bytes] [32 raw HMAC].
pub fn build_client_auth(password: &str, server_nonce: &[u8], stored_hash: &str) -> Vec<u8> {
    let key = derive_argon2_key(password, stored_hash);
    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(server_nonce);
    let hmac_response = mac.finalize().into_bytes().to_vec();
    let mut w = PacketWriter::with_opcode(Opcode::Auth);
    w.write_len_prefixed(password.as_bytes());
    w.write_raw(&hmac_response);
    w.into_bytes()
}

/// Assert two byte slices are equal (handy for packet wire-format checks).
pub fn assert_bytes_eq(a: &[u8], b: &[u8]) {
    assert_eq!(a, b, "byte slices differ: {a:02x?} vs {b:02x?}");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --locked --test common`
Expected: FAIL — `tests/common` is a module without a root test target; after Step 4 the `tests/*.rs` targets compile against it.

- [ ] **Step 3: Create the integration test files**

`tests/handshake.rs` — move `auth_tests` (tests.rs:173-271), `handshake_tests` (tests.rs:286-443), and the auth portions of `integration_protocol_tests` (tests.rs:536-811) here, using `tests::common::{build_client_auth, derive_argon2_key}`. Test naming: `snake_case`, no `test_` prefix (e.g. `full_handshake_valid_password` stays; `test_auth_packet_full_wire_format` becomes `auth_packet_full_wire_format`).

```rust
mod common;

use impulse_server::crypto::{argon2_hash, argon2_verify};
use impulse_server::protocol::{
    Opcode, PacketReader, PacketWriter, encode_auth_challenge, encode_auth_result,
};
use common::{assert_bytes_eq, build_client_auth, derive_argon2_key};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
/* ... moved test bodies (snake_case names, via common helpers) ... */
```

`tests/relay.rs` — move the multi-client relay, key-exchange relay, per-recipient blob, and E2E lifecycle tests (tests.rs:813-1058, 1213-1438, 1444-1897) here, using `tests::common`. Fix `crate::server::try_read_packet` references to `impulse_server::protocol::framing::{try_read_packet, TryReadResult}`. Add the Bug 1 regression: extend an existing lifecycle test so that after a client drops mid-session, the relay session registry and `stats.sessions` return to 0 (assert `server.sessions.len() == 0` and `server.stats.sessions.load(Ordering::Relaxed) == 0` after the disconnect path completes).

`tests/config.rs` — move `config_tests` (tests.rs:1900-2067) here with imports `impulse_server::config::cli::*`, `impulse_server::config::*`.

`tests/storage.rs` — move the public-API tests (`storage_tests` public parts, `test_storage_ttl_boundary`, concurrency/ordering tests) here with `impulse_server::storage::*`. Keep the `push_with_timestamp` timestamp-injection tests inline in `src/storage/mod.rs` — that method is `pub(crate)` and integration tests cannot see it. Add the Bug 2 regression test:

```rust
#[tokio::test]
async fn concurrent_push_allocates_monotonic_ids_within_lock() {
    use std::sync::Arc;
    let store = Arc::new(MessageStore::new());
    let mut handles = Vec::new();
    for i in 0u32..100 {
        let s = store.clone();
        handles.push(tokio::spawn(async move { s.push(vec![i as u8; 4]) }));
    }
    for h in handles { h.await.unwrap(); }
    let all = store.since(0, 200);
    for w in all.windows(2) {
        assert!(w[0].id < w[1].id, "ids must be strictly monotonic");
    }
}
```

- [ ] **Step 4: Fix the storage id-ordering race (Bug 2)**

`src/storage/mod.rs` (was `storage.rs`): allocate the id inside the same mutex as `order.push_back` so concurrent pushes yield strictly monotonic ids. Today `alloc_id` = `fetch_add` runs outside the lock (storage.rs:61-63), so thread A can take id 5 and thread B id 6, then B enqueues before A → `since()` returns `[6,5]`. Move the allocation under the lock:

```rust
/// Core insertion used by [`push`]; also lets tests inject a fixed timestamp.
pub(crate) fn push_with_timestamp(&self, payload: Vec<u8>, timestamp: u64) -> StoredMessage {
    // Bug 2: allocate the id while holding the lock so the sequence observed
    // in `order` (and returned by `since`) is strictly monotonic even under
    // concurrent pushes.
    let mut order = lock_order(&self.order);
    let id = self.next_id.fetch_add(1, Ordering::Relaxed);
    let msg = StoredMessage { id, payload, timestamp };
    self.inner.insert(id, msg.clone());
    order.push_back(id);
    while order.len() > MAX_MESSAGES {
        if let Some(oldest) = order.front().copied() {
            order.pop_front();
            self.inner.remove(&oldest);
        } else {
            break;
        }
    }
    msg
}
```

Delete the now-unused `alloc_id` helper. Note: `msg.clone()` (payload copy into the ring) is required to return the owned record while storing the same one — the relay reads stored records via `since()`, so the payload must live in the map; the spec §2 "stops cloning" line is intentionally NOT applied because the return type (`StoredMessage`) would have to change.

Run just the regression first to confirm RED→GREEN: `cargo test --locked --test storage concurrent_push_allocates_monotonic_ids_within_lock`.

- [ ] **Step 5: Move the remaining unit tests inline**

- `protocol_tests` (tests.rs:11-94) → inline `#[cfg(test)] mod tests` in `src/protocol/mod.rs` (or `framing.rs`). Naming: `snake_case` (`auth_roundtrip_layout`, etc.).
- `cert_tests` (tests.rs:96-112) → `src/cert.rs` `#[cfg(test)] mod`.
- `combined_key_exchange_tests` (tests.rs:1214-1438) → inline in `src/protocol/mod.rs`, using `try_read_packet` from `framing`.
- `setup_tests` (tests.rs:2069-2122) → `src/cli/write.rs` `#[cfg(test)] mod tests` (already staged in Task 4).
- Fix the missing `#[cfg(test)]` on `setup_tests` (tests.rs:2069) — it gets it by being inside `write.rs`'s `#[cfg(test)] mod tests`.
- Unify naming to `snake_case` throughout.

- [ ] **Step 6: Delete `src/tests.rs` and its registration**

`src/lib.rs`: remove `#[cfg(test)] mod tests;` (the current lines 21-22).

- [ ] **Step 7: Run the full test suite**

Run: `cargo test --locked`
Expected: PASS — all relocated tests run, count stays at 69 + new (Task 3/5 tests + Bug 2 regression + any added during moves). Verify pristine output (no warnings).

- [ ] **Step 8: Commit**

```bash
git add tests src
git rm src/tests.rs
git commit -m "test: reorganize into inline module units and tests/ integration, unify naming, add storage race regression"
```

---

### Task 7: Docs, CI, version bump → release 2.6.0

**Files:**
- Modify: `Cargo.toml`, `Cargo.lock`, `flake.nix`
- Modify: `.github/workflows/server-build.yml` (add `cargo test --locked` job)
- Modify: `src/lib.rs` (module overview), `src/relay/mod.rs`, `src/protocol/mod.rs`, `src/ui/mod.rs` (module docs), `README.md`, `README.ru.md`
- Test: CI workflow + release

**Interfaces:**
- Consumes: everything from Tasks 1-6.
- Produces: tag `v2.6.0`, 10 release assets.

- [ ] **Step 1: Version bump to 2.6.0**

`Cargo.toml`: line 3 `version = "2.5.1"` → `"2.6.0"`; line 104 (generate-rpm) `version = "2.5.1"` → `"2.6.0"`.

`Cargo.lock`: update the `impulse-server` package version. Run `cargo check` to regenerate, then confirm the diff shows `2.6.0`.

`flake.nix`: line 18 `version = "2.5.1"` → `"2.6.0"`.

- [ ] **Step 2: Add CI test job to `.github/workflows/server-build.yml`**

Add a `test` job (runs on push/PR, before build):

```yaml
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust nightly
        uses: dtolnay/rust-toolchain@nightly
      - name: Cache cargo registry + build
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-test-${{ hashFiles('Cargo.lock') }}
          restore-keys: |
            ${{ runner.os }}-cargo-test-
      - name: Test
        run: cargo test --locked
```

Add `build` job dependency: `needs: test`.

- [ ] **Step 3: Add `checks` to `flake.nix`**

```nix
      checks = forAllSystems (system:
        let pkgs = pkgsFor system;
        in {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "impulse-server";
            version = "2.6.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            nativeBuildInputs = with pkgs; [ cmake perl ];
            doCheck = true;
          };
        });
```

- [ ] **Step 4: Documentation refresh**

`src/lib.rs` module overview (lib.rs:1-10) — rewrite to list all modules:

```rust
//! Impulse server — a secure, ephemeral messenger relay over WebTransport (QUIC).
//!
//! Architecture overview:
//! * `cert` — self-signed ECDSA P-256 certificate generation, 14-day TTL,
//!   2-day overlap rotation, SHA-256 TOFU fingerprint.
//! * `storage` — ephemeral in-RAM message log with 72h TTL and sequence ids.
//! * `protocol` — binary wire frames (opcodes 0x01–0x0C) over WebTransport;
//!   framing and size limits live in `protocol::framing` / `protocol::limits`.
//! * `crypto` — Argon2id password hashing + verification (auth chain).
//! * `relay` — WebTransport endpoint, session handling, broadcast relay,
//!   auth handshake (`relay::auth`), and housekeeping (`relay::housekeeping`).
//! * `ui` — terminal UI: Server/Sessions panels, TOFU QR, live stats, log view.
//! * `config` — configuration resolution (`mod`), CLI parsing (`cli`), file
//!   loading (`file`).
//! * `cli` — first-run / `--init` interactive wizards and config writing.
//! * `logging` — `tracing` → TUI / file bridge.
```

Add module doc headers to `relay/session.rs`, `relay/auth.rs`, `relay/housekeeping.rs`, `protocol/framing.rs`, `ui/mod.rs`, `ui/draw.rs` (done in their tasks; verify).

`README.md` / `README.ru.md`: update the TUI section to describe the new keys (`1-5` = ERR/WRN/INF/DBG/TRC, `Space` pause, `Tab` panel cycle, `f` QR focus, mouse wheel), the status bar, and live stats.

Delete stale comments: `tests.rs:466` (already gone with tests.rs), `tui.rs:97-98` (gone with tui.rs). Verify no remaining references to `server.rs`/`tui.rs` paths in comments (`git grep -n "server.rs" src/`).

- [ ] **Step 5: Full local verification**

Run: `cargo test --locked` → PASS, pristine output.
Run: `cargo build --release` → clean.

Manual TUI smoke (interactive, on a terminal): scroll `↑↓`/`PgUp`/`End`, filters `1-5`, `/` search, `Space` pause, `Tab`/`f` panel toggles, mouse wheel, QR renders fully (no truncation), stats update live, `q` restores terminal.

Manual CLI smoke: `impulse-server --license`; `--init --force` writes config; `--force` alone rejected ("--force requires --init"); `--config packaging/config.toml` (missing file) loud-error; `--hash-password` prints an Argon2 hash and exits.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock flake.nix .github/workflows/server-build.yml src/lib.rs README.md README.ru.md
git commit -m "chore: bump to 2.6.0, add CI tests and nix checks, refresh docs"
```

- [ ] **Step 7: Release 2.6.0**

```bash
git push origin master
git tag v2.6.0
git push origin v2.6.0
gh run watch
```

Expected: workflow (including the new `test` job) succeeds. Verify 10 assets named `ImpulseServer-2.6.0-<os>-<arch>.<ext>`; spot-check `ImpulseServer-2.6.0-linux-amd64.tar.gz` contains exactly `impulse-server` + `LICENSE`; spot-check `ImpulseServer-2.6.0-linux-amd64.deb` installs `/etc/impulse-server/config.toml` with an empty `password_hash`.

---

## Verification

- `cargo test --locked` passes on Windows at the end of every task; final run pristine (no warnings).
- `cargo build --release` clean.
- Manual TUI smoke per Task 7 Step 5.
- Manual CLI smoke per Task 7 Step 5.
- Release v2.6.0 with 10 verified assets.
