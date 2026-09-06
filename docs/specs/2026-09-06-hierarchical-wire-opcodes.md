# SPEC: Hierarchical Domain-Categorized Wire Opcodes (v3.0)

- **Date:** 2026-09-06
- **Status:** APPROVED-FOR-IMPLEMENTATION
- **Scope:** Synchronous wire-protocol refactoring across Server (Rust) and Client (Android/Kotlin).
- **Authors:** Impulse Architecture Working Group

---

## 1. Motivation & Context

The historical opcode scheme in Impulse grew incrementally, resulting in:
1. Non-contiguous opcode ranges: `0x01`–`0x08`, unused gap `0x09`–`0x0A`, then `0x0B` and `0x0C`.
2. Disconnected handshake ordering: `AuthChallenge` was assigned `0x0B` despite being the first packet exchanged on connection.
3. Lack of domain namespacing in both code and wire packet analysis.

## 2. Specification of Domain-Categorized Opcodes

All packets retain their 1-byte opcode prefix (`u8`). The byte is divided into:
- **High Nibble (bits 4..7):** Domain/Category
  - `0x1_`: **Auth Handshake**
  - `0x2_`: **Session Control & Transport**
  - `0x3_`: **Data, Cryptography & Relay**
- **Low Nibble (bits 0..3):** Action / Command ID within the domain.

### Complete Opcode Mapping

| Domain | Hex Byte | Symbol | Description | Direction |
| :--- | :---: | :--- | :--- | :---: |
| **Auth (0x1_)** | `0x11` | `AuthChallenge` | 16-byte nonce + salt + Argon2 params | Server $\rightarrow$ Client |
| | `0x12` | `AuthResponse` | 32-byte HMAC-SHA-256 password proof | Client $\rightarrow$ Server |
| | `0x13` | `AuthResult` | Status byte (`0x01`=OK, `0x00`=Err) + error string | Server $\rightarrow$ Client |
| **Session (0x2_)** | `0x21` | `Heartbeat` | Monotonic client timestamp (`u64`) | Bidirectional |
| | `0x22` | `NewCertHash` | 32-byte SHA-256 cert hash + expiry timestamp (`u64`) | Server $\rightarrow$ Client |
| | `0x23` | `Disconnect` | Graceful disconnection notice (0 payload bytes) | Bidirectional |
| **Data (0x3_)** | `0x31` | `KeyExchange` | KEM pubkey + DSA pubkey + ML-DSA-65 signature | Bidirectional |
| | `0x32` | `Data` | AES-256-GCM encrypted message payload | Bidirectional |
| | `0x33` | `Sync` | Sync request with `last_seen_id` (`u64`) | Client $\rightarrow$ Server |
| | `0x34` | `SyncResponse` | Sync reply: `count` (`u32`) + array of messages | Server $\rightarrow$ Client |

---

## 3. Server Architecture Changes (Rust)

In `src/protocol.rs`:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    AuthChallenge = 0x11,
    Auth = 0x12,
    AuthResult = 0x13,
    Heartbeat = 0x21,
    NewCertHash = 0x22,
    Disconnect = 0x23,
    KeyExchangeKemDsa = 0x31,
    Data = 0x32,
    Sync = 0x33,
    SyncResponse = 0x34,
}
```
Category helper methods:
```rust
pub enum OpcodeCategory { Auth, Session, Data }
```
Framing (`framing.rs`):
- `try_read_packet` updated for opcodes `0x11..=0x34`.

---

## 4. Client Architecture Changes (Kotlin)

In `transport/Protocol.kt`:
```kotlin
object Protocol {
    object Op {
        object Auth {
            const val CHALLENGE: Byte = 0x11
            const val RESPONSE: Byte = 0x12
            const val RESULT: Byte = 0x13
        }
        object Session {
            const val HEARTBEAT: Byte = 0x21
            const val NEW_CERT_HASH: Byte = 0x22
            const val DISCONNECT: Byte = 0x23
        }
        object Data {
            const val KEY_EXCHANGE: Byte = 0x31
            const val DATA: Byte = 0x32
            const val SYNC: Byte = 0x33
            const val SYNC_RESPONSE: Byte = 0x34
        }
    }
}
```
Backward-compatible aliases (`OP_AUTH = Op.Auth.RESPONSE`, etc.) maintained for zero regression.

---

## 5. Test Gate
- Server: `cargo test` and `cargo clippy -- -D warnings` must pass 100%.
- Client: `./gradlew testDebugUnitTest` must pass 100%.
