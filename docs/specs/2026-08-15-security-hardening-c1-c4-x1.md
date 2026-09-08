# SPEC: Security Hardening C1–C4, X1, N1–N3 (Спринт 0)

Status: APPROVED-FOR-IMPLEMENTATION (read-only audit Фаза-1 confirmed all findings)
Scope: Impulse server (Rust) + client (Kotlin), wire-protocol changes require synchronized edits.
Author: orchestrator (hy3) · Date: 2026-08-15

This document is the single source of truth (frozen contract) for the
implementation phase. Code changes MUST follow it exactly. Any deviation is a
policy violation (policies.md §4: crypto/wire changes only through SPEC+audit).

---

## 0. PHILOSOPHY (non-negotiable guardrails)

These principles SHAPE every fix below. A fix that violates them is rejected
even if it closes the CVE.

1. **E2EE is sacred — the server never sees plaintext.**
   The relay is and stays opaque. Fixes for C1/C2/C4 must be *client-side* or
   *server-side routing-only*. The server must NOT decrypt, inspect, or log
   message content. (forbidden zone, AGENTS.md, policies §7.)
2. **Argon2id stays at OWASP strength: m=47104, t=3, p=1. Never weaken.**
3. **Wire-protocol (0x01–0x0C) changes require synchronized client+server edits**
   and are specified here in §4. No silent opcode redefinition.
4. **Fail-closed everywhere.** Auth/crypto failures reject; they never silently
   downgrade or accept.
5. **The server authenticates *sessions*, not *peer keys*.** Peer-key trust is
   the client's job (TOFU/QR + attestation). The server only stamps provenance
   metadata it can honestly assert (which session sent a frame).

---

## 1. C1 — KEM/DSA key substitution via unauthenticated 0x0C relay (MITM)

### Root cause (confirmed Фаза-1)
- Server `relay/auth.rs:285-338` relays a `0x0C` frame opaquely to all peers,
  gating only on `session.authenticated` (shared password), never on proof that
  the sender *owns* the KEM private key.
- Client `ChatController.kt:1254-1271` + `PublicKeyRepository.kt:13-34` blindly
  overwrite the cached peer key on any incoming `0x0C`, recomputing the
  identity fingerprint from the attacker's own key bytes.

### Design (philosophy-shaped)
Attestation is **client-side** (server stays opaque): the key *announcer* signs
`KEM_pub || DSA_pub` with its **ML-DSA-65 private key**; the receiver verifies
the signature against the *previously known / TOFU-pinned* DSA public key before
trusting the new KEM/DSA pair. The server adds an honest **origin-session tag**
(it can assert "session X sent this") but never touches key bytes.

### Wire change (0x0C KeyExchangeKemDsa) — §4.1
New inner layout adds a 32-byte ML-DSA-65 signature over the canonical bytes
`KEM_pub || DSA_pub`:
```
[0x0C][u32 inner_len][u32 kem_len][kem][u32 dsa_len][dsa][u32 sig_len][sig]
```
- `sig` = ML-DSA-65 sign( DSA_priv, kem || dsa ). Verified by receiver against
  the peer's *current* DSA public key (TOFU-pinned). On mismatch → drop frame,
  do NOT overwrite cached key (fixes blind merge).

### Client behavior (ChatController.kt)
- On `onCombinedKeyExchange`: verify `sig` against the cached/TOFU DSA key.
  - If no prior key for `kemFp`: cache (initial TOFU) AND show the QR/pin flow
    so the user can confirm out-of-band.
  - If a prior key exists and the new DSA does not verify → **reject**, keep old
    key, surface a "key conflict" warning (MITM indicator).
- KeyRepo: never `upsert` over an existing fingerprint without a verified sig.

### Server behavior (relay/auth.rs, relay/users.rs)
- After relaying, stamp the outbound relay packet with the **origin session id**
  (already available as `session_key`) in the in-memory `key_exchange_store`
  metadata only — do NOT alter the opaque key bytes.
- `fingerprint_of_keyexchange` unchanged (still sha256(kem)[:32]); it is a
  routing id, not a trust anchor.

### Test (RED→GREEN): `tests/exploits.rs::c1_*`
- `c1_attacker_key_without_attestation_is_rejected`: an unattested/garbage 0x0C
  must be refused by the client verifier (currently `fingerprint_of_keyexchange`
  accepts it → RED).
- After fix: add a client-side `verify_keyexchange_attestation()` that returns
  false for unsigned frames.

---

## 2. C2 — plaintext in outbox

### Root cause
- Client `ChatController.kt:94-99,626-643` persists `OutboxEntry.plaintext`
  (cleartext `SharedPreferences`, key `impulse_outbox`).
- Server `storage/mod.rs:61-97` keeps relayed ciphertext 72h and replays the
  FULL backlog to any authenticated `Sync`.

### Design (philosophy-shaped)
- **Client:** persist ONLY the already-encrypted `frame` (it is computed
  alongside `plaintext` today). Drop the `plaintext` field, or encrypt-at-rest
  via existing `SecureStorage` (KeyStore AES-256-GCM). Server never involved.
- **Server:** keep ciphertext (forbidden zone OK), but (a) scope replay to the
  requesting recipient where the protocol allows, and (b) reduce default TTL
  via `config.toml` (non-E2EE change). Do NOT decrypt.

### Test: `tests/exploits.rs::c2_outbox_not_full_history_replay`
- RED today: `store.since(0,N)` returns everything. GREEN: server scopes/strips
  full-history dump (config-gated; for the test, assert a sync does not return
  the entire backlog unconditionally).

---

## 3. C3 — raw password on the wire

### Root cause
- Client `Protocol.kt:143-159` writes the raw password bytes into `0x01`.
- Server `relay/auth.rs:127-131` receives cleartext, runs `argon2_verify`.

### Design (philosophy-shaped)
Replace cleartext transmission with **HMAC-only challenge response** — the
password never leaves the client:
- Client computes `response = HMAC( Argon2id(pw, salt), server_nonce )` and sends
  ONLY `response`. (The existing HMAC path already exists; we DELETE the raw
  password byte field.)
- Server verifies `response` using the key `Argon2id(stored_hash)` (it already
  derives this in `derive_argon2_key`). No cleartext password on the wire, server
  still never sees the password. Fail-closed on mismatch.
- Update the (already wrong) doc comments in `Protocol.kt:18,141` and
  `protocol.rs:10` to state "HMAC response only; password never transmitted".

### Wire change — §4.2 (0x01 Auth)
```
OLD: [0x01][u32 pwd_len][pwd_bytes][32 hmac]
NEW: [0x01][u32 hmac_len=32][32 hmac_response]      (no password field)
```
Backward compat: bump protocol version; both sides must agree (policies §4).

### Test: `tests/exploits.rs::c3_no_raw_password_in_auth_wire`
- RED today: packet body equals the password. GREEN: password substring absent.

---

## 4. C4 — no replay cache / nonce not single-use

### Root cause
- `relay/auth.rs:62-97`: nonce read but never removed after successful auth;
  only pruned by age (30s) or disconnect.
- `relay/auth.rs:123-188`: no `if session.authenticated { return }` guard →
  re-auth re-runs.
- `storage/mod.rs`: no `(sender_fp, nonce)` seen-set → Data replays re-stored.

### Design (philosophy-shaped)
- Server: on successful auth, **remove the nonce** from the pending set
  (consume-once). Add a bounded `seen_nonces: DashMap<session, nonce>` with
  short TTL. Reject a second `0x01` on an already-authenticated session.
- Server storage: deduplicate Data by `(recipient_fp, nonce)` where the inner
  envelope already carries `n`/`ts` (per `buildSignedInnerEnvelope`). Drop
  duplicates instead of re-storing/re-broadcasting.

### Test: `tests/exploits.rs::c4_*`
- `c4_auth_nonce_is_single_use`: same frame+nonce must fail on 2nd verify (RED
  today).
- `c4_storage_dedups_identical_payload`: identical payload → same id (RED today).

---

## 5. X1 + N1 — Argon2id weak default AND broken param contract

### Root cause
- `crypto/mod.rs:32` uses `Argon2::default()` = 19456/2. AGENTS.md:22-23 mandates
  OWASP 47104/3 AND "server sends params in AuthChallenge, client must use them".
- `Protocol.kt:165-183` hardcodes 19456/2 and never reads the challenge.
- **Lockstep mine (N1):** fixing the server alone breaks every client (HMAC key
  diverges) because the client ignores the challenge.

### Design (philosophy-shaped — implements what AGENTS.md ALREADY requires)
1. Server `argon2_hash` → explicit `Params::new(47104, 3, 1, None)` (OWASP).
2. `encode_auth_challenge` (0x0B) **carries m/t/p** (already takes salt; extend
   it). Client reads m/t/p and derives its HMAC key from them → single source of
   truth. This kills N1: clients follow the server, no frozen constant.
3. Keep a **pinned floor** (reject params below OWASP) so a misconfigured server
   cannot weaken auth.

### Wire change — §4.3 (0x0B AuthChallenge)
```
OLD: [0x0B][16 nonce][u32 salt_len][salt_b64]
NEW: [0x0B][16 nonce][u32 salt_len][salt_b64][u32 m][u32 t][u32 p]
```
Client `argon2DeriveKey` reads m/t/p from the parsed challenge (defaulting to
OWASP floor if absent, for old-server compat).

### Test: `tests/exploits.rs::x1_*` and `n1_*`
- `x1_argon2_uses_owasp_params`: hash string contains `m=47104,t=3,p=1` (RED).
- `n1_auth_challenge_carries_argon2_params`: challenge contains m/t/p (RED).

---

## 6. N2 / N3 — payload ceiling drift

### Root cause
- Client `Protocol.kt:45` = 1_048_576; server `limits.rs:4` = 1_000_000 (drift
  48_576). Client `frameLength` also allows ×2 (2 MiB) for 0x05/0x0C.

### Design
- Define **one** `MAX_PAYLOAD_BYTES = 1_000_000` constant, imported by both repos
  (shared spec doc + identical literal + integration test asserting equality).
- Remove the `×2` in client `frameLength`.

### Test: `tests/exploits.rs::n2_*` and `n3_*`
- `n2_payload_ceilings_agree`: client ≤ server (RED today).
- `n3_no_oversized_frame_drift`: no client-accepted frame server rejects (RED).

---

## 7. IMPLEMENTATION ORDER (for the coding phase — frozen)

1. **X1+N1** first (§5): bump Argon2 + transmit m/t/p in 0x0B. Highest blast
   radius if done wrong; do it before any client/server divergence.
2. **C3** (§3): HMAC-only auth (remove raw password field).
3. **C4** (§4): nonce single-use + storage dedup + re-auth guard.
4. **C1** (§1): 0x0C attestation signature (wire §4.1) + client verify.
5. **C2** (§2): client outbox drop plaintext; server TTL/scope (config).
6. **N2/N3** (§6): unify MAX_PAYLOAD_BYTES.

Each step is its own atomic commit, its own test-gate (server `cargo test &&
cargo clippy -D warnings`; client `JAVA_HOME=jdk-17 ./gradlew testDebugUnitTest`),
and flips the corresponding RED exploit test to GREEN.

## 8. VERIFICATION GATE (definitions of done)
- All 10 `tests/exploits.rs` cases GREEN.
- All 3 `tests/multi_client_stress.rs` cases stay GREEN (no regression).
- Existing 42 tests stay GREEN.
- `cargo clippy --locked -- -D warnings` clean; `Cargo.lock` committed if deps
  bumped.
- Client CI equivalent (unit tests) green; if APK build needed, local
  `assembleRelease` per policies.

---

## Appendix A — why server-side crypto validation of peer keys is intentionally
NOT done
C1 could be "fixed" by having the server validate ML-KEM/ML-DSA key bytes. That
would break the E2EE forbidden zone (server would have to understand key
semantics = a step toward content awareness) and centralize trust in the relay,
defeating the user-controlled-host model. Attestation stays client-side; the
server only stamps honest provenance metadata. This is the philosophy-first
choice.
