//! Authentication handshake for WebTransport sessions.
//!
//! Protocol (SPEC C3, §4.2 — HMAC-only challenge response):
//!   Client sends: [0x01] [u32 hmac_len=32] [32 raw bytes: HMAC-SHA-256]
//!   HMAC key   = Argon2id(stored_hash) output (32 bytes) — derived by the
//!                server directly from the stored hash, so the password never
//!                travels on the wire (C3).
//!   HMAC msg   = server nonce (16 bytes)
//! The nonce is single-use (C4): a successful verification consumes it, so a
//! replayed 0x01 frame is rejected.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use argon2::password_hash::PasswordHash;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::protocol::limits::MAX_PAYLOAD_BYTES;
use crate::protocol::{Opcode, PacketReader, RelayedMessage, ServerPacketEncoder};
use crate::relay::{MAX_AUTH_ATTEMPTS, MAX_SYNC_MESSAGES, RelayServer};
use crate::relay::session::Session;

type HmacSha256 = Hmac<Sha256>;

/// Derive the 32-byte HMAC key for challenge-response by re-running Argon2 with
/// the exact parameters and salt stored in the config hash.
///
/// Retained for parity with the client-side derivation (`crypto::derive_argon2_key`);
/// the server verifies the client's HMAC via [`crate::crypto::hmac_key_from_stored_hash`],
/// which needs no password (C3). Kept (not deleted) so the derivation logic stays in one
/// obvious place; marked allow(dead_code) because the server path no longer needs it.
#[allow(dead_code)]
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

/// Verify the client's challenge-response against the stored Argon2 hash.
///
/// The client sends only `HMAC(Argon2id(stored_hash), nonce)` (C3) — no password on the
/// wire. The server derives the HMAC key directly from the stored hash's embedded Argon2id
/// output (via [`crate::crypto::hmac_key_from_stored_hash`]) and compares it to the response.
/// On success the nonce is consumed so a replayed frame fails (C4). Fail-closed: any
/// missing/incorrect/again-used nonce, or a HMAC mismatch, rejects.
pub(crate) async fn verify_auth(
    relay: &Arc<RelayServer>,
    session: &Session,
    client_response: &[u8],
) -> bool {
    // Derive the HMAC key directly from the stored hash — no password needed (C3).
    let key = match crate::crypto::hmac_key_from_stored_hash(&relay.password_hash) {
        Ok(k) => k,
        Err(e) => {
            relay.stats.auth_fail.fetch_add(1, Ordering::Relaxed);
            warn!("[AUTH] Session {} cannot derive HMAC key: {}", session.key, e);
            return false;
        }
    };

    let nonce_valid = match relay.auth_nonces.get(&session.key) {
        Some(entry) => {
            let (nonce, created_at) = (entry.value().0.clone(), entry.value().1);
            let age = Instant::now().duration_since(created_at);
            if age > relay.nonce_max_age {
                warn!("[AUTH] Session {} challenge nonce expired", session.key);
                false
            } else if client_response.len() != 32 {
                warn!("[AUTH] Session {} missing/incorrect challenge response", session.key);
                false
            } else {
                let mut mac = match HmacSha256::new_from_slice(&key) {
                    Ok(m) => m,
                    Err(_) => return false,
                };
                mac.update(&nonce);
                let ok = mac.verify_slice(client_response).is_ok();
                if !ok {
                    warn!("[AUTH] Session {} HMAC challenge response mismatch", session.key);
                }
                ok
            }
        }
        None => {
            warn!("[AUTH] Session {} no challenge nonce found", session.key);
            false
        }
    };

    if nonce_valid {
        // C4 (§4): consume the nonce so a replayed 0x01 frame fails on second use.
        relay.auth_nonces.remove(&session.key);
        relay.stats.auth_ok.fetch_add(1, Ordering::Relaxed);
    } else {
        relay.stats.auth_fail.fetch_add(1, Ordering::Relaxed);
    }
    nonce_valid
}

/// Dispatch a complete client packet to its handler.
///
/// Server→client opcodes (AuthResult, SyncResponse, NewCertHash, AuthChallenge)
/// are unreachable here — `try_read_packet` filters them out as
/// `UnknownOpcode` — so the former `IGNORE` arm is dead code (spec Bug 7) and
/// is handled only for match exhaustiveness.
pub(crate) async fn process_packet(
    relay: &Arc<RelayServer>,
    session: &mut Session,
    direct_tx: &mpsc::Sender<Vec<u8>>,
    packet_data: &[u8],
) -> anyhow::Result<()> {
    let mut reader = PacketReader::new(packet_data);
    let opcode = reader.read_opcode().map_err(|e| anyhow::anyhow!("{}", e))?;
    let session_key = session.key;

    match opcode {
        Opcode::Auth => {
            // C3 (§4.2): HMAC-only challenge response. Wire:
            //   [0x01] [u32 hmac_len=32] [32 hmac_response]
            // The password never travels on the wire; the server verifies the HMAC
            // against the key derived directly from the stored Argon2id hash (no password
            // needed). C4 (§4): skip re-auth for an already-authenticated session.
            if session.authenticated {
                // Drain the frame and ignore — do not re-verify or re-broadcast.
                let _ = reader.remaining();
                return Ok(());
            }

            let hmac_field = reader
                .read_len_prefixed()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if hmac_field.len() != 32 {
                warn!(
                    "[AUTH] Session {} malformed Auth frame (HMAC field is {} bytes, expected 32)",
                    session_key, hmac_field.len()
                );
                return Err(anyhow::anyhow!("malformed Auth frame"));
            }

            // Check brute-force limit.
            let attempts = relay.auth_attempts.entry(session_key).or_insert_with(|| AtomicU32::new(0));
            if attempts.load(Ordering::Relaxed) >= MAX_AUTH_ATTEMPTS {
                warn!("[AUTH] Session {} brute-force limit reached ({} attempts), closing",
                    session_key, MAX_AUTH_ATTEMPTS);
                return Err(anyhow::anyhow!("brute-force limit exceeded"));
            }
            attempts.fetch_add(1, Ordering::Relaxed);

            // Verify the HMAC challenge-response (key derived from stored hash, C3).
            let ok = verify_auth(relay, session, &hmac_field).await;

            let response = ServerPacketEncoder::auth_result(
                ok,
                if ok { None } else { Some("Invalid password or challenge") },
            );
            direct_tx
                .send(response)
                .await
                .map_err(|_| anyhow::anyhow!("direct channel closed"))?;

            if ok {
                session.authenticated = true;
            }
            if !ok {
                // Slow down brute-force attempts
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                return Err(anyhow::anyhow!("authentication failed"));
            }

            // Replay stored key exchanges from ALL OTHER sessions so this
            // newly-authenticated client can send messages to peers that
            // connected before it.
            let mut replayed = 0u32;
            for entry in relay.key_exchange_store.iter() {
                let src = *entry.key();
                if src == session_key {
                    continue;
                }
                for packet in entry.value() {
                    if let Err(e) = direct_tx.send(packet.clone()).await {
                        warn!("[AUTH] Session {} failed to replay keyex from session {}: {}", session_key, src, e);
                    } else {
                        replayed += 1;
                    }
                }
            }
            if replayed > 0 {
                debug!(
                    "[AUTH] Session {} replayed {} stored key exchanges from peers",
                    session_key, replayed
                );
            }

            Ok(())
        }
        Opcode::Sync => {
            if !session.authenticated {
                warn!("[SYNC] Session {} REJECTED: not authenticated", session_key);
                return Err(anyhow::anyhow!("not authenticated"));
            }
            let last_seen_id = reader.read_u64().map_err(|e| anyhow::anyhow!("{}", e))?;
            debug!(
                "[SYNC] Session {} sync request last_seen_id={}",
                session_key, last_seen_id
            );

            let replay = relay.store.since(last_seen_id, MAX_SYNC_MESSAGES);
            let messages: Vec<(u64, u64, Vec<u8>)> = replay
                .into_iter()
                .map(|m| (m.id, m.timestamp, m.payload))
                .collect();
            debug!(
                "[SYNC] Session {} returning {} messages",
                session_key,
                messages.len()
            );

            let response = ServerPacketEncoder::sync_response(&messages);
            direct_tx
                .send(response)
                .await
                .map_err(|_| anyhow::anyhow!("direct channel closed"))?;
            Ok(())
        }
        Opcode::Data => {
            if !session.authenticated {
                warn!("[DATA] Session {} REJECTED: not authenticated", session_key);
                return Err(anyhow::anyhow!("not authenticated"));
            }
            let payload = reader
                .read_len_prefixed()
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            debug!(
                "[DATA] Session {} data payload={} bytes",
                session_key,
                payload.len()
            );

            if payload.len() > MAX_PAYLOAD_BYTES {
                warn!(
                    "[DATA] Session {} OVERSIZED payload {} > {}, dropping",
                    session_key,
                    payload.len(),
                    MAX_PAYLOAD_BYTES
                );
                return Ok(());
            }

            let stored = relay.store.push(payload.clone());
            debug!(
                "[DATA] Session {} stored id={}, broadcasting",
                session_key, stored.id
            );
            let relayed = RelayedMessage {
                id: stored.id,
                timestamp: stored.timestamp,
                payload: stored.payload,
            };
            let subs = relay.data_tx.send((session_key, relayed));
            match subs {
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
                Err(_) => debug!("[DATA] Session {} broadcast: no receivers", session_key),
            }
            Ok(())
        }
        Opcode::Heartbeat => {
            if !session.authenticated {
                warn!("[HEARTBEAT] Session {} REJECTED: not authenticated", session_key);
                return Err(anyhow::anyhow!("not authenticated"));
            }
            let client_ts = reader.read_u64().map_err(|e| anyhow::anyhow!("{}", e))?;
            debug!(
                "[HEARTBEAT] Session {} client_ts={}",
                session_key, client_ts
            );
            let response = ServerPacketEncoder::heartbeat(client_ts);
            direct_tx
                .send(response)
                .await
                .map_err(|_| anyhow::anyhow!("direct channel closed"))?;
            Ok(())
        }
        Opcode::KeyExchangeKemDsa => {
            if !session.authenticated {
                warn!(
                    "[KEYEX] Session {} REJECTED: not authenticated",
                    session_key
                );
                return Err(anyhow::anyhow!("not authenticated"));
            }
            let combined_payload = reader.remaining().to_vec();
            debug!(
                "[KEYEX] Session {} combined KEM+DSA payload={} bytes",
                session_key,
                combined_payload.len()
            );

            // Build relay packet preserving the original client frame format:
            // [0x0C] [u32: total_inner] [u32: kem_len] [kem] [u32: dsa_len] [dsa]
            // combined_payload already contains everything after the opcode byte
            // (including the outer u32 total_inner), so just prepend the opcode.
            let mut packet = vec![opcode.as_u8()];
            packet.extend_from_slice(&combined_payload);
            let _ = relay
                .keyexchange_tx
                .send((session_key, packet.clone()));
            relay.key_exchange_store
                .entry(session_key)
                .or_default()
                .push(packet);
            debug!("[KEYEX] Session {} relayed combined KEM+DSA to all peers", session_key);
            // Derive the user identity from the KEM public key (no wire change).
            // First 0x0C of a session binds it to the user; a re-sent 0x0C
            // (peer key request) only refreshes last_seen.
            if session.user.is_none() {
                if let Some(fp) = crate::relay::users::fingerprint_of_keyexchange(packet_data) {
                    let alias = relay.users.bind_session(&fp);
                    session.user = Some(fp.clone());
                    // Mirror the binding into the live-session registry so
                    // disconnect cleanup can release the user (Bug: online
                    // status stuck after client disconnect).
                    if let Some(mut meta) = relay.sessions.get_mut(&session_key) {
                        meta.user = Some(fp);
                    }
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
            Ok(())
        }
        Opcode::Disconnect => {
            info!("[DISCONNECT] Session {} disconnecting", session_key);
            Err(anyhow::anyhow!("client disconnected"))
        }
        // Server→client opcodes never reach this function (see the module doc);
        // kept only for match exhaustiveness.
        Opcode::AuthResult
        | Opcode::SyncResponse
        | Opcode::NewCertHash
        | Opcode::AuthChallenge => Ok(()),
    }
}
