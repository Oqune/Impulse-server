//! Authentication handshake for WebTransport sessions.
//!
//! Protocol (byte-compatible with v2.5.x):
//!   Client sends: [0x01] [len:raw_password_bytes] [32 raw bytes: HMAC-SHA-256]
//!   HMAC key   = Argon2id(password) output (32 bytes)
//!   HMAC msg   = server nonce (16 bytes)

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use argon2::password_hash::PasswordHash;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::protocol::limits::MAX_PAYLOAD_BYTES;
use crate::protocol::{Opcode, PacketReader, RelayedMessage, ServerPacketEncoder};
use crate::relay::{MAX_AUTH_ATTEMPTS, MAX_SYNC_MESSAGES, RelayServer};
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
/// Returns `true` when the password matches AND the HMAC challenge is valid.
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
            // Auth: [0x01] [len-prefixed: raw password bytes] [32 raw bytes: HMAC-SHA-256]
            // HMAC key = Argon2id(password) output bytes (32 bytes)
            // HMAC message = server nonce (16 bytes)
            let password_bytes = reader
                .read_len_prefixed()
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let password = String::from_utf8(password_bytes)
                .map_err(|_| anyhow::anyhow!("invalid UTF-8 in password"))?;

            // Check brute-force limit.
            let attempts = relay.auth_attempts.entry(session_key).or_insert_with(|| AtomicU32::new(0));
            if attempts.load(Ordering::Relaxed) >= MAX_AUTH_ATTEMPTS {
                warn!("[AUTH] Session {} brute-force limit reached ({} attempts), closing",
                    session_key, MAX_AUTH_ATTEMPTS);
                return Err(anyhow::anyhow!("brute-force limit exceeded"));
            }
            attempts.fetch_add(1, Ordering::Relaxed);

            // Verify password + challenge-response (byte-compatible with v2.5.x).
            let ok = verify_auth(relay, session, &password, reader.remaining()).await;

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
                    relay.stats.relayed_bytes.fetch_add(payload.len() as usize, Ordering::Relaxed);
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
            Ok(())
        }
        // Server→client opcodes never reach this function (see the module doc);
        // kept only for match exhaustiveness.
        Opcode::AuthResult
        | Opcode::SyncResponse
        | Opcode::NewCertHash
        | Opcode::AuthChallenge => Ok(()),
    }
}
