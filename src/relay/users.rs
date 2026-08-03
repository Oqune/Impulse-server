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

