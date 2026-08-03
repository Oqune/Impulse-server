//! Ephemeral, in-memory message storage.
//!
//! Messages are kept only in RAM (no persistence) and expire after a TTL of
//! 72 hours. Each message carries:
//!   * a monotonically increasing `u64` sequence id,
//!   * the opaque encrypted payload (produced end-to-end by the clients),
//!   * a creation timestamp.
//!
//! A bounded ring buffer (by count) plus a TTL sweep bounds memory usage.

use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

/// How long a message stays available for late joiners before being dropped.
pub const MESSAGE_TTL: Duration = Duration::from_secs(60 * 60 * 24 * 3); // 72 hours

/// Hard cap on the number of retained messages (ring-buffer behaviour).
pub const MAX_MESSAGES: usize = 10_000;

/// A single relayed message. The payload is already end-to-end encrypted by the
/// client; the server only stores and forwards it. No sender metadata is kept.
#[derive(Clone, Debug)]
pub struct StoredMessage {
    pub id: u64,
    /// Encrypted payload bytes (client-side encryption).
    pub payload: Vec<u8>,
    /// Unix millis at creation.
    pub timestamp: u64,
}

/// Lock helper that recovers from poisoned mutexes with a warning.
fn lock_order(mutex: &std::sync::Mutex<VecDeque<u64>>) -> std::sync::MutexGuard<'_, VecDeque<u64>> {
    mutex.lock().unwrap_or_else(|e| {
        warn!("order mutex poisoned, recovering: {}", e);
        e.into_inner()
    })
}

/// In-memory message log with TTL eviction and sequence-id ordering.
#[derive(Default)]
pub struct MessageStore {
    inner: DashMap<u64, StoredMessage>,
    next_id: AtomicU64,
    /// Ordered list of ids, used to implement the ring-buffer cap and TTL sweep.
    order: std::sync::Mutex<VecDeque<u64>>,
}

impl MessageStore {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
            next_id: AtomicU64::new(1),
            order: std::sync::Mutex::new(VecDeque::with_capacity(MAX_MESSAGES)),
        }
    }

    /// Append a message, returning the stored record (id + timestamp + payload).
    pub fn push(&self, payload: Vec<u8>) -> StoredMessage {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.push_with_timestamp(payload, timestamp)
    }

    /// Core insertion used by [`push`]; also lets tests inject a fixed timestamp.
    pub(crate) fn push_with_timestamp(&self, payload: Vec<u8>, timestamp: u64) -> StoredMessage {
        // Bug 2: allocate the id while holding the lock so the sequence observed
        // in `order` (and returned by `since`) is strictly monotonic even under
        // concurrent pushes. Previously `alloc_id` ran `fetch_add` outside the
        // lock, so thread A could take id 5 and thread B id 6, then B enqueue
        // before A → `since()` could return `[6,5]`.
        let mut order = lock_order(&self.order);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let msg = StoredMessage {
            id,
            payload,
            timestamp,
        };
        // `msg.clone()` (payload copy into the ring) is required to return the
        // owned record while storing the same one — the relay reads stored
        // records via `since()`, so the payload must live in the map.
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

    /// Return up to `limit` messages with `id > after_id`, used to synchronise a
    /// client that (re)connects and reports the last id it has seen. The cap
    /// (`limit`) prevents a single `Sync` from replaying the entire buffer and
    /// producing a multi-hundred-MB response (C3).
    pub fn since(&self, after_id: u64, limit: usize) -> Vec<StoredMessage> {
        let ids: Vec<u64> = {
            let order = lock_order(&self.order);
            order
                .iter()
                .copied()
                .filter(|id| *id > after_id)
                .take(limit)
                .collect()
        };
        ids.iter()
            .filter_map(|id| self.inner.get(id).map(|r| r.clone()))
            .collect()
    }
    /// Remove messages older than the TTL. Called periodically.
    pub fn sweep(&self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let ttl_ms = MESSAGE_TTL.as_millis() as u64;

        let mut to_remove: Vec<u64> = Vec::new();
        for entry in self.inner.iter() {
            if now.saturating_sub(entry.value().timestamp) > ttl_ms {
                to_remove.push(*entry.key());
            }
        }
        let removed = to_remove.len();
        for id in to_remove {
            self.inner.remove(&id);
        }
        if removed > 0 {
            let mut order = lock_order(&self.order);
            order.retain(|id| self.inner.contains_key(id));
        }
        removed
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    #[test]
    fn sweep_removes_expired() {
        let store = MessageStore::new();
        store.push(vec![1]);

        let expired_ts = now_ms() - (MESSAGE_TTL.as_millis() as u64) - 1000;
        store.push_with_timestamp(vec![2], expired_ts);
        assert_eq!(store.len(), 2);

        let removed = store.sweep();
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 1);

        // MESSAGE_TTL must stay 72 hours for the compatibility tests.
        assert_eq!(MESSAGE_TTL, Duration::from_secs(60 * 60 * 24 * 3));
    }

    #[test]
    fn storage_ttl_boundary() {
        let store = MessageStore::new();
        let ttl_ms = MESSAGE_TTL.as_millis() as u64;
        let now = now_ms();

        // Exactly at the TTL minus one second: still alive.
        store.push_with_timestamp(b"alive".to_vec(), now - (ttl_ms - 1000));
        // One second past the TTL: dead.
        store.push_with_timestamp(b"dead".to_vec(), now - (ttl_ms + 1000));
        // Fresh.
        store.push_with_timestamp(b"fresh".to_vec(), now - 1000);
        assert_eq!(store.len(), 3);

        let removed = store.sweep();
        assert_eq!(removed, 1, "only the expired message should be removed");
        assert_eq!(store.len(), 2, "two messages should remain");

        let remaining = store.since(0, 10);
        let payloads: Vec<&[u8]> = remaining.iter().map(|m| m.payload.as_slice()).collect();
        assert!(
            payloads.contains(&b"alive".as_slice()),
            "alive should remain, got: {payloads:?}"
        );
        assert!(
            payloads.contains(&b"fresh".as_slice()),
            "fresh should remain, got: {payloads:?}"
        );
        assert!(
            !payloads.contains(&b"dead".as_slice()),
            "dead should have been swept, got: {payloads:?}"
        );
    }
}
