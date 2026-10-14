//! Ephemeral, in-memory message storage.
//!
//! Messages are kept only in RAM (no persistence) and expire after a TTL of
//! 72 hours. Each record carries a monotonically increasing `u64` sequence id,
//! the opaque client payload, and a server timestamp. The payload may include
//! client-defined routing identifiers; the relay does not parse it as metadata.
//!
//! Count and payload-byte caps plus a TTL sweep bound retained storage.

use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

/// How long a message stays available for late joiners before being dropped.
/// Unified across client and server to 72 hours (3 days) with 4-day overlap.
pub const MESSAGE_TTL: Duration = Duration::from_secs(60 * 60 * 72); // 72 hours

/// Hard cap on the number of retained messages (ring-buffer behaviour).
pub const MAX_MESSAGES: usize = 10_000;

/// Maximum total opaque payload bytes retained for reconnect synchronization.
pub const MAX_STORE_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// A single relayed message. The server stores/forwards the payload opaquely and
/// keeps no separately parsed sender metadata; client payloads can contain
/// application-defined routing identifiers visible to the relay.
#[derive(Clone, Debug)]
pub struct StoredMessage {
    pub id: u64,
    /// Opaque client-defined payload bytes.
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
    /// Ordered list of ids, used for count/byte eviction and TTL sweep.
    order: std::sync::Mutex<VecDeque<u64>>,
    /// Sum of retained payload sizes. Mutations happen while `order` is locked.
    retained_bytes: std::sync::atomic::AtomicUsize,
}

impl MessageStore {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
            next_id: AtomicU64::new(1),
            order: std::sync::Mutex::new(VecDeque::with_capacity(MAX_MESSAGES)),
            retained_bytes: std::sync::atomic::AtomicUsize::new(0),
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
        let mut retained = self.retained_bytes.load(Ordering::Relaxed) + msg.payload.len();
        while order.len() > MAX_MESSAGES || retained > MAX_STORE_BYTES {
            if let Some(oldest) = order.front().copied() {
                order.pop_front();
                if let Some((_, removed)) = self.inner.remove(&oldest) {
                    retained = retained.saturating_sub(removed.payload.len());
                }
            } else {
                break;
            }
        }
        self.retained_bytes.store(retained, Ordering::Relaxed);
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

    /// Snapshot a bounded page through `through_id`, accounting for the full
    /// encoded-record overhead. The caller can advance from the last returned
    /// id without allocating or encoding an unbounded backlog at once.
    pub fn since_bounded(
        &self,
        after_id: u64,
        through_id: u64,
        max_count: usize,
        max_encoded_bytes: usize,
    ) -> Vec<StoredMessage> {
        const RESPONSE_HEADER_BYTES: usize = 5; // opcode + u32 count
        const RECORD_HEADER_BYTES: usize = 20; // id + timestamp + u32 payload length

        if max_count == 0 || max_encoded_bytes < RESPONSE_HEADER_BYTES {
            return Vec::new();
        }
        let mut selected = Vec::new();
        let mut encoded_bytes = RESPONSE_HEADER_BYTES;
        let order = lock_order(&self.order);
        for id in order.iter().copied().filter(|id| *id > after_id && *id <= through_id) {
            let Some(message) = self.inner.get(&id) else { continue };
            let record_bytes = RECORD_HEADER_BYTES.saturating_add(message.payload.len());
            if selected.len() >= max_count
                || encoded_bytes.saturating_add(record_bytes) > max_encoded_bytes
            {
                break;
            }
            encoded_bytes += record_bytes;
            selected.push(message.clone());
        }
        selected
    }

    /// Highest sequence id allocated so far, used to make Sync finite even
    /// while new messages arrive concurrently.
    pub fn latest_id(&self) -> u64 {
        self.next_id.load(Ordering::Relaxed).saturating_sub(1)
    }

    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes.load(Ordering::Relaxed)
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
        let mut order = lock_order(&self.order);
        let mut removed = 0;
        let mut removed_bytes = 0usize;
        for id in to_remove {
            if let Some((_, message)) = self.inner.remove(&id) {
                removed += 1;
                removed_bytes = removed_bytes.saturating_add(message.payload.len());
            }
        }
        if removed > 0 {
            order.retain(|id| self.inner.contains_key(id));
            self.retained_bytes.fetch_sub(removed_bytes, Ordering::Relaxed);
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

        // MESSAGE_TTL must stay 72 hours (3 days) unified across client and server.
        assert_eq!(MESSAGE_TTL, Duration::from_secs(60 * 60 * 72));
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
        assert_eq!(store.retained_bytes(), b"alive".len() + b"fresh".len());

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

    #[test]
    fn store_byte_budget_evicts_oldest_and_tracks_exact_retained_bytes() {
        let store = MessageStore::new();
        let payload = vec![7; 1024 * 1024];
        for _ in 0..=MAX_STORE_BYTES / payload.len() {
            store.push(payload.clone());
        }
        assert_eq!(store.retained_bytes(), MAX_STORE_BYTES);
        assert_eq!(store.len(), MAX_STORE_BYTES / payload.len());
        assert_eq!(store.since(0, 1)[0].id, 2, "oldest record is evicted first");
    }

    #[test]
    fn store_count_budget_remains_ten_thousand() {
        let store = MessageStore::new();
        for _ in 0..=MAX_MESSAGES {
            store.push(vec![1]);
        }
        assert_eq!(store.len(), MAX_MESSAGES);
        assert_eq!(store.since(0, 1)[0].id, 2);
        assert_eq!(store.retained_bytes(), MAX_MESSAGES);
    }

    #[test]
    fn bounded_sync_pages_obey_count_bytes_and_high_water_mark() {
        let store = MessageStore::new();
        for n in 0..10u8 {
            store.push(vec![n; 32]);
        }
        let high_water = store.latest_id();
        store.push(vec![99; 32]);

        let page = store.since_bounded(0, high_water, 3, 5 + 2 * (20 + 32));
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].id, 1);
        assert_eq!(page[1].id, 2);
        assert!(page.last().unwrap().id < store.latest_id());
        assert!(store.since_bounded(2, high_water, 3, 5 + 20).is_empty());

        let mut cursor = 0;
        let mut ids = Vec::new();
        loop {
            let page = store.since_bounded(cursor, high_water, 3, 5 + 2 * (20 + 32));
            if page.is_empty() {
                break;
            }
            cursor = page.last().unwrap().id;
            ids.extend(page.into_iter().map(|message| message.id));
        }
        assert_eq!(ids, (1..=10).collect::<Vec<_>>());
    }
}
