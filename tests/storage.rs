//! `MessageStore` public-API integration tests (moved from `src/tests.rs`,
//! Task 6).
//!
//! These use only the public API (`push`, `since`, `len`, `sweep`); the
//! timestamp-injection tests that need `push_with_timestamp` (`pub(crate)`)
//! live inline in `src/storage/mod.rs`.
//!
//! Includes the Bug 2 regression: concurrent pushes must allocate strictly
//! monotonic ids under the ordering lock so `since` never returns `[6,5]`.

use std::sync::Arc;

use impulse_server::protocol::{Opcode, PacketReader, encode_sync_response};
use impulse_server::storage::MessageStore;

#[test]
fn push_assigns_monotonic_ids() {
    let store = MessageStore::new();
    let a = store.push(vec![1]);
    let b = store.push(vec![2]);
    assert_eq!(b.id, a.id + 1);
    assert!(b.timestamp >= a.timestamp);
}

#[test]
fn since_returns_only_newer() {
    let store = MessageStore::new();
    for i in 0..5 {
        store.push(vec![i]);
    }
    let all = store.since(0, 100);
    assert_eq!(all.len(), 5);
    let some = store.since(2, 100);
    assert_eq!(some.len(), 3); // ids 3,4,5
}

#[test]
fn since_respects_limit() {
    let store = MessageStore::new();
    for _ in 0..10 {
        store.push(vec![0]);
    }
    assert_eq!(store.since(0, 3).len(), 3);
}

#[tokio::test]
async fn concurrent_storage_operations() {
    let store = Arc::new(MessageStore::new());
    let mut handles = Vec::new();

    for i in 0u32..100 {
        let store_clone = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            store_clone.push(vec![i as u8; 4]);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(store.len(), 100);

    // Verify monotonic IDs.
    let all = store.since(0, 200);
    assert_eq!(all.len(), 100);
    for i in 1..all.len() {
        assert!(
            all[i].id > all[i - 1].id,
            "IDs should be monotonically increasing: {} > {}",
            all[i].id,
            all[i - 1].id
        );
    }
}

#[tokio::test]
async fn concurrent_push_allocates_monotonic_ids_within_lock() {
    let store = Arc::new(MessageStore::new());
    let mut handles = Vec::new();

    for i in 0u32..100 {
        let s = store.clone();
        handles.push(tokio::spawn(async move { s.push(vec![i as u8; 4]) }));
    }
    for h in handles {
        h.await.unwrap();
    }

    let all = store.since(0, 200);
    for w in all.windows(2) {
        assert!(w[0].id < w[1].id, "ids must be strictly monotonic");
    }
}

#[tokio::test]
async fn multi_client_concurrent_send() {
    let store = Arc::new(MessageStore::new());
    let num_clients = 5;
    let mut handles = Vec::new();

    for i in 0..num_clients {
        let store_clone = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            let payload = format!("message from client {}", i);
            store_clone.push(payload.into_bytes());
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(store.len(), num_clients);

    // All messages visible with monotonic IDs.
    let all = store.since(0, 100);
    assert_eq!(all.len(), num_clients);
    for i in 1..all.len() {
        assert!(
            all[i].id > all[i - 1].id,
            "IDs must be monotonic: {} > {}",
            all[i].id,
            all[i - 1].id
        );
    }

    // Sync response contains all messages.
    let sync_resp = encode_sync_response(
        &all.iter()
            .map(|m| (m.id, m.timestamp, m.payload.clone()))
            .collect::<Vec<_>>(),
    );
    let mut sr = PacketReader::new(&sync_resp);
    assert_eq!(sr.read_opcode().unwrap(), Opcode::SyncResponse);
    let count = sr.read_u32().unwrap();
    assert_eq!(count, num_clients as u32);
}

#[test]
fn sync_after_reconnect() {
    let store = MessageStore::new();

    // Phase 1: client connects and receives 3 messages.
    let _msg1 = store.push(b"msg1".to_vec());
    let _msg2 = store.push(b"msg2".to_vec());
    let msg3 = store.push(b"msg3".to_vec());
    assert_eq!(store.len(), 3);

    let initial = store.since(0, 100);
    assert_eq!(initial.len(), 3);
    let last_seen_id = initial.last().unwrap().id;
    assert_eq!(last_seen_id, msg3.id);

    // Phase 2: client disconnects, 2 more messages arrive.
    let msg4 = store.push(b"msg4".to_vec());
    let msg5 = store.push(b"msg5".to_vec());
    assert_eq!(store.len(), 5);

    // Phase 3: client reconnects with last_seen_id, gets only new messages.
    let after_reconnect = store.since(last_seen_id, 100);
    assert_eq!(after_reconnect.len(), 2, "should only get 2 new messages");
    assert_eq!(after_reconnect[0].id, msg4.id);
    assert_eq!(after_reconnect[0].payload, b"msg4");
    assert_eq!(after_reconnect[1].id, msg5.id);
    assert_eq!(after_reconnect[1].payload, b"msg5");

    // Sync response encoding.
    let sync_resp = encode_sync_response(
        &after_reconnect
            .iter()
            .map(|m| (m.id, m.timestamp, m.payload.clone()))
            .collect::<Vec<_>>(),
    );
    let mut sr = PacketReader::new(&sync_resp);
    assert_eq!(sr.read_opcode().unwrap(), Opcode::SyncResponse);
    let count = sr.read_u32().unwrap();
    assert_eq!(count, 2);
    for expected_payload in &[b"msg4".as_slice(), b"msg5".as_slice()] {
        let _id = sr.read_u64().unwrap();
        let _ts = sr.read_u64().unwrap();
        let payload = sr.read_len_prefixed().unwrap();
        assert_eq!(&payload, expected_payload);
    }
}

#[test]
fn message_ordering_and_sync_limit() {
    let store = MessageStore::new();

    for i in 0..10 {
        store.push(format!("msg_{}", i).into_bytes());
    }

    // Full sync.
    let all = store.since(0, 100);
    assert_eq!(all.len(), 10);
    for (i, msg) in all.iter().enumerate() {
        assert_eq!(msg.payload, format!("msg_{}", i).as_bytes());
    }

    // Partial sync with limit.
    let partial = store.since(0, 3);
    assert_eq!(partial.len(), 3);
    assert_eq!(partial[0].payload, b"msg_0");
    assert_eq!(partial[2].payload, b"msg_2");

    // Sync from the middle.
    let mid_id = all[4].id;
    let from_mid = store.since(mid_id, 100);
    assert_eq!(from_mid.len(), 5);
    assert_eq!(from_mid[0].payload, b"msg_5");

    // Sync with a very small limit.
    let tiny = store.since(0, 1);
    assert_eq!(tiny.len(), 1);
}

#[tokio::test]
async fn storage_push_sync_interleave() {
    let store = Arc::new(MessageStore::new());

    // Push 50 messages from "client A".
    for i in 0..50 {
        store.push(format!("A_{}", i).into_bytes());
    }

    // "Client B" syncs, gets the first batch.
    let batch1 = store.since(0, 25);
    assert_eq!(batch1.len(), 25);
    let last_id = batch1.last().unwrap().id;

    // Push 25 more from "client A".
    for i in 50..75 {
        store.push(format!("A_{}", i).into_bytes());
    }

    // "Client B" syncs again with last_id.
    let batch2 = store.since(last_id, 25);
    assert_eq!(batch2.len(), 25);

    // Verify no overlap.
    let batch1_ids: Vec<u64> = batch1.iter().map(|m| m.id).collect();
    let batch2_ids: Vec<u64> = batch2.iter().map(|m| m.id).collect();
    for id in &batch2_ids {
        assert!(
            !batch1_ids.contains(id),
            "batch2 should not contain batch1 id {}",
            id
        );
    }

    // Total messages.
    assert_eq!(store.len(), 75);
}
