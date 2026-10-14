//! MULTI-CLIENT STORAGE-LEVEL TESTS — deterministic checks for auth helper
//! behavior, opaque payload retention, and monotonic storage ids.
//!
//! These do not exercise server-side routing, recipient isolation, concurrent
//! WebTransport sessions, or delivery. See `ui::live_tests` for the smaller
//! production-path loopback relay smoke test.

mod common;

use std::collections::HashSet;

use impulse_server::crypto::argon2_hash;
use impulse_server::protocol::{Opcode, PacketReader, PacketWriter, encode_sync_response};
use impulse_server::storage::MessageStore;

/// Build a per-recipient data blob (client→server wire format):
/// [u32 sender_pub_hash_len][sender_pub_hash][u32 count]
///   [u32 recipient_id_len][recipient_id][u32 enc_key_len][enc_key]
///   [u32 ct_len][ciphertext] ...repeated
fn build_per_recipient_blob(
    sender: &[u8],
    recipients: &[(&[u8], &[u8], &[u8])],
) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&(sender.len() as u32).to_le_bytes());
    blob.extend_from_slice(sender);
    blob.extend_from_slice(&(recipients.len() as u32).to_le_bytes());
    for (id, enc_key, ct) in recipients {
        blob.extend_from_slice(&(id.len() as u32).to_le_bytes());
        blob.extend_from_slice(id);
        blob.extend_from_slice(&(enc_key.len() as u32).to_le_bytes());
        blob.extend_from_slice(enc_key);
        blob.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        blob.extend_from_slice(ct);
    }
    let mut w = PacketWriter::with_opcode(Opcode::Data);
    w.write_len_prefixed(&blob);
    w.into_bytes()
}

/// Exercise auth helper calculations and independent opaque storage entries.
/// This does not test whether recipients receive only their addressed frames;
/// the server deliberately does not parse recipient metadata in ciphertext.
#[test]
fn many_client_auth_and_opaque_payload_storage() {
    const N: usize = 8;
    let password = "stress_password";
    let stored_hash = argon2_hash(password).unwrap();

    // Each client authenticates (parallel simulation via collected auth frames).
    let mut auth_frames = Vec::with_capacity(N);
    let mut auth_nonces: Vec<Vec<u8>> = Vec::with_capacity(N);
    for i in 0..N {
        let n: Vec<u8> = vec![0x20 + i as u8; 16];
        auth_nonces.push(n.clone());
        auth_frames.push(common::build_client_auth(password, &n, &stored_hash));
    }
    // All must verify successfully (each with its own single-use nonce, C4).
    for (f, n) in auth_frames.iter().zip(auth_nonces.iter()) {
        let (h, nn) = common::server_verify_auth(f, &stored_hash, n).unwrap();
        assert!(h && nn, "every client must authenticate");
    }

    // Unique recipient ids (simulating distinct KEM fingerprints).
    let recipients: Vec<Vec<u8>> = (0..N).map(|i| format!("user-{i:02}").into_bytes()).collect();

    let store = MessageStore::new();
    // Model distinct client-generated opaque payloads. Storage does not parse
    // recipient IDs and this test makes no routing or confidentiality claim.
    for i in 1..N {
        let ct = format!("secret-from-0-to-{i}").into_bytes();
        let blob = build_per_recipient_blob(
            &recipients[0],
            &[(&recipients[i], b"enckey", &ct)],
        );
        assert!(blob.windows(ct.len()).any(|window| window == ct));
        store.push(blob);
    }

    // The storage layer retains N-1 distinct opaque payloads. This says nothing
    // about what any live recipient receives.
    let all = store.since(0, 10_000);
    assert_eq!(all.len(), N - 1, "exactly N-1 opaque payloads stored");

    // Every modeled payload is non-empty and distinct in storage.
    let mut seen = HashSet::new();
    for m in &all {
        assert!(!m.payload.is_empty());
        assert!(seen.insert(m.payload.clone()), "duplicate opaque payload stored");
    }
}

/// Verify monotonic, collision-free message ids under heavy interleaved pushes
/// from many "clients" (simulates concurrent senders).
#[test]
fn many_clients_monotonic_ids_no_collision() {
    let store = MessageStore::new();
    let total: usize = 200;
    let mut ids = Vec::with_capacity(total);
    for i in 0..total {
        let m = store.push(format!("m-{i}").into_bytes());
        ids.push(m.id);
    }
    // Ids strictly increasing + unique.
    for w in ids.windows(2) {
        assert!(w[1] > w[0], "message ids must be strictly monotonic");
    }
    let unique: usize = ids.iter().collect::<std::collections::HashSet<_>>().len();
    assert_eq!(unique, total, "no id collisions across many senders");
}

/// Verify a sync response encodes exactly the requested window and a client
/// can parse it back — the round-trip used when many clients poll concurrently.
#[test]
fn many_clients_sync_roundtrip() {
    let store = MessageStore::new();
    for i in 0..20 {
        store.push(format!("bulk-{i}").into_bytes());
    }
    let window = store.since(0, 100);
    let resp = encode_sync_response(
        &window.iter().map(|m| (m.id, m.timestamp, m.payload.clone())).collect::<Vec<_>>(),
    );
    let mut r = PacketReader::new(&resp);
    assert_eq!(r.read_opcode().unwrap(), Opcode::SyncResponse);
    let count = r.read_u32().unwrap();
    assert_eq!(count as usize, window.len());
    for _ in 0..count {
        let _id = r.read_u64().unwrap();
        let _ts = r.read_u64().unwrap();
        let _payload = r.read_len_prefixed().unwrap();
    }
    // After a client consumes up to id K, a subsequent sync from K must be empty.
    let last_id = window.last().unwrap().id;
    let after = store.since(last_id, 100);
    assert!(after.is_empty(), "sync is resumable and does not re-deliver");
}
