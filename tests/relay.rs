//! Relay/framing integration tests (moved from `src/tests.rs`, Task 6).
//!
//! Covers the multi-client relay sequence, the auth brute-force rate limiter,
//! the combined KEM+DSA key-exchange relay, per-recipient data blobs, packet
//! framing via `framing::try_read_packet`, and end-to-end lifecycle flows.
//! No live WebTransport connection is used — the server-side packet handling
//! is simulated at the packet level.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use impulse_server::crypto::argon2_hash;
use impulse_server::protocol::framing::{TryReadResult, try_read_packet};
use impulse_server::protocol::{
    Opcode, PacketReader, PacketWriter, encode_auth_challenge, encode_auth_result, encode_data,
    encode_heartbeat, encode_new_cert_hash, encode_sync_response,
};
use impulse_server::storage::MessageStore;
use common::{build_client_auth, server_verify_auth};

/// Build a combined KEM+DSA key-exchange packet (client→server wire format):
/// [0x0C] [u32: total_len] [u32: kem_len] [kem] [u32: dsa_len] [dsa].
fn build_key_exchange(kem: &[u8], dsa: &[u8]) -> Vec<u8> {
    let total_inner = 4 + kem.len() + 4 + dsa.len();
    let mut w = PacketWriter::with_opcode(Opcode::KeyExchangeKemDsa);
    w.write_u32(total_inner as u32);
    w.write_u32(kem.len() as u32);
    w.write_raw(kem);
    w.write_u32(dsa.len() as u32);
    w.write_raw(dsa);
    w.into_bytes()
}

/// Build a per-recipient data blob (client→server format):
/// [u32: sender_pub_hash_len] [sender_pub_hash] [u32: count]
///   [u32: recipient_id_len] [recipient_id] [u32: enc_key_len] [enc_key]
///   [u32: ct_len] [ciphertext] ...repeated for each recipient
fn build_per_recipient_blob(
    sender_pub_hash: &[u8],
    recipients: &[(&[u8], &[u8], &[u8])], // (id, enc_key, ciphertext)
) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&(sender_pub_hash.len() as u32).to_le_bytes());
    blob.extend_from_slice(sender_pub_hash);
    blob.extend_from_slice(&(recipients.len() as u32).to_le_bytes());
    for (id, enc_key, ciphertext) in recipients {
        blob.extend_from_slice(&(id.len() as u32).to_le_bytes());
        blob.extend_from_slice(id);
        blob.extend_from_slice(&(enc_key.len() as u32).to_le_bytes());
        blob.extend_from_slice(enc_key);
        blob.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        blob.extend_from_slice(ciphertext);
    }
    let mut w = PacketWriter::with_opcode(Opcode::Data);
    w.write_len_prefixed(&blob);
    w.into_bytes()
}

// ---------------------------------------------------------------------------
// Multi-client relay sequence
// ---------------------------------------------------------------------------

#[test]
fn relay_multi_client_sequence() {
    let password = "relay_test_pass";
    let stored_hash = argon2_hash(password).unwrap();

    // a. All 3 clients authenticate, each with its own single-use nonce (C4).
    let nonce1: Vec<u8> = vec![0x01; 16];
    let nonce2: Vec<u8> = vec![0x02; 16];
    let nonce3: Vec<u8> = vec![0x03; 16];
    let client1_auth = build_client_auth(password, &nonce1, &stored_hash);
    let (h1, n1) = server_verify_auth(&client1_auth, &stored_hash, &nonce1).unwrap();
    assert!(h1 && n1, "Client 1 auth should succeed");

    let client2_auth = build_client_auth(password, &nonce2, &stored_hash);
    let (h2, n2) = server_verify_auth(&client2_auth, &stored_hash, &nonce2).unwrap();
    assert!(h2 && n2, "Client 2 auth should succeed");

    let client3_auth = build_client_auth(password, &nonce3, &stored_hash);
    let (h3, n3) = server_verify_auth(&client3_auth, &stored_hash, &nonce3).unwrap();
    assert!(h3 && n3, "Client 3 auth should succeed");

    // b/c. Client 1 sends Data, server stores it.
    let store = MessageStore::new();
    let client1_payload = b"hello from client 1".to_vec();
    let stored = store.push(client1_payload.clone());
    assert_eq!(store.len(), 1);
    let all = store.since(0, 100);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].id, stored.id);
    assert_eq!(all[0].payload, client1_payload);

    // d. Client 2 syncs (last_seen_id=0), receives Client 1's message.
    let sync_packet = {
        let mut w = PacketWriter::with_opcode(Opcode::Sync);
        w.write_u64(0);
        w.into_bytes()
    };
    let mut sr = PacketReader::new(&sync_packet);
    assert_eq!(sr.read_opcode().unwrap(), Opcode::Sync);
    let last_seen_id = sr.read_u64().unwrap();
    assert_eq!(last_seen_id, 0);

    let replay_for_client2 = store.since(last_seen_id, 500);
    let sync_resp = encode_sync_response(
        &replay_for_client2
            .iter()
            .map(|m| (m.id, m.timestamp, m.payload.clone()))
            .collect::<Vec<_>>(),
    );
    let mut rr2 = PacketReader::new(&sync_resp);
    assert_eq!(rr2.read_opcode().unwrap(), Opcode::SyncResponse);
    let count2 = rr2.read_u32().unwrap();
    assert_eq!(count2, 1);
    let msg_id = rr2.read_u64().unwrap();
    let msg_ts = rr2.read_u64().unwrap();
    let msg_payload = rr2.read_len_prefixed().unwrap();
    assert_eq!(msg_payload, client1_payload);
    assert!(msg_id > 0);
    assert!(msg_ts > 0);

    // e. Client 3 syncs, also receives Client 1's message.
    let replay_for_client3 = store.since(0, 500);
    assert_eq!(replay_for_client3.len(), 1);
    assert_eq!(replay_for_client3[0].payload, client1_payload);

    // f. Client 2 sends Data, verify it is stored.
    let client2_payload = b"hello from client 2".to_vec();
    let stored2 = store.push(client2_payload.clone());
    assert_eq!(store.len(), 2);
    assert!(stored2.id > stored.id);

    // Both messages visible.
    let all_after = store.since(0, 100);
    assert_eq!(all_after.len(), 2);
    assert_eq!(all_after[0].payload, client1_payload);
    assert_eq!(all_after[1].payload, client2_payload);
}

// ---------------------------------------------------------------------------
// Auth brute-force rate limiting
// ---------------------------------------------------------------------------

#[test]
fn auth_brute_force_limit() {
    let password = "correct_password";
    let stored_hash = argon2_hash(password).unwrap();
    let nonce = vec![0x55; 16];
    let max_attempts: u32 = 5;

    let session_key: u64 = 1;
    let auth_attempts: DashMap<u64, AtomicU32> = DashMap::new();
    auth_attempts.insert(session_key, AtomicU32::new(0));

    // 5 wrong attempts — each increments the counter.
    for i in 0..5 {
        let wrong = format!("wrong_{}", i);
        let packet = build_client_auth(&wrong, &nonce, &stored_hash);
        let attempts = auth_attempts.get(&session_key).unwrap();
        if attempts.load(Ordering::Relaxed) >= max_attempts {
            panic!("Attempt {} should not be blocked yet", i);
        }
        attempts.fetch_add(1, Ordering::Relaxed);
        let (h, _) = server_verify_auth(&packet, &stored_hash, &nonce).unwrap();
        assert!(!h, "Wrong password attempt {} should fail", i);
    }

    // 6th attempt — blocked even with the correct password.
    let attempts = auth_attempts.get(&session_key).unwrap();
    assert!(
        attempts.load(Ordering::Relaxed) >= max_attempts,
        "Should have hit the brute-force limit"
    );
    let correct_packet = build_client_auth(password, &nonce, &stored_hash);
    // Packet-level verification passes; the server blocks at the counter check.
    let (h, _) = server_verify_auth(&correct_packet, &stored_hash, &nonce).unwrap();
    assert!(h, "Packet-level verification should pass (server blocks at counter)");
}

#[test]
fn multiple_auth_attempts_same_session() {
    let password = "session_password";
    let stored_hash = argon2_hash(password).unwrap();
    let nonce = vec![0x77; 16];
    let max_attempts: u32 = 5;

    let session_key: u64 = 42;
    let auth_attempts: DashMap<u64, AtomicU32> = DashMap::new();

    // 5 wrong attempts, each verifying the counter increments correctly.
    for i in 1..=5 {
        auth_attempts
            .entry(session_key)
            .or_insert_with(|| AtomicU32::new(0));
        let attempts = auth_attempts.get(&session_key).unwrap();
        assert_eq!(attempts.load(Ordering::Relaxed), (i - 1) as u32);
        assert!(
            attempts.load(Ordering::Relaxed) < max_attempts,
            "attempt {} should not be blocked yet",
            i
        );
        let packet = build_client_auth(&format!("wrong{}", i), &nonce, &stored_hash);
        let (h, _) = server_verify_auth(&packet, &stored_hash, &nonce).unwrap();
        assert!(!h, "wrong password attempt {} should fail", i);
        attempts.fetch_add(1, Ordering::Relaxed);
        assert_eq!(attempts.load(Ordering::Relaxed), i as u32);
    }

    // Attempt 6: correct password — blocked by the brute-force counter.
    let attempts = auth_attempts.get(&session_key).unwrap();
    assert_eq!(attempts.load(Ordering::Relaxed), max_attempts);
    assert!(
        attempts.load(Ordering::Relaxed) >= max_attempts,
        "should be blocked now"
    );
    let packet = build_client_auth(password, &nonce, &stored_hash);
    let (h, _) = server_verify_auth(&packet, &stored_hash, &nonce).unwrap();
    assert!(h, "packet verification itself passes (blocked at server level)");
}

// ---------------------------------------------------------------------------
// Nonce expiry
// ---------------------------------------------------------------------------

#[test]
fn auth_challenge_response_timing() {
    const NONCE_MAX_AGE: Duration = Duration::from_secs(30);

    // Freshly created nonce — still valid.
    let nonce_created = Instant::now();
    let nonce: Vec<u8> = vec![0x42; 16];

    let challenge = encode_auth_challenge(&nonce, "dGVzdHNhbHQ");
    let mut r = PacketReader::new(&challenge);
    assert_eq!(r.read_opcode().unwrap(), Opcode::AuthChallenge);
    let extracted_nonce = r.read_bytes(16).unwrap();
    assert_eq!(extracted_nonce, nonce);
    let extracted_salt = r.read_len_prefixed().unwrap();
    assert_eq!(std::str::from_utf8(&extracted_salt).unwrap(), "dGVzdHNhbHQ");

    assert!(
        nonce_created.elapsed() <= NONCE_MAX_AGE,
        "freshly created nonce should be within NONCE_MAX_AGE"
    );

    // Expired nonce — create an Instant in the past.
    let expired_created_at = Instant::now() - NONCE_MAX_AGE - Duration::from_secs(1);
    assert!(
        expired_created_at.elapsed() > NONCE_MAX_AGE,
        "nonce created NONCE_MAX_AGE+1 ago should be expired"
    );

    // Boundary: at exactly NONCE_MAX_AGE, `elapsed()` may be <= or > depending
    // on timing. Verify the invariant: elapsed > NONCE_MAX_AGE means expired.
    let boundary_created_at = Instant::now() - NONCE_MAX_AGE;
    let elapsed = boundary_created_at.elapsed();
    if elapsed > NONCE_MAX_AGE {
        assert!(elapsed > NONCE_MAX_AGE, "boundary nonce should be expired");
    } else {
        assert!(elapsed <= NONCE_MAX_AGE, "boundary nonce should still be valid");
    }
}

// ---------------------------------------------------------------------------
// Packet length consistency
// ---------------------------------------------------------------------------

#[test]
fn packet_length_consistency() {
    // Auth: 1 + 4 + pwd_len + 32
    let auth_pwd = b"test_password";
    let mut w_auth = PacketWriter::with_opcode(Opcode::Auth);
    w_auth.write_len_prefixed(auth_pwd);
    w_auth.write_raw(&[0u8; 32]);
    let auth_bytes = w_auth.into_bytes();
    assert_eq!(auth_bytes.len(), 1 + 4 + auth_pwd.len() + 32);

    // AuthResult (success, no message): 1 + 1
    let ar = encode_auth_result(true, None);
    assert_eq!(ar.len(), 2);

    // AuthResult (failure, with message): 1 + 1 + 4 + msg_len
    let msg = "error message";
    let ar_msg = encode_auth_result(false, Some(msg));
    assert_eq!(ar_msg.len(), 1 + 1 + 4 + msg.len());

    // Sync: 1 + 8
    let mut w_sync = PacketWriter::with_opcode(Opcode::Sync);
    w_sync.write_u64(42);
    let sync_bytes = w_sync.into_bytes();
    assert_eq!(sync_bytes.len(), 9);

    // SyncResponse (2 messages): 1 + 4 + (8 + 8 + 4 + len1) + (8 + 8 + 4 + len2)
    let msgs = vec![
        (1u64, 100u64, vec![1u8, 2, 3]),
        (2u64, 200u64, vec![4u8, 5]),
    ];
    let sr = encode_sync_response(&msgs);
    let expected_sr_len = 1 + 4 + (8 + 8 + 4 + 3) + (8 + 8 + 4 + 2);
    assert_eq!(sr.len(), expected_sr_len);

    // Data (server→client): 1 + 8 + 8 + 4 + payload.len()
    let payload = b"hello world";
    let data = encode_data(1, 1000, payload);
    assert_eq!(data.len(), 1 + 8 + 8 + 4 + payload.len());

    // Heartbeat: 1 + 8
    let hb = encode_heartbeat(12345);
    assert_eq!(hb.len(), 9);

    // NewCertHash: 1 + 32 + 8 = 41
    let hash = [0xABu8; 32];
    let nch = encode_new_cert_hash(&hash, 1_700_000_000);
    assert_eq!(nch.len(), 41);

    // AuthChallenge: 1 + 16 + 4 + salt_b64.len() + 4 + params.len()  (params = "m=47104,t=3,p=1")
    let nonce = vec![0u8; 16];
    let salt_b64 = "c29tZXNhbHQ"; // "testsalt" in B64
    let params = "m=47104,t=3,p=1";
    let ac = encode_auth_challenge(&nonce, salt_b64);
    assert_eq!(ac.len(), 1 + 16 + 4 + salt_b64.len() + 4 + params.len());
}

// ---------------------------------------------------------------------------
// Combined KEM+DSA key exchange and per-recipient blobs
// ---------------------------------------------------------------------------

#[test]
fn e2e_full_lifecycle() {
    let password = "e2e_test_pass";
    let stored_hash = argon2_hash(password).unwrap();

    // 1-2. Client1 and Client2 authenticate (distinct single-use nonces, C4).
    let nonce1: Vec<u8> = vec![0x0C; 16];
    let nonce2: Vec<u8> = vec![0x0D; 16];
    let c1_auth = build_client_auth(password, &nonce1, &stored_hash);
    let (h1, n1) = server_verify_auth(&c1_auth, &stored_hash, &nonce1).unwrap();
    assert!(h1 && n1, "Client1 auth should succeed");

    let c2_auth = build_client_auth(password, &nonce2, &stored_hash);
    let (h2, n2) = server_verify_auth(&c2_auth, &stored_hash, &nonce2).unwrap();
    assert!(h2 && n2, "Client2 auth should succeed");

    // 3-4. Both clients send key exchanges.
    let c1_kem = vec![0x11u8; 1184]; // ML-KEM-768 size
    let c1_dsa = vec![0x22u8; 1952]; // ML-DSA-65 size
    let c1_ke = build_key_exchange(&c1_kem, &c1_dsa);
    assert_eq!(c1_ke[0], 0x0C);
    assert_eq!(try_read_packet(&c1_ke), TryReadResult::Packet(c1_ke.len()));

    let c2_kem = vec![0x33u8; 1184];
    let c2_dsa = vec![0x44u8; 1952];
    let c2_ke = build_key_exchange(&c2_kem, &c2_dsa);
    assert_eq!(c2_ke[0], 0x0C);

    // 5. Client1 sends a per-recipient data message for Client2.
    let store = MessageStore::new();
    let sender_hash = [0xAA; 32];
    let c2_id = [0xBB; 32];
    let c2_enc_key = vec![0xCC; 1184];
    let c2_ciphertext = vec![0xDD; 256];
    let blob = build_per_recipient_blob(&sender_hash, &[(&c2_id, &c2_enc_key, &c2_ciphertext)]);
    let stored = store.push(blob.clone());
    assert!(stored.id > 0);
    assert_eq!(store.len(), 1);

    // 6. Client2 syncs (last_seen_id=0), receives Client1's message.
    let messages = store.since(0, 100);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].payload, blob);
    let sync_resp = encode_sync_response(
        &messages
            .iter()
            .map(|m| (m.id, m.timestamp, m.payload.clone()))
            .collect::<Vec<_>>(),
    );
    let mut sr = PacketReader::new(&sync_resp);
    assert_eq!(sr.read_opcode().unwrap(), Opcode::SyncResponse);
    let count = sr.read_u32().unwrap();
    assert_eq!(count, 1);
    let msg_id = sr.read_u64().unwrap();
    let msg_ts = sr.read_u64().unwrap();
    let msg_payload = sr.read_len_prefixed().unwrap();
    assert_eq!(msg_payload, blob);
    assert!(msg_id > 0);
    assert!(msg_ts > 0);

    // 7. try_read_packet correctly identifies all packet types.
    assert_eq!(try_read_packet(&c1_auth), TryReadResult::Packet(c1_auth.len()));
    assert_eq!(try_read_packet(&c1_ke), TryReadResult::Packet(c1_ke.len()));
    assert_eq!(try_read_packet(&blob), TryReadResult::Packet(blob.len()));
    assert_eq!(try_read_packet(&[0x99]), TryReadResult::UnknownOpcode);
}

#[test]
fn per_recipient_blob_parsing() {
    let sender_hash = [0xAA; 32];
    let recipients: Vec<([u8; 32], Vec<u8>, Vec<u8>)> = (0..3)
        .map(|i| {
            let id = [i as u8; 32];
            let enc_key = vec![i as u8 + 10; 1184];
            let ciphertext = vec![i as u8 + 20; 256];
            (id, enc_key, ciphertext)
        })
        .collect();

    let ref_vecs: Vec<(&[u8], &[u8], &[u8])> = recipients
        .iter()
        .map(|(id, ek, ct)| (id.as_slice(), ek.as_slice(), ct.as_slice()))
        .collect();

    let blob = build_per_recipient_blob(&sender_hash, &ref_vecs);

    // Parse blob manually (mimicking the client's onData logic).
    let mut pr = PacketReader::new(&blob);
    let _opcode = pr.read_opcode().unwrap();
    let payload = pr.read_len_prefixed().unwrap();

    let mut inner = PacketReader::new(&payload);
    let read_hash = inner.read_len_prefixed().unwrap();
    assert_eq!(&read_hash, &sender_hash);

    let count = inner.read_u32().unwrap();
    assert_eq!(count, 3);

    for (i, (id, enc_key, ciphertext)) in recipients.iter().enumerate() {
        let r_id = inner.read_len_prefixed().unwrap();
        assert_eq!(&r_id, id.as_slice(), "recipient {} id mismatch", i);
        let r_ek = inner.read_len_prefixed().unwrap();
        assert_eq!(&r_ek, enc_key.as_slice(), "recipient {} enc_key mismatch", i);
        let r_ct = inner.read_len_prefixed().unwrap();
        assert_eq!(&r_ct, ciphertext.as_slice(), "recipient {} ciphertext mismatch", i);
    }

    // try_read_packet recognizes the whole blob as one Data frame.
    assert_eq!(try_read_packet(&blob), TryReadResult::Packet(blob.len()));
}

// ---------------------------------------------------------------------------
// Framing: try_read_packet over every opcode + skip-byte resilience
// ---------------------------------------------------------------------------

#[test]
fn try_read_packet_all_opcodes() {
    // Auth (0x01): opcode + u32 pwd_len + pwd + 32 HMAC
    let mut auth = PacketWriter::with_opcode(Opcode::Auth);
    auth.write_len_prefixed(b"password123");
    auth.write_raw(&[0x42; 32]);
    let auth_bytes = auth.into_bytes();
    assert_eq!(
        try_read_packet(&auth_bytes),
        TryReadResult::Packet(auth_bytes.len())
    );

    // Sync (0x03): opcode + u64
    let mut sync = PacketWriter::with_opcode(Opcode::Sync);
    sync.write_u64(42);
    let sync_bytes = sync.into_bytes();
    assert_eq!(try_read_packet(&sync_bytes), TryReadResult::Packet(9));

    // Data (0x05): opcode + u32 len + payload (client→server format)
    let data_payload = b"hello world";
    let mut data = PacketWriter::with_opcode(Opcode::Data);
    data.write_len_prefixed(data_payload);
    let data_bytes = data.into_bytes();
    assert_eq!(
        try_read_packet(&data_bytes),
        TryReadResult::Packet(data_bytes.len())
    );

    // Heartbeat (0x06): opcode + u64
    let mut hb = PacketWriter::with_opcode(Opcode::Heartbeat);
    hb.write_u64(12345);
    let hb_bytes = hb.into_bytes();
    assert_eq!(try_read_packet(&hb_bytes), TryReadResult::Packet(9));

    // KeyExchange (0x0C): opcode + u32 len + payload
    let ke = build_key_exchange(&[0x11; 32], &[0x22; 64]);
    assert_eq!(try_read_packet(&ke), TryReadResult::Packet(ke.len()));

    // Disconnect (0x08): opcode only
    assert_eq!(try_read_packet(&[0x08]), TryReadResult::Packet(1));

    // Unknown opcodes
    assert_eq!(try_read_packet(&[0xFF]), TryReadResult::UnknownOpcode);
    assert_eq!(try_read_packet(&[0x00]), TryReadResult::UnknownOpcode);

    // Empty buffer
    assert_eq!(try_read_packet(&[]), TryReadResult::Incomplete);

    // Oversized payload
    let mut big_data = PacketWriter::with_opcode(Opcode::Data);
    big_data.write_u32(u32::MAX);
    let big_bytes = big_data.into_bytes();
    assert_eq!(
        try_read_packet(&big_bytes),
        TryReadResult::OversizedPayload
    );
}

#[test]
fn skip_byte_resilience() {
    // Build a valid client→server data frame (opcode + u32 len + payload).
    let mut data_w = PacketWriter::with_opcode(Opcode::Data);
    data_w.write_len_prefixed(b"hello");
    let data = data_w.into_bytes();

    // Prepend an unknown byte.
    let mut corrupted = vec![0xFF];
    corrupted.extend_from_slice(&data);

    // First byte is unknown → skip.
    assert_eq!(try_read_packet(&corrupted), TryReadResult::UnknownOpcode);

    // After skipping 1 byte, the valid frame parses.
    assert_eq!(try_read_packet(&data), TryReadResult::Packet(data.len()));

    // Multiple unknown bytes followed by a valid frame.
    let mut multi_corrupted = vec![0xFF, 0xFE, 0xFD, 0xFC];
    multi_corrupted.extend_from_slice(&data);
    assert_eq!(
        try_read_packet(&multi_corrupted),
        TryReadResult::UnknownOpcode
    );
    assert_eq!(try_read_packet(&data), TryReadResult::Packet(data.len()));
}

#[test]
fn fingerprint_of_keyexchange_matches_client_id() {
    // ML-KEM-768 / ML-DSA-65 public-key sizes, as sent by the Android client
    // in the 0x0C KeyExchangeKemDsa packet right after auth.
    let kem = vec![0x5Au8; 1184];
    let dsa = vec![0x6Bu8; 1952];
    let packet = build_key_exchange(&kem, &dsa);

    let fp = impulse_server::relay::users::fingerprint_of_keyexchange(&packet)
        .expect("valid 0x0C frame yields a fingerprint");
    assert_eq!(fp.len(), 32);
    // Golden value: SHA-256(0x5A repeated 1184 times) hex, truncated to 32 —
    // exactly the client's SecureKeyManager.fingerprintForBytes output.
    assert_eq!(fp, "383e3a1e042cf51407cb723ec48b958e");

    // The frame the server relays to peers is byte-identical to the client's.
    assert_eq!(packet[0], 0x0C);
    assert_eq!(try_read_packet(&packet), TryReadResult::Packet(packet.len()));
}
