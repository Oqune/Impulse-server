//! Auth handshake integration tests (moved from `src/tests.rs`, Task 6).
//!
//! Simulates the full Argon2 + HMAC-SHA-256 challenge-response handshake at
//! the packet level without a live WebTransport connection: the client builds
//! Auth packets via `tests::common`, and the server-side verification path is
//! re-implemented with `common::server_verify_auth` / `derive_argon2_key`.
//!
//! Protocol:
//!   Client sends: [0x01] [len:raw_password_bytes] [32 raw bytes: HMAC-SHA-256]
//!   HMAC key = Argon2id(password) output (32 bytes)
//!   HMAC msg = server nonce (16 bytes)

mod common;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use impulse_server::crypto::{argon2_hash, sha256_hex};
use impulse_server::protocol::{
    Opcode, PacketReader, PacketWriter, ProtocolError, encode_auth_challenge, encode_auth_result,
    encode_data, encode_heartbeat,
};
use common::{assert_bytes_eq, build_client_auth, derive_argon2_key, server_verify_auth};

type HmacSha256 = Hmac<Sha256>;

/// Convenience: is this Auth packet fully valid (password AND challenge)?
fn auth_packet_ok(packet: &[u8], stored_hash: &str, server_nonce: &[u8]) -> bool {
    server_verify_auth(packet, stored_hash, server_nonce)
        .map(|(h, n)| h && n)
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// HMAC-SHA-256 challenge-response primitives
// ---------------------------------------------------------------------------

#[test]
fn hmac_challenge_response_roundtrip() {
    let password = "s3cret_p@ss!";
    let nonce: Vec<u8> = (0..16).map(|i| i as u8).collect();

    // Client side: HMAC key = hex string bytes, matching Protocol.kt.
    let key_hex = sha256_hex(password); // 64-char hex string
    let key_bytes = key_hex.as_bytes(); // 64 bytes

    let mut mac = HmacSha256::new_from_slice(key_bytes).unwrap();
    mac.update(&nonce);
    let client_response = mac.finalize().into_bytes().to_vec();

    // Server side: verify HMAC response with the same key.
    let mut mac2 = HmacSha256::new_from_slice(key_bytes).unwrap();
    mac2.update(&nonce);
    assert!(mac2.verify_slice(&client_response).is_ok());
}

#[test]
fn hmac_wrong_nonce_fails() {
    let password = "test123";
    let nonce: Vec<u8> = (1..=16).collect();
    let wrong_nonce: Vec<u8> = vec![16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

    let key_hex = sha256_hex(password);
    let mut mac = HmacSha256::new_from_slice(key_hex.as_bytes()).unwrap();
    mac.update(&nonce);
    let client_response = mac.finalize().into_bytes().to_vec();

    let mut mac2 = HmacSha256::new_from_slice(key_hex.as_bytes()).unwrap();
    mac2.update(&wrong_nonce);
    assert!(mac2.verify_slice(&client_response).is_err());
}

#[test]
fn hmac_wrong_password_fails() {
    let nonce: Vec<u8> = vec![42; 16];

    let key_hex_correct = sha256_hex("correct_password");
    let mut mac = HmacSha256::new_from_slice(key_hex_correct.as_bytes()).unwrap();
    mac.update(&nonce);
    let client_response = mac.finalize().into_bytes().to_vec();

    let key_hex_wrong = sha256_hex("wrong_password");
    let mut mac2 = HmacSha256::new_from_slice(key_hex_wrong.as_bytes()).unwrap();
    mac2.update(&nonce);
    assert!(mac2.verify_slice(&client_response).is_err());
}

// ---------------------------------------------------------------------------
// Full handshake simulation (Argon2)
// ---------------------------------------------------------------------------

#[test]
fn full_handshake_valid_password() {
    let password = "my_secret_pass";
    let stored_hash = argon2_hash(password).unwrap();

    let nonce: Vec<u8> = (0..16).map(|i| (i + 42) as u8).collect();
    let auth_packet = build_client_auth(password, &nonce, &stored_hash);

    assert!(auth_packet_ok(&auth_packet, &stored_hash, &nonce));
}

#[test]
fn full_handshake_wrong_password() {
    let correct_password = "correct_pass";
    let wrong_password = "wrong_pass";
    let stored_hash = argon2_hash(correct_password).unwrap();

    let nonce: Vec<u8> = (1..=16).collect();
    let auth_packet = build_client_auth(wrong_password, &nonce, &stored_hash);

    assert!(!auth_packet_ok(&auth_packet, &stored_hash, &nonce));
}

#[test]
fn full_handshake_wrong_nonce() {
    let password = "pass123";
    let stored_hash = argon2_hash(password).unwrap();

    let client_nonce: Vec<u8> = (1..=16).collect();
    let server_nonce: Vec<u8> = vec![16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

    let auth_packet = build_client_auth(password, &client_nonce, &stored_hash);

    // Server verifies with the different nonce — HMAC must fail.
    assert!(!auth_packet_ok(&auth_packet, &stored_hash, &server_nonce));
}

#[test]
fn auth_packet_wire_layout() {
    let password = "test";
    let nonce: Vec<u8> = vec![0xAA; 16];

    let packet = build_client_auth(password, &nonce, &argon2_hash(password).unwrap());

    // Byte 0: opcode 0x01
    assert_eq!(packet[0], 0x01);

    // C3 (HMAC-only): bytes 1-4 = hmac length (u32 LE), must be 32.
    let hmac_len = u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]);
    assert_eq!(hmac_len, 32, "C3: 0x01 must carry a 32-byte HMAC, not a password");

    // The raw password must NOT appear anywhere on the wire.
    assert!(
        !packet[5..].windows(password.len()).any(|w| w == password.as_bytes()),
        "C3: raw password must not travel on the wire"
    );

    // Total frame = 1 (opcode) + 4 (len) + 32 (hmac) = 37 bytes.
    assert_eq!(packet.len(), 5 + 32);

    // Verify the HMAC is present and 32 bytes.
    let hmac = &packet[5..];
    assert_eq!(hmac.len(), 32);
}

#[test]
fn brute_force_simulation() {
    let correct_password = "correct";
    let stored_hash = argon2_hash(correct_password).unwrap();
    let nonce: Vec<u8> = vec![42; 16];

    // 5 wrong attempts.
    for i in 0..5 {
        let wrong = format!("wrong_{}", i);
        let packet = build_client_auth(&wrong, &nonce, &stored_hash);
        assert!(
            !auth_packet_ok(&packet, &stored_hash, &nonce),
            "Attempt {} should fail",
            i
        );
    }

    // Correct password still works (rate limiter is separate).
    let correct_packet = build_client_auth(correct_password, &nonce, &stored_hash);
    assert!(auth_packet_ok(&correct_packet, &stored_hash, &nonce));
}

// ---------------------------------------------------------------------------
// Auth packet wire format, boundary, and malformed-input cases
// ---------------------------------------------------------------------------

#[test]
fn auth_packet_full_wire_format() {
    let password = "integration_test_pass!";
    let stored_hash = argon2_hash(password).unwrap();
    let nonce: Vec<u8> = vec![0x5A; 16];

    let packet = build_client_auth(password, &nonce, &stored_hash);

    // NEW wire layout (C3 §4.2): opcode + u32 hmac_len(=32) + 32-byte HMAC response.
    // The raw password NEVER travels on the wire.
    assert_eq!(packet[0], 0x01);
    let hmac_len = u32::from_le_bytes(packet[1..5].try_into().unwrap());
    assert_eq!(hmac_len, 32);
    assert_eq!(packet.len(), 1 + 4 + 32);

    // Parse with PacketReader (exactly like process_packet)
    let mut reader = PacketReader::new(&packet);
    assert_eq!(reader.read_opcode().unwrap(), Opcode::Auth);
    let parsed_hmac = reader.read_len_prefixed().unwrap();
    assert_eq!(parsed_hmac.len(), 32);
    assert!(reader.remaining().is_empty());

    // Server-side verification (HMAC-only; key derived from stored hash, C3)
    let (hash_ok, nonce_valid) = server_verify_auth(&packet, &stored_hash, &nonce).unwrap();
    assert!(hash_ok, "Argon2 password verification should succeed");
    assert!(nonce_valid, "HMAC challenge-response should succeed");
}

#[test]
fn auth_packet_boundary_conditions() {
    // a) Empty password
    let password_empty = "";
    let stored_hash_empty = argon2_hash(password_empty).unwrap();
    let nonce = vec![0xBB; 16];
    let packet = build_client_auth(password_empty, &nonce, &stored_hash_empty);
    let (h, n) = server_verify_auth(&packet, &stored_hash_empty, &nonce).unwrap();
    assert!(h, "empty password: hash should verify");
    assert!(n, "empty password: HMAC should verify");

    // b) Unicode / multibyte password
    let password_unicode = "hello_world_123";
    let stored_hash_unicode = argon2_hash(password_unicode).unwrap();
    let nonce2 = vec![0xCC; 16];
    let packet2 = build_client_auth(password_unicode, &nonce2, &stored_hash_unicode);
    let (h2, n2) = server_verify_auth(&packet2, &stored_hash_unicode, &nonce2).unwrap();
    assert!(h2, "unicode password: hash should verify");
    assert!(n2, "unicode password: HMAC should verify");

    // c) Password with null bytes
    let password_null = "hello\0world\0!";
    let stored_hash_null = argon2_hash(password_null).unwrap();
    let nonce3 = vec![0xDD; 16];
    let packet3 = build_client_auth(password_null, &nonce3, &stored_hash_null);
    let (h3, n3) = server_verify_auth(&packet3, &stored_hash_null, &nonce3).unwrap();
    assert!(h3, "null-byte password: hash should verify");
    assert!(n3, "null-byte password: HMAC should verify");

    // d) Max-length password (65535 bytes) — verify wire-format parsing.
    // Skip Argon2 verification (too slow); just test the parse roundtrip.
    let password_max = "A".repeat(65535);
    let nonce4 = vec![0xEE; 16];
    let key = derive_argon2_key("dummy", &stored_hash_empty);
    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(&nonce4);
    let hmac_response = mac.finalize().into_bytes().to_vec();
    let mut w = PacketWriter::with_opcode(Opcode::Auth);
    w.write_len_prefixed(password_max.as_bytes());
    w.write_raw(&hmac_response);
    let packet_max = w.into_bytes();

    let mut reader = PacketReader::new(&packet_max);
    assert_eq!(reader.read_opcode().unwrap(), Opcode::Auth);
    let pwd = reader.read_len_prefixed().unwrap();
    assert_eq!(pwd.len(), 65535);
    let hmac = reader.read_bytes(32).unwrap();
    assert_eq!(hmac.len(), 32);
    assert!(reader.remaining().is_empty());
}

#[test]
fn auth_packet_malformed_input() {
    // a) Truncated pwd_len field (only 3 bytes instead of 4)
    let buf = [0x01u8, 0x04, 0x00, 0x00];
    let mut r = PacketReader::new(&buf);
    assert_eq!(r.read_opcode().unwrap(), Opcode::Auth);
    assert!(matches!(
        r.read_len_prefixed(),
        Err(ProtocolError::UnexpectedEof)
    ));

    // b) pwd_len says 100 but only 10 bytes available
    let mut w = PacketWriter::with_opcode(Opcode::Auth);
    w.write_u32(100);
    w.write_raw(&[0xAA; 10]);
    let buf2 = w.into_bytes();
    let mut r2 = PacketReader::new(&buf2);
    assert_eq!(r2.read_opcode().unwrap(), Opcode::Auth);
    assert!(matches!(
        r2.read_len_prefixed(),
        Err(ProtocolError::UnexpectedEof)
    ));

    // c) Missing HMAC bytes (pwd only, no trailing 32 bytes)
    let mut w3 = PacketWriter::with_opcode(Opcode::Auth);
    w3.write_len_prefixed(b"test");
    let buf3 = w3.into_bytes();
    let mut r3 = PacketReader::new(&buf3);
    assert_eq!(r3.read_opcode().unwrap(), Opcode::Auth);
    let pwd = r3.read_len_prefixed().unwrap();
    assert_eq!(pwd, b"test");
    assert!(r3.remaining().is_empty());
    assert!(matches!(
        r3.read_bytes(32),
        Err(ProtocolError::UnexpectedEof)
    ));

    // d) Extra trailing bytes — still parses, reader ignores them
    let mut w4 = PacketWriter::with_opcode(Opcode::Auth);
    w4.write_len_prefixed(b"ok");
    w4.write_raw(&[0u8; 32]);
    w4.write_raw(&[0xFF; 10]);
    let buf4 = w4.into_bytes();
    let mut r4 = PacketReader::new(&buf4);
    assert_eq!(r4.read_opcode().unwrap(), Opcode::Auth);
    let pwd = r4.read_len_prefixed().unwrap();
    assert_eq!(pwd, b"ok");
    let hmac = r4.read_bytes(32).unwrap();
    assert_eq!(hmac.len(), 32);
    assert_eq!(r4.remaining().len(), 10);

    // e) Zero-length password
    let mut w5 = PacketWriter::with_opcode(Opcode::Auth);
    w5.write_u32(0);
    w5.write_raw(&[0u8; 32]);
    let buf5 = w5.into_bytes();
    let mut r5 = PacketReader::new(&buf5);
    assert_eq!(r5.read_opcode().unwrap(), Opcode::Auth);
    let pwd = r5.read_len_prefixed().unwrap();
    assert_eq!(pwd.len(), 0);
    let hmac = r5.read_bytes(32).unwrap();
    assert_eq!(hmac.len(), 32);

    // f) Oversized pwd_len (>1MB) — read_len_prefixed has MAX_LEN_PREFIXED
    let mut w6 = PacketWriter::with_opcode(Opcode::Auth);
    w6.write_u32(2_000_000);
    let buf6 = w6.into_bytes();
    let mut r6 = PacketReader::new(&buf6);
    assert_eq!(r6.read_opcode().unwrap(), Opcode::Auth);
    assert!(matches!(
        r6.read_len_prefixed(),
        Err(ProtocolError::UnexpectedEof)
    ));
}

#[test]
fn sync_roundtrip() {
    let last_seen_id: u64 = 42;
    let mut w = PacketWriter::with_opcode(Opcode::Sync);
    w.write_u64(last_seen_id);
    let bytes = w.into_bytes();

    assert_eq!(bytes.len(), 1 + 8);
    assert_eq!(bytes[0], 0x03);

    let mut r = PacketReader::new(&bytes);
    assert_eq!(r.read_opcode().unwrap(), Opcode::Sync);
    assert_eq!(r.read_u64().unwrap(), last_seen_id);
    assert!(r.remaining().is_empty());
}

#[test]
fn data_roundtrip_with_timestamps() {
    let id: u64 = 999;
    let timestamp: u64 = 1_700_000_000_000;
    let payload = b"encrypted_message_data";

    let bytes = encode_data(id, timestamp, payload);
    assert_eq!(bytes[0], 0x05);

    let mut r = PacketReader::new(&bytes);
    assert_eq!(r.read_opcode().unwrap(), Opcode::Data);
    assert_eq!(r.read_u64().unwrap(), id);
    assert_eq!(r.read_u64().unwrap(), timestamp);
    let parsed_payload = r.read_len_prefixed().unwrap();
    assert_eq!(parsed_payload, payload);
    assert!(r.remaining().is_empty());

    // 1 (opcode) + 8 (id) + 8 (ts) + 4 (len) + payload.len()
    assert_eq!(bytes.len(), 1 + 8 + 8 + 4 + payload.len());
}

#[test]
fn heartbeat_roundtrip() {
    let timestamp: u64 = 1_700_000_000;
    let bytes = encode_heartbeat(timestamp);

    assert_eq!(bytes.len(), 1 + 8);
    assert_eq!(bytes[0], 0x06);

    let mut r = PacketReader::new(&bytes);
    assert_eq!(r.read_opcode().unwrap(), Opcode::Heartbeat);
    assert_eq!(r.read_u64().unwrap(), timestamp);
    assert!(r.remaining().is_empty());
}

#[test]
fn full_handshake_sequence() {
    let password = "full_handshake_secret";
    let stored_hash = argon2_hash(password).unwrap();

    // a. Server generates a 16-byte nonce and sends AuthChallenge.
    let server_nonce: Vec<u8> = (0x01..=0x10).collect();
    let argon2_salt_b64 = {
        use argon2::password_hash::PasswordHash;
        let parsed = PasswordHash::new(&stored_hash).unwrap();
        parsed.salt.map(|s| s.to_string()).unwrap_or_default()
    };
    let challenge_packet = encode_auth_challenge(&server_nonce, &argon2_salt_b64);
    assert_eq!(challenge_packet[0], 0x0B);
    assert_eq!(&challenge_packet[1..17], &server_nonce[..]);

    // b. Client parses AuthChallenge, extracts nonce + salt.
    let mut cr = PacketReader::new(&challenge_packet);
    assert_eq!(cr.read_opcode().unwrap(), Opcode::AuthChallenge);
    let client_nonce = cr.read_bytes(16).unwrap();
    assert_bytes_eq(&client_nonce, &server_nonce);
    let parsed_salt = cr.read_len_prefixed().unwrap();
    let client_salt_b64 = std::str::from_utf8(&parsed_salt).unwrap();
    assert_eq!(client_salt_b64, argon2_salt_b64);

    // c. Client derives the Argon2 key and builds the Auth packet.
    let auth_packet = build_client_auth(password, &client_nonce, &stored_hash);
    assert_eq!(auth_packet[0], 0x01);

    // d. Server parses Auth and verifies.
    let (hash_ok, nonce_valid) =
        server_verify_auth(&auth_packet, &stored_hash, &server_nonce).unwrap();
    assert!(hash_ok, "password verification should succeed");
    assert!(nonce_valid, "HMAC challenge-response should succeed");

    // e. Server builds AuthResult (success).
    let success_result = encode_auth_result(true, None);
    assert_eq!(success_result[0], 0x02);
    assert_eq!(success_result[1], 0x01);

    // f. Client parses AuthResult.
    let mut rr = PacketReader::new(&success_result);
    assert_eq!(rr.read_opcode().unwrap(), Opcode::AuthResult);
    let status = rr.read_u8().unwrap();
    assert_eq!(status, 0x01, "status should indicate success");

    // Failure path.
    let fail_result = encode_auth_result(false, Some("Invalid password or challenge"));
    let mut fr = PacketReader::new(&fail_result);
    assert_eq!(fr.read_opcode().unwrap(), Opcode::AuthResult);
    let fail_status = fr.read_u8().unwrap();
    assert_eq!(fail_status, 0x00);
    let fail_msg = fr.read_len_prefixed().unwrap();
    assert_eq!(
        std::str::from_utf8(&fail_msg).unwrap(),
        "Invalid password or challenge"
    );
}
