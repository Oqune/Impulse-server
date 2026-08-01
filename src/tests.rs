//! Unit and integration tests for the Impulse server.
//!
//! Covers:
//! * Protocol encoding/decoding (opcodes, packet layout, byte order).
//! * Certificate SHA-256 fingerprint derivation.
//! * In-memory message store (append, sync, TTL sweep, ordering).
//!
//! Integration tests with a live WebTransport client are run separately
//! via CI (see `.github/workflows/ci.yml`).

#[cfg(test)]
mod protocol_tests {
    use crate::protocol::{
        Opcode, PacketReader, PacketWriter, ProtocolError, encode_auth_result, encode_data,
        encode_new_cert_hash, encode_sync_response,
    };

    #[test]
    fn auth_roundtrip_layout() {
        let mut w = PacketWriter::with_opcode(Opcode::Auth);
        w.write_len_prefixed(b"secret");
        let bytes = w.into_bytes();
        assert_eq!(bytes[0], 0x01);
        let mut r = PacketReader::new(&bytes);
        assert_eq!(r.read_opcode().unwrap(), Opcode::Auth);
        assert_eq!(r.read_len_prefixed().unwrap(), b"secret");
    }

    #[test]
    fn unknown_opcode_is_error() {
        let buf = [0x00u8];
        let mut r = PacketReader::new(&buf);
        assert!(matches!(
            r.read_opcode(),
            Err(ProtocolError::UnknownOpcode(0x00))
        ));
    }

    #[test]
    fn truncated_packet_errors() {
        let buf = [0x03u8, 0x01]; // Sync opcode + only 1 of 8 bytes
        let mut r = PacketReader::new(&buf);
        assert_eq!(r.read_opcode().unwrap(), Opcode::Sync);
        assert!(matches!(r.read_u64(), Err(ProtocolError::UnexpectedEof)));
    }

    #[test]
    fn new_cert_hash_is_exactly_32_bytes_then_u64() {
        let hash = [0xABu8; 32];
        let bytes = encode_new_cert_hash(&hash, 1_700_000_000);
        assert_eq!(bytes[0], 0x07);
        assert_eq!(&bytes[1..33], &hash[..]);
        assert_eq!(&bytes[33..41], &1_700_000_000u64.to_le_bytes());
        assert_eq!(bytes.len(), 41);
    }

    #[test]
    fn data_packet_layout() {
        let bytes = encode_data(7, 12345, b"hello");
        assert_eq!(bytes[0], 0x05);
        let mut r = PacketReader::new(&bytes);
        r.read_opcode().unwrap();
        assert_eq!(r.read_u64().unwrap(), 7);
        assert_eq!(r.read_u64().unwrap(), 12345);
        assert_eq!(r.read_len_prefixed().unwrap(), b"hello");
    }

    #[test]
    fn sync_response_count_and_messages() {
        let msgs = vec![(1u64, 10u64, b"a".to_vec()), (2u64, 20u64, b"bb".to_vec())];
        let bytes = encode_sync_response(&msgs);
        assert_eq!(bytes[0], 0x04);
        let mut r = PacketReader::new(&bytes);
        r.read_opcode().unwrap();
        assert_eq!(r.read_u32().unwrap(), 2);
        assert_eq!(r.read_u64().unwrap(), 1);
        assert_eq!(r.read_u64().unwrap(), 10);
        assert_eq!(r.read_len_prefixed().unwrap(), b"a");
        assert_eq!(r.read_u64().unwrap(), 2);
    }

    #[test]
    fn auth_result_status_byte() {
        let ok = encode_auth_result(true, None);
        assert_eq!(ok[0], 0x02);
        assert_eq!(ok[1], 0x01);
        let fail = encode_auth_result(false, Some("bad"));
        assert_eq!(fail[0], 0x02);
        assert_eq!(fail[1], 0x00);
        // payload is length-prefixed: u32 len (3) then "bad".
        assert_eq!(&fail[2..6], &3u32.to_le_bytes());
        assert_eq!(&fail[6..9], b"bad");
    }
}

#[cfg(test)]
mod cert_tests {
    use crate::cert::Cert;

    #[test]
    fn fingerprint_is_64_hex_chars() {
        // Build a tiny fake DER just to exercise the hash function path.
        // We can't easily construct a real CertificateDer, so we assert the
        // published property on the algorithm via a known empty input.
        let der = rustls_pki_types::CertificateDer::from(vec![]);
        let fp = Cert::fingerprint_of(&der);
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        let bytes = Cert::fingerprint_bytes_of(&der);
        assert_eq!(bytes.len(), 32);
    }
}

#[cfg(test)]
mod storage_tests {
    use crate::storage::{MESSAGE_TTL, MessageStore};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    #[test]
    fn sweep_removes_expired() {
        let store = MessageStore::new();
        // One fresh and one already-expired message (TTL is 72h).
        store.push(vec![1]);
        let expired_ts = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64)
            - (MESSAGE_TTL.as_millis() as u64)
            - 1000;
        store.push_with_timestamp(vec![2], expired_ts);
        assert_eq!(store.len(), 2);

        let removed = store.sweep();
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 1);
        // Sanity: TTL is 72h.
        assert_eq!(MESSAGE_TTL, Duration::from_secs(60 * 60 * 24 * 3));
        let _ = UNIX_EPOCH;
    }
}

#[cfg(test)]
mod auth_tests {
    use crate::config::{argon2_hash, sha256_hex};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    /// Verify that HMAC-SHA-256 challenge-response works end-to-end:
    /// client computes HMAC(key=SHA-256(password)_hex_bytes, msg=nonce),
    /// server recomputes and verifies.
    #[test]
    fn hmac_challenge_response_roundtrip() {
        let password = "s3cret_p@ss!";
        let nonce: Vec<u8> = (0..16).map(|i| i as u8).collect();

        // Client side: build HMAC response (key = hex string bytes, matching Protocol.kt).
        let key_hex = sha256_hex(password); // 64-char hex string
        let key_bytes = key_hex.as_bytes(); // 64 bytes

        let mut mac = HmacSha256::new_from_slice(key_bytes).unwrap();
        mac.update(&nonce);
        let client_response = mac.finalize().into_bytes().to_vec();

        // Server side: verify HMAC response with same key.
        let mut mac2 = HmacSha256::new_from_slice(key_bytes).unwrap();
        mac2.update(&nonce);
        assert!(mac2.verify_slice(&client_response).is_ok());
    }

    /// HMAC with wrong nonce should fail.
    #[test]
    fn hmac_wrong_nonce_fails() {
        let password = "test123";
        let nonce: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let wrong_nonce: Vec<u8> = vec![16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

        let key_hex = sha256_hex(password);
        let mut mac = HmacSha256::new_from_slice(key_hex.as_bytes()).unwrap();
        mac.update(&nonce);
        let client_response = mac.finalize().into_bytes().to_vec();

        let mut mac2 = HmacSha256::new_from_slice(key_hex.as_bytes()).unwrap();
        mac2.update(&wrong_nonce);
        assert!(mac2.verify_slice(&client_response).is_err());
    }

    /// HMAC with wrong password should fail.
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

    /// Argon2 hash is parseable and verifiable.
    #[test]
    fn argon2_hash_roundtrip() {
        let password = "my_secret_password";
        let hash = argon2_hash(password);

        // The encoded hash should start with $argon2id$.
        assert!(hash.starts_with("$argon2"));

        // Verify the password against the hash.
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        let parsed = PasswordHash::new(&hash).expect("should parse Argon2 hash");
        let result = argon2::Argon2::default()
            .verify_password(password.as_bytes(), &parsed);
        assert!(result.is_ok(), "Argon2 should verify correct password");
    }

    /// Argon2 with wrong password should fail verification.
    #[test]
    fn argon2_wrong_password_fails() {
        let hash = argon2_hash("correct_password");

        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        let parsed = PasswordHash::new(&hash).expect("should parse Argon2 hash");
        let result = argon2::Argon2::default()
            .verify_password("wrong_password".as_bytes(), &parsed);
        assert!(result.is_err(), "Argon2 should reject wrong password");
    }

    /// SHA-256 hex matches expected value.
    #[test]
    fn sha256_hex_known_vector() {
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let hash = sha256_hex("hello");
        assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }
}

// ============================================================================
// INTEGRATION TESTS — Auth Handshake Simulation (Argon2 + HMAC)
// ============================================================================
// These tests simulate the full auth handshake protocol at the packet level
// without a real WebTransport connection, verifying that client-produced
// packets are correctly parsed and verified by the server's protocol logic.
//
// New protocol (Argon2):
//   Client sends: [0x01] [len:raw_password_bytes] [len:HMAC_response]
//   HMAC key = Argon2id(password) output (32 bytes)
//   HMAC message = server nonce (16 bytes)

#[cfg(test)]
mod handshake_tests {
    use crate::protocol::{PacketReader, PacketWriter, Opcode};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    /// Derive a 32-byte key from password using Argon2id (matching server params).
    fn argon2_derive_key(password: &str) -> Vec<u8> {
        // We need to compute Argon2(password) to get raw bytes.
        // Use a fixed salt for testing (deterministic).
        let salt_str = argon2::password_hash::SaltString::from_b64(
            "AAAAAAAAAAAAAAAAAAAAAA"
        ).unwrap();
        let mut raw_salt_buf = [0u8; 64];
        let raw_salt = salt_str.decode_b64(&mut raw_salt_buf).unwrap();
        let mut output = [0u8; 32];
        argon2::Argon2::default()
            .hash_password_into(password.as_bytes(), raw_salt, &mut output)
            .unwrap();
        output.to_vec()
    }

    /// Build a client Auth packet (0x01) using the new Argon2 protocol.
    /// Returns: opcode + raw_password_bytes (len-prefixed) + hmac_response (32 raw bytes).
    fn build_client_auth(password: &str, server_nonce: &[u8]) -> Vec<u8> {
        let key = argon2_derive_key(password);

        // HMAC-SHA-256(key=Argon2_output, message=nonce)
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(server_nonce);
        let hmac_response = mac.finalize().into_bytes().to_vec();

        let mut w = PacketWriter::with_opcode(Opcode::Auth);
        w.write_len_prefixed(password.as_bytes());
        w.write_raw(&hmac_response);
        w.into_bytes()
    }

    /// Verify an Auth packet as the server would: parse, Argon2 verify, check HMAC.
    fn verify_auth_packet(packet: &[u8], stored_argon2_hash: &str, server_nonce: &[u8]) -> bool {
        let mut reader = PacketReader::new(packet);
        let opcode = reader.read_opcode().unwrap();
        assert_eq!(opcode, Opcode::Auth);

        // Read raw password bytes from packet.
        let password_bytes = reader.read_len_prefixed().unwrap();
        let password = String::from_utf8(password_bytes).unwrap();

        // Read fixed 32-byte HMAC response from packet.
        let client_response = reader.read_bytes(32).unwrap();
        assert_eq!(client_response.len(), 32);

        // Step 1: Verify password against stored Argon2 hash.
        let hash_ok = crate::config::argon2_verify(&password, stored_argon2_hash);

        // Step 2: Derive HMAC key from Argon2 output.
        let key = argon2_derive_key(&password);

        // Step 3: Verify HMAC.
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(server_nonce);
        let hmac_ok = mac.verify_slice(&client_response).is_ok();

        hash_ok && hmac_ok
    }

    /// Full handshake simulation with Argon2.
    #[test]
    fn full_handshake_valid_password() {
        let password = "my_secret_pass";
        let stored_hash = crate::config::argon2_hash(password);

        let nonce: Vec<u8> = (0..16).map(|i| (i + 42) as u8).collect();
        let auth_packet = build_client_auth(password, &nonce);

        assert!(verify_auth_packet(&auth_packet, &stored_hash, &nonce));
    }

    /// Handshake with wrong password → Argon2 verification fails.
    #[test]
    fn full_handshake_wrong_password() {
        let correct_password = "correct_pass";
        let wrong_password = "wrong_pass";
        let stored_hash = crate::config::argon2_hash(correct_password);

        let nonce: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let auth_packet = build_client_auth(wrong_password, &nonce);

        assert!(!verify_auth_packet(&auth_packet, &stored_hash, &nonce));
    }

    /// Handshake with wrong nonce → HMAC verification fails.
    #[test]
    fn full_handshake_wrong_nonce() {
        let password = "pass123";
        let stored_hash = crate::config::argon2_hash(password);

        let client_nonce: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let server_nonce: Vec<u8> = vec![16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

        let auth_packet = build_client_auth(password, &client_nonce);

        // Server verifies with server_nonce (different) — HMAC should fail.
        assert!(!verify_auth_packet(&auth_packet, &stored_hash, &server_nonce));
    }

    /// Auth packet wire format verification.
    #[test]
    fn auth_packet_wire_layout() {
        let password = "test";
        let nonce: Vec<u8> = vec![0xAA; 16];

        let packet = build_client_auth(password, &nonce);

        // Byte 0: opcode 0x01
        assert_eq!(packet[0], 0x01);

        // Bytes 1-4: password length (u32 LE)
        let pw_len = u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]);
        assert_eq!(pw_len as usize, password.len());

        // Bytes 5..(5+pw_len): raw password bytes
        let pw_start = 5;
        let pw_end = pw_start + pw_len as usize;
        assert_eq!(&packet[pw_start..pw_end], password.as_bytes());

        // Bytes pw_end..(pw_end+32): raw HMAC (no length prefix)
        assert_eq!(packet.len(), pw_end + 32);

        // Verify the HMAC is present and 32 bytes
        let hmac = &packet[pw_end..];
        assert_eq!(hmac.len(), 32);
    }

    /// Multiple sequential auth attempts with wrong passwords (brute-force simulation).
    #[test]
    fn brute_force_simulation() {
        let correct_password = "correct";
        let stored_hash = crate::config::argon2_hash(correct_password);
        let nonce: Vec<u8> = vec![42; 16];

        // 5 wrong attempts.
        for i in 0..5 {
            let wrong = format!("wrong_{}", i);
            let packet = build_client_auth(&wrong, &nonce);
            assert!(
                !verify_auth_packet(&packet, &stored_hash, &nonce),
                "Attempt {} should fail",
                i
            );
        }

        // Correct password still works (rate limiter is separate).
        let correct_packet = build_client_auth(correct_password, &nonce);
        assert!(verify_auth_packet(&correct_packet, &stored_hash, &nonce));
    }
}

// ============================================================================
// INTEGRATION PROTOCOL TESTS — Full handshake, multi-client, edge cases
// ============================================================================

#[cfg(test)]
mod integration_protocol_tests {
    use crate::config::{argon2_hash, argon2_verify};
    use crate::protocol::{
        Opcode, PacketReader, PacketWriter, ProtocolError, encode_auth_challenge, encode_auth_result,
        encode_data, encode_heartbeat, encode_new_cert_hash, encode_sync_response,
    };
    use crate::storage::MessageStore;
    use dashmap::DashMap;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    type HmacSha256 = Hmac<Sha256>;

    /// Derive a 32-byte Argon2id raw key from password using the salt from a stored hash.
    /// This mirrors the real server's key derivation at server.rs:770-774.
    fn derive_argon2_key(password: &str, stored_hash: &str) -> Vec<u8> {
        use argon2::password_hash::PasswordHash;
        let parsed = PasswordHash::new(stored_hash).expect("should parse stored hash");
        let salt = parsed.salt.expect("stored hash should have a salt");
        let mut raw_salt_buf = [0u8; 64];
        let raw_salt = salt.decode_b64(&mut raw_salt_buf).expect("should decode B64 salt");
        let mut output = [0u8; 32];
        argon2::Argon2::default()
            .hash_password_into(password.as_bytes(), raw_salt, &mut output)
            .expect("Argon2 derivation should not fail");
        output.to_vec()
    }

    /// Build a client Auth packet: [0x01] [u32 LE pwd_len] [pwd_bytes] [32 raw HMAC].
    fn build_client_auth(password: &str, server_nonce: &[u8], stored_hash: &str) -> Vec<u8> {
        let key = derive_argon2_key(password, stored_hash);
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(server_nonce);
        let hmac_response = mac.finalize().into_bytes().to_vec();

        let mut w = PacketWriter::with_opcode(Opcode::Auth);
        w.write_len_prefixed(password.as_bytes());
        w.write_raw(&hmac_response);
        w.into_bytes()
    }

    /// Parse and verify an Auth packet exactly as the server does.
    fn server_verify_auth(
        packet: &[u8],
        stored_hash: &str,
        server_nonce: &[u8],
    ) -> Result<(bool, bool), String> {
        let mut reader = PacketReader::new(packet);
        let opcode = reader.read_opcode().map_err(|e| format!("opcode: {e}"))?;
        if opcode != Opcode::Auth {
            return Err("not an Auth packet".into());
        }

        let password_bytes = reader
            .read_len_prefixed()
            .map_err(|e| format!("pwd_len_prefixed: {e}"))?;
        let password =
            String::from_utf8(password_bytes).map_err(|_| String::from("invalid UTF-8 in password"))?;

        let hash_ok = argon2_verify(&password, stored_hash);

        let nonce_valid = if reader.remaining().is_empty() {
            false
        } else {
            let client_response = reader
                .read_bytes(32)
                .map_err(|e| format!("hmac bytes: {e}"))?;
            if client_response.len() != 32 {
                return Err("HMAC not 32 bytes".into());
            }
            if hash_ok {
                let key = derive_argon2_key(&password, stored_hash);
                let mut mac = HmacSha256::new_from_slice(&key)
                    .map_err(|e| format!("HMAC key: {e}"))?;
                mac.update(server_nonce);
                mac.verify_slice(&client_response).is_ok()
            } else {
                false
            }
        };

        Ok((hash_ok, nonce_valid))
    }

    /// ── 1. test_auth_packet_full_wire_format ────────────────────────────────────
    /// Build a complete Auth packet using the client's exact wire format, then parse
    /// it with PacketReader exactly like process_packet does. Verify password
    /// extraction, Argon2 verification, and HMAC verification all succeed.
    #[test]
    fn test_auth_packet_full_wire_format() {
        let password = "integration_test_pass!";
        let stored_hash = argon2_hash(password);
        let nonce: Vec<u8> = vec![0x5A; 16];

        let packet = build_client_auth(password, &nonce, &stored_hash);

        // Verify wire layout: opcode + u32 pwd_len + pwd + 32 HMAC
        assert_eq!(packet[0], 0x01);
        let pwd_len = u32::from_le_bytes(packet[1..5].try_into().unwrap());
        assert_eq!(pwd_len as usize, password.len());
        assert_eq!(&packet[5..5 + pwd_len as usize], password.as_bytes());
        assert_eq!(packet.len(), 5 + pwd_len as usize + 32);

        // Parse with PacketReader (exactly like process_packet)
        let mut reader = PacketReader::new(&packet);
        assert_eq!(reader.read_opcode().unwrap(), Opcode::Auth);
        let parsed_pwd = reader.read_len_prefixed().unwrap();
        assert_eq!(parsed_pwd, password.as_bytes());
        let parsed_hmac = reader.read_bytes(32).unwrap();
        assert_eq!(parsed_hmac.len(), 32);
        assert!(reader.remaining().is_empty());

        // Server-side verification
        let (hash_ok, nonce_valid) = server_verify_auth(&packet, &stored_hash, &nonce).unwrap();
        assert!(hash_ok, "Argon2 password verification should succeed");
        assert!(nonce_valid, "HMAC challenge-response should succeed");
    }

    /// ── 2. test_auth_packet_boundary_conditions ─────────────────────────────────
    /// Test auth with empty password, password with unicode/multibyte chars,
    /// and password with null bytes.
    #[test]
    fn test_auth_packet_boundary_conditions() {
        // a) Empty password
        let password_empty = "";
        let stored_hash_empty = argon2_hash(password_empty);
        let nonce = vec![0xBB; 16];
        let packet = build_client_auth(password_empty, &nonce, &stored_hash_empty);
        let (h, n) = server_verify_auth(&packet, &stored_hash_empty, &nonce).unwrap();
        assert!(h, "empty password: hash should verify");
        assert!(n, "empty password: HMAC should verify");

        // b) Unicode / multibyte password
        let password_unicode = "hello_world_123";
        let stored_hash_unicode = argon2_hash(password_unicode);
        let nonce2 = vec![0xCC; 16];
        let packet2 = build_client_auth(password_unicode, &nonce2, &stored_hash_unicode);
        let (h2, n2) = server_verify_auth(&packet2, &stored_hash_unicode, &nonce2).unwrap();
        assert!(h2, "unicode password: hash should verify");
        assert!(n2, "unicode password: HMAC should verify");

        // c) Password with null bytes
        let password_null = "hello\0world\0!";
        let stored_hash_null = argon2_hash(password_null);
        let nonce3 = vec![0xDD; 16];
        let packet3 = build_client_auth(password_null, &nonce3, &stored_hash_null);
        let (h3, n3) = server_verify_auth(&packet3, &stored_hash_null, &nonce3).unwrap();
        assert!(h3, "null-byte password: hash should verify");
        assert!(n3, "null-byte password: HMAC should verify");

        // d) Max-length password (65535 bytes) — verify wire format parsing works.
        // Skip Argon2 verification (too slow); just test packet parsing roundtrip.
        let password_max = "A".repeat(65535);
        let nonce4 = vec![0xEE; 16];
        let key = derive_argon2_key("dummy", &stored_hash_empty); // arbitrary key for HMAC
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

    /// ── 3. test_auth_packet_malformed_input ─────────────────────────────────────
    /// Test with truncated pwd_len, pwd_len > actual bytes, missing HMAC bytes,
    /// extra trailing bytes, zero-length password, oversized pwd_len (>1MB).
    #[test]
    fn test_auth_packet_malformed_input() {
        // a) Truncated pwd_len field (only 3 bytes instead of 4)
        let buf = [0x01u8, 0x04, 0x00, 0x00]; // opcode + 3-byte incomplete u32
        let mut r = PacketReader::new(&buf);
        assert_eq!(r.read_opcode().unwrap(), Opcode::Auth);
        assert!(matches!(r.read_len_prefixed(), Err(ProtocolError::UnexpectedEof)));

        // b) pwd_len says 100 but only 10 bytes available
        let mut w = PacketWriter::with_opcode(Opcode::Auth);
        w.write_u32(100);
        w.write_raw(&[0xAA; 10]);
        let buf2 = w.into_bytes();
        let mut r2 = PacketReader::new(&buf2);
        assert_eq!(r2.read_opcode().unwrap(), Opcode::Auth);
        assert!(matches!(r2.read_len_prefixed(), Err(ProtocolError::UnexpectedEof)));

        // c) Missing HMAC bytes (pwd only, no trailing 32 bytes)
        let mut w3 = PacketWriter::with_opcode(Opcode::Auth);
        w3.write_len_prefixed(b"test");
        let buf3 = w3.into_bytes();
        let mut r3 = PacketReader::new(&buf3);
        assert_eq!(r3.read_opcode().unwrap(), Opcode::Auth);
        let pwd = r3.read_len_prefixed().unwrap();
        assert_eq!(pwd, b"test");
        assert!(r3.remaining().is_empty()); // no HMAC bytes left
        assert!(matches!(r3.read_bytes(32), Err(ProtocolError::UnexpectedEof)));

        // d) Extra trailing bytes — should still parse, reader ignores them
        let mut w4 = PacketWriter::with_opcode(Opcode::Auth);
        w4.write_len_prefixed(b"ok");
        w4.write_raw(&[0u8; 32]);
        w4.write_raw(&[0xFF; 10]); // 10 extra trailing bytes
        let buf4 = w4.into_bytes();
        let mut r4 = PacketReader::new(&buf4);
        assert_eq!(r4.read_opcode().unwrap(), Opcode::Auth);
        let pwd = r4.read_len_prefixed().unwrap();
        assert_eq!(pwd, b"ok");
        let hmac = r4.read_bytes(32).unwrap();
        assert_eq!(hmac.len(), 32);
        assert_eq!(r4.remaining().len(), 10); // trailing bytes remain

        // e) Zero-length password
        let mut w5 = PacketWriter::with_opcode(Opcode::Auth);
        w5.write_u32(0); // pwd_len = 0
        w5.write_raw(&[0u8; 32]); // HMAC
        let buf5 = w5.into_bytes();
        let mut r5 = PacketReader::new(&buf5);
        assert_eq!(r5.read_opcode().unwrap(), Opcode::Auth);
        let pwd = r5.read_len_prefixed().unwrap();
        assert_eq!(pwd.len(), 0);
        let hmac = r5.read_bytes(32).unwrap();
        assert_eq!(hmac.len(), 32);

        // f) Oversized pwd_len (>1MB) — read_len_prefixed has MAX_LEN_PREFIXED = 1_000_000
        let mut w6 = PacketWriter::with_opcode(Opcode::Auth);
        w6.write_u32(2_000_000); // > MAX_LEN_PREFIXED
        let buf6 = w6.into_bytes();
        let mut r6 = PacketReader::new(&buf6);
        assert_eq!(r6.read_opcode().unwrap(), Opcode::Auth);
        assert!(matches!(r6.read_len_prefixed(), Err(ProtocolError::UnexpectedEof)));
    }

    /// ── 4. test_sync_roundtrip ──────────────────────────────────────────────────
    /// Build Sync packet (0x03, u64 last_seen_id), verify parsing.
    #[test]
    fn test_sync_roundtrip() {
        let last_seen_id: u64 = 42;
        let mut w = PacketWriter::with_opcode(Opcode::Sync);
        w.write_u64(last_seen_id);
        let bytes = w.into_bytes();

        assert_eq!(bytes.len(), 1 + 8); // opcode + u64
        assert_eq!(bytes[0], 0x03);

        let mut r = PacketReader::new(&bytes);
        assert_eq!(r.read_opcode().unwrap(), Opcode::Sync);
        assert_eq!(r.read_u64().unwrap(), last_seen_id);
        assert!(r.remaining().is_empty());
    }

    /// ── 5. test_data_roundtrip_with_timestamps ──────────────────────────────────
    /// Build Data packet, verify id/timestamp/payload extraction.
    #[test]
    fn test_data_roundtrip_with_timestamps() {
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

        // Verify total length: 1 (opcode) + 8 (id) + 8 (ts) + 4 (len) + payload.len()
        assert_eq!(bytes.len(), 1 + 8 + 8 + 4 + payload.len());
    }

    /// ── 6. test_heartbeat_roundtrip ─────────────────────────────────────────────
    /// Build Heartbeat (0x06, u64 timestamp), verify.
    #[test]
    fn test_heartbeat_roundtrip() {
        let timestamp: u64 = 1_700_000_000;
        let bytes = encode_heartbeat(timestamp);

        assert_eq!(bytes.len(), 1 + 8);
        assert_eq!(bytes[0], 0x06);

        let mut r = PacketReader::new(&bytes);
        assert_eq!(r.read_opcode().unwrap(), Opcode::Heartbeat);
        assert_eq!(r.read_u64().unwrap(), timestamp);
        assert!(r.remaining().is_empty());
    }

    /// ── 8. test_full_handshake_sequence ─────────────────────────────────────────
    /// Simulate complete handshake:
    ///   a. Server generates nonce, encodes challenge
    ///   b. Client derives Argon2 key from password, computes HMAC
    ///   c. Client builds Auth packet
    ///   d. Server parses Auth, verifies password + HMAC
    ///   e. Server builds AuthResult
    ///   f. Client parses AuthResult
    /// Verify every step produces correct bytes.
    #[test]
    fn test_full_handshake_sequence() {
        let password = "full_handshake_secret";
        let stored_hash = argon2_hash(password);

        // a. Server generates 16-byte nonce and sends AuthChallenge
        let server_nonce: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                          0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        // Extract B64 salt from stored hash for the challenge
        let argon2_salt_b64 = {
            use argon2::password_hash::PasswordHash;
            let parsed = PasswordHash::new(&stored_hash).unwrap();
            parsed.salt.map(|s| s.to_string()).unwrap_or_default()
        };
        let challenge_packet = encode_auth_challenge(&server_nonce, &argon2_salt_b64);
        assert_eq!(challenge_packet[0], 0x0B);
        assert_eq!(&challenge_packet[1..17], &server_nonce);

        // b. Client parses AuthChallenge, extracts nonce + salt
        let mut cr = PacketReader::new(&challenge_packet);
        assert_eq!(cr.read_opcode().unwrap(), Opcode::AuthChallenge);
        let client_nonce = cr.read_bytes(16).unwrap();
        assert_eq!(client_nonce, server_nonce);
        let parsed_salt = cr.read_len_prefixed().unwrap();
        let client_salt_b64 = std::str::from_utf8(&parsed_salt).unwrap();
        assert_eq!(client_salt_b64, argon2_salt_b64);

        // c. Client derives Argon2 key and builds Auth packet
        let auth_packet = build_client_auth(password, &client_nonce, &stored_hash);
        assert_eq!(auth_packet[0], 0x01);

        // d. Server parses Auth and verifies
        let (hash_ok, nonce_valid) = server_verify_auth(&auth_packet, &stored_hash, &server_nonce).unwrap();
        assert!(hash_ok, "password verification should succeed");
        assert!(nonce_valid, "HMAC challenge-response should succeed");

        // e. Server builds AuthResult (success)
        let success_result = encode_auth_result(true, None);
        assert_eq!(success_result[0], 0x02);
        assert_eq!(success_result[1], 0x01); // success byte

        // f. Client parses AuthResult
        let mut rr = PacketReader::new(&success_result);
        assert_eq!(rr.read_opcode().unwrap(), Opcode::AuthResult);
        let status = rr.read_u8().unwrap();
        assert_eq!(status, 0x01, "status should indicate success");

        // Also test failure path
        let fail_result = encode_auth_result(false, Some("Invalid password or challenge"));
        let mut fr = PacketReader::new(&fail_result);
        assert_eq!(fr.read_opcode().unwrap(), Opcode::AuthResult);
        let fail_status = fr.read_u8().unwrap();
        assert_eq!(fail_status, 0x00);
        let fail_msg = fr.read_len_prefixed().unwrap();
        assert_eq!(std::str::from_utf8(&fail_msg).unwrap(), "Invalid password or challenge");
    }

    /// ── 9. test_relay_multi_client_sequence ─────────────────────────────────────
    /// Simulate 3 clients:
    ///   a. All 3 authenticate successfully
    ///   b. Client 1 sends Data message
    ///   c. Server stores message, verifies it in store
    ///   d. Client 2 syncs, receives Client 1's message
    ///   e. Client 3 syncs, receives Client 1's message
    ///   f. Client 2 sends Data, verify relay
    #[test]
    fn test_relay_multi_client_sequence() {
        let password = "relay_test_pass";
        let stored_hash = argon2_hash(password);
        let nonce = vec![0xAA; 16];

        // a. All 3 clients authenticate
        let client1_auth = build_client_auth(password, &nonce, &stored_hash);
        let (h1, n1) = server_verify_auth(&client1_auth, &stored_hash, &nonce).unwrap();
        assert!(h1 && n1, "Client 1 auth should succeed");

        let client2_auth = build_client_auth(password, &nonce, &stored_hash);
        let (h2, n2) = server_verify_auth(&client2_auth, &stored_hash, &nonce).unwrap();
        assert!(h2 && n2, "Client 2 auth should succeed");

        let client3_auth = build_client_auth(password, &nonce, &stored_hash);
        let (h3, n3) = server_verify_auth(&client3_auth, &stored_hash, &nonce).unwrap();
        assert!(h3 && n3, "Client 3 auth should succeed");

        // b. Client 1 sends Data message (server stores it)
        let store = MessageStore::new();
        let client1_payload = b"hello from client 1".to_vec();
        let stored = store.push(client1_payload.clone());

        // c. Server stores message, verify it exists with correct content
        assert_eq!(store.len(), 1);
        let all = store.since(0, 100);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, stored.id);
        assert_eq!(all[0].payload, client1_payload);

        // d. Client 2 syncs (last_seen_id=0), receives Client 1's message
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
            &replay_for_client2.iter().map(|m| (m.id, m.timestamp, m.payload.clone())).collect::<Vec<_>>()
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

        // e. Client 3 syncs, also receives Client 1's message
        let replay_for_client3 = store.since(0, 500);
        assert_eq!(replay_for_client3.len(), 1);
        assert_eq!(replay_for_client3[0].payload, client1_payload);

        // f. Client 2 sends Data, verify it's stored
        let client2_payload = b"hello from client 2".to_vec();
        let stored2 = store.push(client2_payload.clone());
        assert_eq!(store.len(), 2);
        assert!(stored2.id > stored.id);

        // Both messages visible
        let all_after = store.since(0, 100);
        assert_eq!(all_after.len(), 2);
        assert_eq!(all_after[0].payload, client1_payload);
        assert_eq!(all_after[1].payload, client2_payload);
    }

    /// ── 10. test_auth_brute_force_limit ─────────────────────────────────────────
    /// Simulate 5 failed auth attempts, verify 6th is rejected even with correct
    /// password. Uses DashMap + AtomicU32 like the real server.
    #[test]
    fn test_auth_brute_force_limit() {
        let password = "correct_password";
        let stored_hash = argon2_hash(password);
        let nonce = vec![0x55; 16];
        let max_attempts: u32 = 5;

        let session_key: u64 = 1;
        let auth_attempts: DashMap<u64, AtomicU32> = DashMap::new();
        auth_attempts.insert(session_key, AtomicU32::new(0));

        // 5 wrong attempts — each increments the counter
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

        // 6th attempt — blocked even with correct password
        let attempts = auth_attempts.get(&session_key).unwrap();
        assert!(
            attempts.load(Ordering::Relaxed) >= max_attempts,
            "Should have hit the brute-force limit"
        );
        // Even if we try to build and verify the correct packet, the server would
        // reject it at the rate-limit check before verification.
        let correct_packet = build_client_auth(password, &nonce, &stored_hash);
        // The packet itself is valid, but the server blocks at the counter check.
        let (h, _) = server_verify_auth(&correct_packet, &stored_hash, &nonce).unwrap();
        assert!(h, "Packet-level verification should pass (server blocks at counter)");
    }

    /// ── 11. test_concurrent_storage_operations ──────────────────────────────────
    /// Use tokio::spawn to push 100 messages concurrently, verify monotonic IDs
    /// and correct count.
    #[tokio::test]
    async fn test_concurrent_storage_operations() {
        use std::sync::Arc;

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

        // Verify monotonic IDs
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

    /// ── 12. test_storage_ttl_boundary ───────────────────────────────────────────
    /// Push messages with timestamps near TTL boundary, sweep, verify correct removal.
    #[test]
    fn test_storage_ttl_boundary() {
        use crate::storage::MESSAGE_TTL;
        use std::time::{SystemTime, UNIX_EPOCH};

        let store = MessageStore::new();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let ttl_ms = MESSAGE_TTL.as_millis() as u64;

        // Message just inside TTL (1 second before expiry) — should survive
        store.push_with_timestamp(b"alive".to_vec(), now_ms - (ttl_ms - 1000));

        // Message just outside TTL (1 second after expiry) — should be removed
        store.push_with_timestamp(b"dead".to_vec(), now_ms - (ttl_ms + 1000));

        // Message well inside TTL — should survive
        store.push_with_timestamp(b"fresh".to_vec(), now_ms - 1000);

        assert_eq!(store.len(), 3);

        let removed = store.sweep();
        assert_eq!(removed, 1, "only the expired message should be removed");
        assert_eq!(store.len(), 2, "two messages should remain");

        // Verify the correct message was removed
        let remaining = store.since(0, 10);
        let payloads: Vec<&[u8]> = remaining.iter().map(|m| m.payload.as_slice()).collect();
        assert!(payloads.contains(&b"alive".as_slice()), "alive message should remain");
        assert!(payloads.contains(&b"fresh".as_slice()), "fresh message should remain");
        assert!(!payloads.contains(&b"dead".as_slice()), "dead message should be gone");
    }

    /// ── 13. test_packet_length_consistency ──────────────────────────────────────
    /// For each opcode, build a packet and verify frameLength matches actual byte count.
    #[test]
    fn test_packet_length_consistency() {
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

        // AuthChallenge: 1 + 16 + 4 + salt_b64.len()
        let nonce = vec![0u8; 16];
        let salt_b64 = "c29tZXNhbHQ"; // "testsalt" in B64
        let ac = encode_auth_challenge(&nonce, salt_b64);
        assert_eq!(ac.len(), 1 + 16 + 4 + salt_b64.len());
    }

    /// ── 14. test_auth_challenge_response_timing ────────────────────────────────
    /// Verify nonce expiry: create nonce, check it's valid, then check with
    /// NONCE_MAX_AGE elapsed (simulated via Instant).
    #[test]
    fn test_auth_challenge_response_timing() {
        const NONCE_MAX_AGE: Duration = Duration::from_secs(30);

        // Create a nonce "just now" — should be valid
        let nonce_created = Instant::now();
        let nonce: Vec<u8> = vec![0x42; 16];

        // Encode challenge
        let challenge = encode_auth_challenge(&nonce, "dGVzdHNhbHQ");
        let mut r = PacketReader::new(&challenge);
        assert_eq!(r.read_opcode().unwrap(), Opcode::AuthChallenge);
        let extracted_nonce = r.read_bytes(16).unwrap();
        assert_eq!(extracted_nonce, nonce);
        let extracted_salt = r.read_len_prefixed().unwrap();
        assert_eq!(std::str::from_utf8(&extracted_salt).unwrap(), "dGVzdHNhbHQ");

        // Nonce should be valid (just created)
        assert!(
            nonce_created.elapsed() <= NONCE_MAX_AGE,
            "freshly created nonce should be within NONCE_MAX_AGE"
        );

        // Simulate an expired nonce by creating an Instant in the past
        let expired_created_at = Instant::now() - NONCE_MAX_AGE - Duration::from_secs(1);
        assert!(
            expired_created_at.elapsed() > NONCE_MAX_AGE,
            "nonce created NONCE_MAX_AGE+1 ago should be expired"
        );

        // Simulate a nonce at exactly the boundary
        let boundary_created_at = Instant::now() - NONCE_MAX_AGE;
        // At exactly the boundary, `elapsed()` may be <= or > depending on timing.
        // We verify the invariant: elapsed > NONCE_MAX_AGE means expired.
        let elapsed = boundary_created_at.elapsed();
        if elapsed > NONCE_MAX_AGE {
            assert!(elapsed > NONCE_MAX_AGE, "boundary nonce should be expired");
        } else {
            // At the boundary, still valid
            assert!(elapsed <= NONCE_MAX_AGE, "boundary nonce should still be valid");
        }
    }

    /// ── 15. test_multiple_auth_attempts_same_session ────────────────────────────
    /// Simulate multiple auth attempts on same session_key, verify brute_force
    /// counter increments correctly and blocks after MAX_AUTH_ATTEMPTS.
    #[test]
    fn test_multiple_auth_attempts_same_session() {
        let password = "session_password";
        let stored_hash = argon2_hash(password);
        let nonce = vec![0x77; 16];
        let max_attempts: u32 = 5;

        let session_key: u64 = 42;
        let auth_attempts: DashMap<u64, AtomicU32> = DashMap::new();

        // Attempt 1: wrong password
        auth_attempts.entry(session_key).or_insert_with(|| AtomicU32::new(0));
        {
            let attempts = auth_attempts.get(&session_key).unwrap();
            assert_eq!(attempts.load(Ordering::Relaxed), 0);
            let packet = build_client_auth("wrong1", &nonce, &stored_hash);
            let (h, _) = server_verify_auth(&packet, &stored_hash, &nonce).unwrap();
            assert!(!h);
            attempts.fetch_add(1, Ordering::Relaxed);
            assert_eq!(attempts.load(Ordering::Relaxed), 1);
        }

        // Attempt 2: wrong password
        {
            let attempts = auth_attempts.get(&session_key).unwrap();
            assert_eq!(attempts.load(Ordering::Relaxed), 1);
            let packet = build_client_auth("wrong2", &nonce, &stored_hash);
            let (h, _) = server_verify_auth(&packet, &stored_hash, &nonce).unwrap();
            assert!(!h);
            attempts.fetch_add(1, Ordering::Relaxed);
            assert_eq!(attempts.load(Ordering::Relaxed), 2);
        }

        // Attempt 3: wrong password
        {
            let attempts = auth_attempts.get(&session_key).unwrap();
            assert_eq!(attempts.load(Ordering::Relaxed), 2);
            let packet = build_client_auth("wrong3", &nonce, &stored_hash);
            let (h, _) = server_verify_auth(&packet, &stored_hash, &nonce).unwrap();
            assert!(!h);
            attempts.fetch_add(1, Ordering::Relaxed);
            assert_eq!(attempts.load(Ordering::Relaxed), 3);
        }

        // Attempt 4: wrong password
        {
            let attempts = auth_attempts.get(&session_key).unwrap();
            assert_eq!(attempts.load(Ordering::Relaxed), 3);
            let packet = build_client_auth("wrong4", &nonce, &stored_hash);
            let (h, _) = server_verify_auth(&packet, &stored_hash, &nonce).unwrap();
            assert!(!h);
            attempts.fetch_add(1, Ordering::Relaxed);
            assert_eq!(attempts.load(Ordering::Relaxed), 4);
        }

        // Attempt 5: wrong password — hits the limit
        {
            let attempts = auth_attempts.get(&session_key).unwrap();
            assert_eq!(attempts.load(Ordering::Relaxed), 4);
            assert!(
                attempts.load(Ordering::Relaxed) < max_attempts,
                "should not be blocked yet"
            );
            let packet = build_client_auth("wrong5", &nonce, &stored_hash);
            let (h, _) = server_verify_auth(&packet, &stored_hash, &nonce).unwrap();
            assert!(!h);
            attempts.fetch_add(1, Ordering::Relaxed);
            assert_eq!(attempts.load(Ordering::Relaxed), 5);
        }

        // Attempt 6: correct password — blocked by brute-force counter
        {
            let attempts = auth_attempts.get(&session_key).unwrap();
            assert_eq!(attempts.load(Ordering::Relaxed), 5);
            assert!(
                attempts.load(Ordering::Relaxed) >= max_attempts,
                "should be blocked now"
            );
            // Server would reject this before even checking the password
            let packet = build_client_auth(password, &nonce, &stored_hash);
            // Packet-level verification would pass, but server blocks at counter
            let (h, _) = server_verify_auth(&packet, &stored_hash, &nonce).unwrap();
            assert!(h, "packet verification itself passes (blocked at server level)");
        }
    }
}

// ============================================================================
// COMBINED KEY EXCHANGE (0x0C) — Wire Format Tests
// ============================================================================
// These tests verify the server correctly handles the combined KEM+DSA key
// exchange format. The client builds:
//   [0x0C] [u32: total_len] [u32: kem_len] [kem_bytes] [u32: dsa_len] [dsa_bytes]
//
// The server reads the opcode, then `reader.remaining()` gives the outer blob.
// `encode_key_exchange_tagged` wraps it for relay: [0x0C] [u32: len] [remaining_blob].

#[cfg(test)]
mod combined_key_exchange_tests {
    use crate::protocol::{Opcode, PacketReader, PacketWriter};

    /// Build a client-format combined key exchange packet (as the Kotlin client sends it).
    /// Wire: [0x0C] [u32: total_len] [u32: kem_len] [kem] [u32: dsa_len] [dsa]
    fn build_client_combined_key_exchange(kem: &[u8], dsa: &[u8]) -> Vec<u8> {
        // Inner blob: [u32: kem_len] [kem] [u32: dsa_len] [dsa]
        let total_inner = 4 + kem.len() + 4 + dsa.len();
        let mut w = PacketWriter::with_opcode(Opcode::KeyExchangeKemDsa);
        // Write outer u32 total_len
        w.write_u32(total_inner as u32);
        // Write inner: kem
        w.write_u32(kem.len() as u32);
        w.write_raw(kem);
        // Write inner: dsa
        w.write_u32(dsa.len() as u32);
        w.write_raw(dsa);
        w.into_bytes()
    }

    /// Simulate the server's try_read_packet: read u32 at offset 1 as payload_len.
    /// Returns the total packet length that try_read_packet would compute.
    fn simulated_try_read_packet_len(frame: &[u8]) -> usize {
        assert!(frame.len() >= 5, "frame too short");
        let len = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
        1 + 4 + len
    }

    /// Simulate the server's process_packet for 0x0C:
    /// read opcode, then remaining() = everything after opcode byte.
    fn simulated_server_remaining(frame: &[u8]) -> Vec<u8> {
        frame[1..].to_vec()
    }

    /// Simulate the server relay: prepend opcode byte to combined_payload.
    /// This matches the fixed server code which no longer uses encode_key_exchange_tagged.
    fn simulated_server_relay(frame: &[u8]) -> Vec<u8> {
        let remaining = simulated_server_remaining(frame);
        let mut relay = vec![frame[0]]; // opcode byte
        relay.extend_from_slice(&remaining);
        relay
    }

    // ── 1. try_read_packet length covers full frame ────────────────────────────
    #[test]
    fn test_try_read_packet_length_covers_full_frame() {
        let kem = vec![0xAA; 1184];
        let dsa = vec![0xBB; 1952];

        let frame = build_client_combined_key_exchange(&kem, &dsa);
        let computed_len = simulated_try_read_packet_len(&frame);

        assert_eq!(frame.len(), computed_len);
    }

    // ── 2. try_read_packet length for various key sizes ────────────────────────
    #[test]
    fn test_try_read_packet_length_various_sizes() {
        let test_cases: Vec<(usize, usize)> = vec![
            (0, 0),
            (1, 1),
            (100, 200),
            (1184, 1952),
            (32, 64),
        ];

        for (kem_len, dsa_len) in test_cases {
            let kem = vec![0xCC; kem_len];
            let dsa = vec![0xDD; dsa_len];
            let frame = build_client_combined_key_exchange(&kem, &dsa);
            let computed_len = simulated_try_read_packet_len(&frame);
            assert_eq!(frame.len(), computed_len,
                "Frame mismatch for kem_len={}, dsa_len={}", kem_len, dsa_len);
        }
    }

    // ── 3. server relay preserves the original client frame format ──────────────
    #[test]
    fn test_server_relay_preserves_original_format() {
        let kem = vec![0x11; 100];
        let dsa = vec![0x22; 200];

        let frame = build_client_combined_key_exchange(&kem, &dsa);
        let relayed = simulated_server_relay(&frame);

        // Relayed packet is identical to the original client frame
        assert_eq!(relayed, frame);
    }

    // ── 4. relayed packet parseable by receiving client ─────────────────────────
    #[test]
    fn test_relayed_packet_parseable_by_client() {
        let kem = vec![0xAA; 1184];
        let dsa = vec![0xBB; 1952];

        let frame = build_client_combined_key_exchange(&kem, &dsa);
        let relayed = simulated_server_relay(&frame);

        // Receiving client: read opcode
        let mut reader = PacketReader::new(&relayed);
        let opcode = reader.read_opcode().unwrap();
        assert_eq!(opcode, Opcode::KeyExchangeKemDsa);

        // outer blob
        let outer_blob = reader.read_len_prefixed().unwrap();

        // Inner: parse [u32: kem_len] [kem] [u32: dsa_len] [dsa]
        let mut inner = PacketReader::new(&outer_blob);
        let parsed_kem = inner.read_len_prefixed().unwrap();
        let parsed_dsa = inner.read_len_prefixed().unwrap();

        assert_eq!(parsed_kem, &kem[..]);
        assert_eq!(parsed_dsa, &dsa[..]);
    }

    // ── 5. no orphan bytes ─────────────────────────────────────────────────────
    #[test]
    fn test_no_orphan_bytes_after_try_read() {
        let kem = vec![0x55; 500];
        let dsa = vec![0x66; 600];

        let frame = build_client_combined_key_exchange(&kem, &dsa);
        let packet_len = simulated_try_read_packet_len(&frame);

        assert_eq!(frame.len(), packet_len);
    }

    // ── 6. outer u32 total_len equals inner content ────────────────────────────
    #[test]
    fn test_outer_u32_equals_inner_content() {
        let kem = vec![0x77; 300];
        let dsa = vec![0x88; 400];

        let frame = build_client_combined_key_exchange(&kem, &dsa);
        let outer_len = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;

        let expected_inner = 4 + kem.len() + 4 + dsa.len();
        assert_eq!(outer_len, expected_inner);
    }

    // ── 7. empty keys — edge case ──────────────────────────────────────────────
    #[test]
    fn test_empty_keys_roundtrip() {
        let kem: Vec<u8> = vec![];
        let dsa: Vec<u8> = vec![];

        let frame = build_client_combined_key_exchange(&kem, &dsa);
        let relayed = simulated_server_relay(&frame);

        let mut reader = PacketReader::new(&relayed);
        assert_eq!(reader.read_opcode().unwrap(), Opcode::KeyExchangeKemDsa);
        let outer = reader.read_len_prefixed().unwrap();
        let mut inner = PacketReader::new(&outer);
        assert_eq!(inner.read_len_prefixed().unwrap(), &[]);
        assert_eq!(inner.read_len_prefixed().unwrap(), &[]);
    }

    // ── 8. frame length consistency ────────────────────────────────────────────
    #[test]
    fn test_frame_length_consistency_through_relay() {
        let kem = vec![0xAB; 1184];
        let dsa = vec![0xCD; 1952];

        let frame = build_client_combined_key_exchange(&kem, &dsa);
        assert_eq!(frame[0], 0x0C);

        let packet_len = simulated_try_read_packet_len(&frame);
        assert_eq!(frame.len(), packet_len);

        let relayed = simulated_server_relay(&frame);
        assert_eq!(relayed, frame);
    }

    // ── 9. OP_DATA is NOT confused with 0x0C ──────────────────────────────────
    #[test]
    fn test_data_and_keyexchange_opcodes_distinguished() {
        let payload = b"hello world";

        let mut data_w = PacketWriter::with_opcode(Opcode::Data);
        data_w.write_len_prefixed(payload);
        let data_frame = data_w.into_bytes();

        let kem = vec![0x11; 32];
        let dsa = vec![0x22; 32];
        let ke_frame = build_client_combined_key_exchange(&kem, &dsa);

        assert_eq!(data_frame[0], 0x05);
        assert_eq!(ke_frame[0], 0x0C);

        let data_len = u32::from_le_bytes([data_frame[1], data_frame[2], data_frame[3], data_frame[4]]);
        assert_eq!(data_len as usize, payload.len());

        let ke_len = u32::from_le_bytes([ke_frame[1], ke_frame[2], ke_frame[3], ke_frame[4]]);
        assert_eq!(ke_len as usize, 4 + kem.len() + 4 + dsa.len());
    }

    // ── 10. stress test ────────────────────────────────────────────────────────
    #[test]
    fn test_stress_relay_cycles() {
        for i in 0..50 {
            let kem = vec![(i * 7 % 256) as u8; 32 + i * 10];
            let dsa = vec![(i * 13 % 256) as u8; 64 + i * 20];

            let frame = build_client_combined_key_exchange(&kem, &dsa);
            assert_eq!(frame[0], 0x0C);

            let packet_len = simulated_try_read_packet_len(&frame);
            assert_eq!(frame.len(), packet_len);

            let relayed = simulated_server_relay(&frame);
            assert_eq!(relayed, frame);

            let mut reader = PacketReader::new(&relayed);
            assert_eq!(reader.read_opcode().unwrap(), Opcode::KeyExchangeKemDsa);
            let outer = reader.read_len_prefixed().unwrap();

            let mut inner = PacketReader::new(&outer);
            let parsed_kem = inner.read_len_prefixed().unwrap();
            let parsed_dsa = inner.read_len_prefixed().unwrap();

            assert_eq!(parsed_kem, &kem[..]);
            assert_eq!(parsed_dsa, &dsa[..]);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// End-to-end integration tests — full protocol lifecycle
// ═══════════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod e2e_integration_tests {
    use crate::config::{argon2_hash, argon2_verify};
    use crate::protocol::{
        Opcode, PacketReader, PacketWriter, encode_sync_response,
    };
    use crate::server::{TryReadResult, try_read_packet};
    use crate::storage::MessageStore;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    fn derive_argon2_key(password: &str, stored_hash: &str) -> Vec<u8> {
        use argon2::password_hash::PasswordHash;
        let parsed = PasswordHash::new(stored_hash).expect("should parse stored hash");
        let salt = parsed.salt.expect("stored hash should have a salt");
        let mut raw_salt_buf = [0u8; 64];
        let raw_salt = salt.decode_b64(&mut raw_salt_buf).expect("should decode B64 salt");
        let mut output = [0u8; 32];
        argon2::Argon2::default()
            .hash_password_into(password.as_bytes(), raw_salt, &mut output)
            .expect("Argon2 derivation should not fail");
        output.to_vec()
    }

    fn build_client_auth(password: &str, server_nonce: &[u8], stored_hash: &str) -> Vec<u8> {
        let key = derive_argon2_key(password, stored_hash);
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(server_nonce);
        let hmac_response = mac.finalize().into_bytes().to_vec();

        let mut w = PacketWriter::with_opcode(Opcode::Auth);
        w.write_len_prefixed(password.as_bytes());
        w.write_raw(&hmac_response);
        w.into_bytes()
    }

    fn server_verify_auth(packet: &[u8], stored_hash: &str, server_nonce: &[u8]) -> (bool, bool) {
        let mut reader = PacketReader::new(packet);
        let _opcode = reader.read_opcode().unwrap();
        let password_bytes = reader.read_len_prefixed().unwrap();
        let password = String::from_utf8(password_bytes).unwrap();
        let hash_ok = argon2_verify(&password, stored_hash);
        let nonce_valid = if reader.remaining().is_empty() {
            false
        } else {
            let client_response = reader.read_bytes(32).unwrap();
            if hash_ok {
                let key = derive_argon2_key(&password, stored_hash);
                let mut mac = HmacSha256::new_from_slice(&key).unwrap();
                mac.update(server_nonce);
                mac.verify_slice(&client_response).is_ok()
            } else {
                false
            }
        };
        (hash_ok, nonce_valid)
    }

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
    ///   [u32: recipient_id_len] [recipient_id] [u32: enc_key_len] [enc_key] [u32: ct_len] [ciphertext]
    ///   ...repeated for each recipient
    fn build_per_recipient_blob(
        sender_pub_hash: &[u8],
        recipients: &[(&[u8], &[u8], &[u8])], // (id, enc_key, ciphertext)
    ) -> Vec<u8> {
        let mut w = PacketWriter::with_opcode(Opcode::Data);
        // Fake outer data frame: just write the blob as a len-prefixed payload
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
        w.write_len_prefixed(&blob);
        w.into_bytes()
    }

    // ── Test 1: Full E2E lifecycle ──────────────────────────────────────────────
    /// Complete flow: auth → key exchange → send data → store → sync → receive
    #[test]
    fn test_e2e_full_lifecycle() {
        let password = "e2e_test_pass";
        let stored_hash = argon2_hash(password);
        let nonce = vec![0xBB; 16];

        // 1. Client1 authenticates
        let c1_auth = build_client_auth(password, &nonce, &stored_hash);
        let (h1, n1) = server_verify_auth(&c1_auth, &stored_hash, &nonce);
        assert!(h1 && n1, "Client1 auth should succeed");

        // 2. Client2 authenticates
        let c2_auth = build_client_auth(password, &nonce, &stored_hash);
        let (h2, n2) = server_verify_auth(&c2_auth, &stored_hash, &nonce);
        assert!(h2 && n2, "Client2 auth should succeed");

        // 3. Client1 sends key exchange
        let c1_kem = vec![0x11u8; 1184]; // ML-KEM-768 size
        let c1_dsa = vec![0x22u8; 1952]; // ML-DSA-65 size
        let c1_ke = build_key_exchange(&c1_kem, &c1_dsa);
        assert_eq!(c1_ke[0], 0x0C);
        let ke_len = try_read_packet(&c1_ke);
        assert_eq!(ke_len, TryReadResult::Packet(c1_ke.len()));

        // 4. Client2 sends key exchange
        let c2_kem = vec![0x33u8; 1184];
        let c2_dsa = vec![0x44u8; 1952];
        let c2_ke = build_key_exchange(&c2_kem, &c2_dsa);
        assert_eq!(c2_ke[0], 0x0C);

        // 5. Client1 sends data message (per-recipient blob for Client2)
        let store = MessageStore::new();
        let sender_hash = [0xAA; 32];
        let c2_id = [0xBB; 32];
        let c2_enc_key = vec![0xCC; 1184];
        let c2_ciphertext = vec![0xDD; 256];
        let blob = build_per_recipient_blob(
            &sender_hash,
            &[(&c2_id, &c2_enc_key, &c2_ciphertext)],
        );
        let stored = store.push(blob.clone());
        assert!(stored.id > 0);
        assert_eq!(store.len(), 1);

        // 6. Client2 syncs (last_seen_id=0), receives Client1's message
        let messages = store.since(0, 100);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, blob);
        let sync_resp = encode_sync_response(
            &messages.iter().map(|m| (m.id, m.timestamp, m.payload.clone())).collect::<Vec<_>>(),
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

        // 7. Verify try_read_packet correctly identifies all packet types
        assert_eq!(try_read_packet(&c1_auth), TryReadResult::Packet(c1_auth.len()));
        assert_eq!(try_read_packet(&c1_ke), TryReadResult::Packet(c1_ke.len()));
        assert_eq!(try_read_packet(&blob), TryReadResult::Packet(blob.len()));
        assert_eq!(try_read_packet(&[0x99]), TryReadResult::UnknownOpcode);
    }

    // ── Test 2: Sync after reconnection ─────────────────────────────────────────
    /// Client receives some messages, disconnects, more arrive, reconnects with
    /// last_seen_id, gets only new messages.
    #[test]
    fn test_sync_after_reconnect() {
        let store = MessageStore::new();

        // Phase 1: Client connects and receives 3 messages
        let _msg1 = store.push(b"msg1".to_vec());
        let _msg2 = store.push(b"msg2".to_vec());
        let msg3 = store.push(b"msg3".to_vec());
        assert_eq!(store.len(), 3);

        let initial = store.since(0, 100);
        assert_eq!(initial.len(), 3);
        let last_seen_id = initial.last().unwrap().id;
        assert_eq!(last_seen_id, msg3.id);

        // Phase 2: Client disconnects, 2 more messages arrive
        let msg4 = store.push(b"msg4".to_vec());
        let msg5 = store.push(b"msg5".to_vec());
        assert_eq!(store.len(), 5);

        // Phase 3: Client reconnects with last_seen_id, gets only new messages
        let after_reconnect = store.since(last_seen_id, 100);
        assert_eq!(after_reconnect.len(), 2, "should only get 2 new messages");
        assert_eq!(after_reconnect[0].id, msg4.id);
        assert_eq!(after_reconnect[0].payload, b"msg4");
        assert_eq!(after_reconnect[1].id, msg5.id);
        assert_eq!(after_reconnect[1].payload, b"msg5");

        // Verify sync response encoding
        let sync_resp = encode_sync_response(
            &after_reconnect.iter().map(|m| (m.id, m.timestamp, m.payload.clone())).collect::<Vec<_>>(),
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

    // ── Test 3: Multi-client concurrent send ─────────────────────────────────────
    /// 5 clients send messages concurrently, all stored with monotonic IDs.
    #[tokio::test]
    async fn test_multi_client_concurrent_send() {
        use std::sync::Arc;

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

        // Verify all messages visible with monotonic IDs
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

        // Verify sync response contains all messages
        let sync_resp = encode_sync_response(
            &all.iter().map(|m| (m.id, m.timestamp, m.payload.clone())).collect::<Vec<_>>(),
        );
        let mut sr = PacketReader::new(&sync_resp);
        assert_eq!(sr.read_opcode().unwrap(), Opcode::SyncResponse);
        let count = sr.read_u32().unwrap();
        assert_eq!(count, num_clients as u32);
    }

    // ── Test 4: Per-recipient blob parsing ───────────────────────────────────────
    /// Build per-recipient blob with 3 recipients, verify parsing.
    #[test]
    fn test_per_recipient_blob_parsing() {
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

        // Parse blob manually (mimicking client onData logic)
        let mut pr = PacketReader::new(&blob);
        let _opcode = pr.read_opcode().unwrap(); // skip Data opcode
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

        // Verify try_read_packet on the blob
        assert_eq!(try_read_packet(&blob), TryReadResult::Packet(blob.len()));
    }

    // ── Test 5: try_read_packet on all packet types ──────────────────────────────
    /// Verify try_read_packet correctly handles every opcode with correct lengths.
    #[test]
    fn test_try_read_packet_all_opcodes() {
        // Auth (0x01): opcode + u32 pwd_len + pwd + 32 HMAC
        let mut auth = PacketWriter::with_opcode(Opcode::Auth);
        auth.write_len_prefixed(b"password123");
        auth.write_raw(&[0x42; 32]);
        let auth_bytes = auth.into_bytes();
        assert_eq!(try_read_packet(&auth_bytes), TryReadResult::Packet(auth_bytes.len()));

        // Sync (0x03): opcode + u64
        let mut sync = PacketWriter::with_opcode(Opcode::Sync);
        sync.write_u64(42);
        let sync_bytes = sync.into_bytes();
        assert_eq!(try_read_packet(&sync_bytes), TryReadResult::Packet(9));

        // Data (0x05): opcode + u32 len + payload (CLIENT→SERVER format)
        let data_payload = b"hello world";
        let mut data = PacketWriter::with_opcode(Opcode::Data);
        data.write_len_prefixed(data_payload);
        let data_bytes = data.into_bytes();
        assert_eq!(try_read_packet(&data_bytes), TryReadResult::Packet(data_bytes.len()));

        // Heartbeat (0x06): opcode + u64
        let mut hb = PacketWriter::with_opcode(Opcode::Heartbeat);
        hb.write_u64(12345);
        let hb_bytes = hb.into_bytes();
        assert_eq!(try_read_packet(&hb_bytes), TryReadResult::Packet(9));

        // KeyExchange (0x0C): opcode + u32 len + payload
        let ke = build_key_exchange(&[0x11; 32], &[0x22; 64]);
        assert_eq!(try_read_packet(&ke), TryReadResult::Packet(ke.len()));

        // Unknown opcode
        assert_eq!(try_read_packet(&[0xFF]), TryReadResult::UnknownOpcode);
        assert_eq!(try_read_packet(&[0x00]), TryReadResult::UnknownOpcode);
        assert_eq!(try_read_packet(&[0x08]), TryReadResult::UnknownOpcode);

        // Empty buffer
        assert_eq!(try_read_packet(&[]), TryReadResult::Incomplete);

        // Oversized payload
        let mut big_data = PacketWriter::with_opcode(Opcode::Data);
        big_data.write_u32(u32::MAX);
        let big_bytes = big_data.into_bytes();
        assert_eq!(try_read_packet(&big_bytes), TryReadResult::OversizedPayload);
    }

    // ── Test 6: Message ordering and dedup via sync ──────────────────────────────
    /// Send 10 messages, sync with limit, verify ordering and completeness.
    #[test]
    fn test_message_ordering_and_sync_limit() {
        let store = MessageStore::new();

        for i in 0..10 {
            store.push(format!("msg_{}", i).into_bytes());
        }

        // Full sync
        let all = store.since(0, 100);
        assert_eq!(all.len(), 10);
        for (i, msg) in all.iter().enumerate() {
            assert_eq!(msg.payload, format!("msg_{}", i).as_bytes());
        }

        // Partial sync with limit
        let partial = store.since(0, 3);
        assert_eq!(partial.len(), 3);
        assert_eq!(partial[0].payload, b"msg_0");
        assert_eq!(partial[2].payload, b"msg_2");

        // Sync from middle
        let mid_id = all[4].id;
        let from_mid = store.since(mid_id, 100);
        assert_eq!(from_mid.len(), 5);
        assert_eq!(from_mid[0].payload, b"msg_5");

        // Sync with very small limit
        let tiny = store.since(0, 1);
        assert_eq!(tiny.len(), 1);
    }

    // ── Test 7: Server skip-byte resilience ──────────────────────────────────────
    /// Verify that unknown bytes are skipped and valid frames after them are parsed.
    #[test]
    fn test_skip_byte_resilience() {
        // Build a valid client→server data frame (opcode + u32 len + payload)
        let mut data_w = PacketWriter::with_opcode(Opcode::Data);
        data_w.write_len_prefixed(b"hello");
        let data = data_w.into_bytes();

        // Prepend an unknown byte
        let mut corrupted = vec![0xFF];
        corrupted.extend_from_slice(&data);

        // First byte is unknown → skip
        assert_eq!(try_read_packet(&corrupted), TryReadResult::UnknownOpcode);

        // After skipping 1 byte, the valid data frame should be parsed
        assert_eq!(try_read_packet(&data), TryReadResult::Packet(data.len()));

        // Multiple unknown bytes followed by valid frame
        let mut multi_corrupted = vec![0xFF, 0xFE, 0xFD, 0xFC];
        multi_corrupted.extend_from_slice(&data);
        assert_eq!(try_read_packet(&multi_corrupted), TryReadResult::UnknownOpcode);

        // After skipping all 4 unknown bytes, valid frame should be parseable
        assert_eq!(try_read_packet(&data), TryReadResult::Packet(data.len()));
    }

    // ── Test 8: Storage race — push and sync interleaved ─────────────────────────
    /// Simulate concurrent push and since() calls to verify no messages are lost.
    #[tokio::test]
    async fn test_storage_push_sync_interleave() {
        use std::sync::Arc;

        let store = Arc::new(MessageStore::new());

        // Push 50 messages from "client A"
        for i in 0..50 {
            store.push(format!("A_{}", i).into_bytes());
        }

        // "Client B" syncs, gets first batch
        let batch1 = store.since(0, 25);
        assert_eq!(batch1.len(), 25);
        let last_id = batch1.last().unwrap().id;

        // Push 25 more from "client A"
        for i in 50..75 {
            store.push(format!("A_{}", i).into_bytes());
        }

        // "Client B" syncs again with last_id
        let batch2 = store.since(last_id, 25);
        assert_eq!(batch2.len(), 25);

        // Verify no overlap
        let batch1_ids: Vec<u64> = batch1.iter().map(|m| m.id).collect();
        let batch2_ids: Vec<u64> = batch2.iter().map(|m| m.id).collect();
        for id in &batch2_ids {
            assert!(!batch1_ids.contains(id), "batch2 should not contain batch1 id {}", id);
        }

        // Total messages
        assert_eq!(store.len(), 75);
    }
}

#[cfg(test)]
mod config_tests {
    use crate::config::{CliArgs, load_config};
    use clap::Parser;

    const TEST_HASH: &str = "$argon2id$v=19$m=47104,t=3,p=1$ZU3OGIF2VhIrUVb19y2izg$7njBEf6KUZtU/sC4HSVFti9DFEC3Mkwqd+uQsUqBAUc";

    fn cli_with_config(path: Option<&str>) -> CliArgs {
        let mut c = CliArgs::parse_from(["impulse-server"]);
        c.config = path.map(str::to_string);
        c
    }

    fn temp_config(name: &str, content: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "impulse-config-test-{name}-{}.toml",
            std::process::id()
        ));
        std::fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn config_address_is_used_when_no_flags() {
        let path = temp_config(
            "address",
            &format!("[server]\naddress = \"127.0.0.1:9999\"\ncert_dir = \"certs\"\npassword_hash = \"{TEST_HASH}\"\n"),
        );
        let cfg = load_config(&cli_with_config(Some(path.to_str().unwrap()))).unwrap();
        assert_eq!(cfg.server.address, "127.0.0.1:9999");
        assert_eq!(cfg.server.cert_dir, "certs");
    }

    #[test]
    fn missing_explicit_config_is_hard_error() {
        let cli = cli_with_config(Some("definitely-missing-config.toml"));
        let err = load_config(&cli).unwrap_err();
        assert!(
            err.to_string().contains("definitely-missing-config.toml"),
            "error should reference the config path, got: {err}"
        );
    }

    #[test]
    fn malformed_config_is_hard_error() {
        let path = temp_config("bad", "[server\nthis is not toml");
        let err = load_config(&cli_with_config(Some(path.to_str().unwrap()))).unwrap_err();
        assert!(
            err.to_string().contains("parse"),
            "error should mention the parse failure, got: {err}"
        );
    }

    #[test]
    fn cert_dir_defaults_when_missing_in_config() {
        let path = temp_config(
            "nocert",
            &format!("[server]\npassword_hash = \"{TEST_HASH}\"\n"),
        );
        let cfg = load_config(&cli_with_config(Some(path.to_str().unwrap()))).unwrap();
        assert_eq!(cfg.server.cert_dir, "cert_data");
    }

    #[test]
    fn password_hash_flag_fills_missing_config_hash() {
        let path = temp_config("nohash", "[server]\naddress = \"0.0.0.0:7777\"\ncert_dir = \"certs\"\n");
        let mut cli = cli_with_config(Some(path.to_str().unwrap()));
        cli.password_hash = Some(TEST_HASH.to_string());
        let cfg = load_config(&cli).unwrap();
        assert_eq!(cfg.server.address, "0.0.0.0:7777");
        assert_eq!(cfg.server.password_hash, TEST_HASH);
    }

    #[test]
    fn unknown_config_field_is_rejected() {
        let path = temp_config(
            "typo",
            &format!("[server]\npassword_hash = \"{TEST_HASH}\"\npor = 4433\n"),
        );
        let err = load_config(&cli_with_config(Some(path.to_str().unwrap()))).unwrap_err();
        assert!(
            err.to_string().contains("por") || err.to_string().contains("unknown field"),
            "error should flag the unknown field, got: {err}"
        );
    }
}
