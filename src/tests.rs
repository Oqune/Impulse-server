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
