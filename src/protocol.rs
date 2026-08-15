//! Binary wire protocol for the WebTransport relay.
//!
//! All frames are length-prefixed binary packets exchanged over a WebTransport
//! bidirectional stream. Every packet starts with a single opcode byte, followed
//! by opcode-specific binary fields (all integers little-endian).
//!
//! The server never decrypts payloads; it only forwards opaque bytes.
//!
//! Opcodes:
//! * `0x01` Auth          — client → server: password hash (UTF-8).
//! * `0x02` AuthResult    — server → client: status byte + optional message.
//! * `0x03` Sync          — client → server: `last_seen_id` (u64).
//! * `0x04` SyncResponse  — server → client: count (u32) + messages.
//! * `0x05` Data          — client → server: len (u32) + payload;
//!   server → client: id (u64) + timestamp (u64) + len + payload.
//! * `0x06` Heartbeat     — either direction: client timestamp (u64).
//! * `0x07` NewCertHash   — server → client: 32 raw SHA-256 bytes + expiry (u64).
//! * `0x08` Disconnect    — either direction: no payload.
//! * `0x0B` AuthChallenge — server → client: 16-byte random nonce.
//! * `0x0C` KeyExchangeKemDsa — either direction: combined KEM + DSA public keys.

pub mod framing;
pub mod limits;

/// Packet opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Auth = 0x01,
    AuthResult = 0x02,
    Sync = 0x03,
    SyncResponse = 0x04,
    Data = 0x05,
    Heartbeat = 0x06,
    NewCertHash = 0x07,
    Disconnect = 0x08,
    AuthChallenge = 0x0B,
    KeyExchangeKemDsa = 0x0C,
}

impl Opcode {
    /// Parse an opcode from its byte representation.
    pub fn from_u8(value: u8) -> Option<Opcode> {
        match value {
            0x01 => Some(Opcode::Auth),
            0x02 => Some(Opcode::AuthResult),
            0x03 => Some(Opcode::Sync),
            0x04 => Some(Opcode::SyncResponse),
            0x05 => Some(Opcode::Data),
            0x06 => Some(Opcode::Heartbeat),
            0x07 => Some(Opcode::NewCertHash),
            0x08 => Some(Opcode::Disconnect),
            0x0B => Some(Opcode::AuthChallenge),
            0x0C => Some(Opcode::KeyExchangeKemDsa),
            _ => None,
        }
    }

    /// The wire byte for this opcode.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Human-readable opcode name for logs and the TUI.
    pub fn display_name(self) -> &'static str {
        match self {
            Opcode::Auth => "Auth",
            Opcode::AuthResult => "AuthResult",
            Opcode::Sync => "Sync",
            Opcode::SyncResponse => "SyncResponse",
            Opcode::Data => "Data",
            Opcode::Heartbeat => "Heartbeat",
            Opcode::NewCertHash => "NewCertHash",
            Opcode::Disconnect => "Disconnect",
            Opcode::AuthChallenge => "AuthChallenge",
            Opcode::KeyExchangeKemDsa => "KeyExchangeKemDsa",
        }
    }
}

/// Errors produced while decoding binary packets.
#[derive(Debug)]
pub enum ProtocolError {
    /// Not enough bytes available to read the requested field.
    UnexpectedEof,
    /// The leading byte is not a known opcode.
    UnknownOpcode(u8),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::UnexpectedEof => write!(f, "packet truncated"),
            ProtocolError::UnknownOpcode(b) => write!(f, "unknown opcode 0x{b:02x}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// A small buffered binary reader over a byte slice, all integers little-endian.
pub struct PacketReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PacketReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Read a single opcode byte and validate it.
    pub fn read_opcode(&mut self) -> Result<Opcode, ProtocolError> {
        let b = self.read_u8()?;
        Opcode::from_u8(b).ok_or(ProtocolError::UnknownOpcode(b))
    }

    pub fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        if self.pos + 1 > self.buf.len() {
            return Err(ProtocolError::UnexpectedEof);
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        if self.pos + 4 > self.buf.len() {
            return Err(ProtocolError::UnexpectedEof);
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn read_u64(&mut self) -> Result<u64, ProtocolError> {
        if self.pos + 8 > self.buf.len() {
            return Err(ProtocolError::UnexpectedEof);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Read exactly `n` bytes as a `Vec<u8>`.
    pub fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, ProtocolError> {
        if self.pos + n > self.buf.len() {
            return Err(ProtocolError::UnexpectedEof);
        }
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }

    /// Read a length-prefixed (u32) byte blob.
    pub fn read_len_prefixed(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let n = self.read_u32()? as usize;
        const MAX_LEN_PREFIXED: usize = 1_000_000;
        if n > MAX_LEN_PREFIXED {
            return Err(ProtocolError::UnexpectedEof);
        }
        self.read_bytes(n)
    }

    /// Remaining (unread) bytes in the buffer.
    pub fn remaining(&self) -> &[u8] {
        &self.buf[self.pos..]
    }
}

/// A buffered binary writer producing little-endian wire bytes.
pub struct PacketWriter {
    buf: Vec<u8>,
}

impl Default for PacketWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(64),
        }
    }

    /// Start a packet with the given opcode byte.
    pub fn with_opcode(op: Opcode) -> Self {
        let mut w = Self::new();
        w.buf.push(op.as_u8());
        w
    }

    pub fn write_u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn write_u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn write_u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Append a length-prefixed (u32) byte blob.
    pub fn write_len_prefixed(&mut self, data: &[u8]) -> &mut Self {
        debug_assert!(data.len() <= limits::MAX_PAYLOAD_BYTES);
        self.write_u32(data.len() as u32);
        self.buf.extend_from_slice(data);
        self
    }

    /// Append raw bytes without a length prefix.
    pub fn write_raw(&mut self, data: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(data);
        self
    }

    /// Consume the writer, returning the encoded packet bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// Convenience builders for server→client packets.
/// Build an `AuthResult` packet.
pub fn encode_auth_result(ok: bool, message: Option<&str>) -> Vec<u8> {
    let mut w = PacketWriter::with_opcode(Opcode::AuthResult);
    w.write_u8(if ok { 0x01 } else { 0x00 });
    if let Some(msg) = message {
        w.write_len_prefixed(msg.as_bytes());
    }
    w.into_bytes()
}

/// Build a server→client `Data` packet (id + timestamp + payload).
pub fn encode_data(id: u64, timestamp: u64, payload: &[u8]) -> Vec<u8> {
    let mut w = PacketWriter::with_opcode(Opcode::Data);
    w.write_u64(id);
    w.write_u64(timestamp);
    w.write_len_prefixed(payload);
    w.into_bytes()
}

/// Build a server→client `SyncResponse` packet.
pub fn encode_sync_response(messages: &[(u64, u64, Vec<u8>)]) -> Vec<u8> {
    let mut w = PacketWriter::with_opcode(Opcode::SyncResponse);
    w.write_u32(messages.len() as u32);
    for (id, ts, payload) in messages {
        w.write_u64(*id);
        w.write_u64(*ts);
        w.write_len_prefixed(payload);
    }
    w.into_bytes()
}

/// Build a `Heartbeat` echo packet carrying the client-provided timestamp.
pub fn encode_heartbeat(client_timestamp: u64) -> Vec<u8> {
    let mut w = PacketWriter::with_opcode(Opcode::Heartbeat);
    w.write_u64(client_timestamp);
    w.into_bytes()
}

/// Build a `NewCertHash` packet (SHA-256 fingerprint + expiry timestamp).
///
/// Wire format: `0x07` opcode, exactly 32 raw SHA-256 bytes, then
/// the `u64` unix-expiry — no length prefix.
pub fn encode_new_cert_hash(hash: &[u8; 32], expires_at: u64) -> Vec<u8> {
    let mut w = PacketWriter::with_opcode(Opcode::NewCertHash);
    w.buf.extend_from_slice(hash);
    w.write_u64(expires_at);
    w.into_bytes()
}

/// Canonical Argon2id parameters (OWASP) the server enforces, transmitted in the
/// `AuthChallenge` so the client derives its HMAC key from a single source of truth
/// (SPEC N1). Format: `m=<m>,t=<t>,p=<p>` — a length-prefixed UTF-8 tag.
pub const AUTH_CHALLENGE_PARAMS_TAG: &[u8] = b"m=47104,t=3,p=1";

/// Build an `AuthChallenge` packet (server→client).
///
/// Wire format (SPEC §4.3):
///   `[0x0B] [16 nonce] [u32 salt_len] [salt_b64] [u32 params_len] [m=..,t=..,p=..]`
/// The trailing `m/t/p` tag carries the server's OWASP Argon2id parameters so the client
/// derives its HMAC key from them instead of a frozen constant (kills the N1 lockstep mine).
pub fn encode_auth_challenge(nonce: &[u8], argon2_salt_b64: &str) -> Vec<u8> {
    let mut w = PacketWriter::with_opcode(Opcode::AuthChallenge);
    w.buf.extend_from_slice(nonce);                      // 16 raw bytes
    w.write_len_prefixed(argon2_salt_b64.as_bytes());    // u32 + B64 salt string
    w.write_len_prefixed(AUTH_CHALLENGE_PARAMS_TAG);     // u32 + "m=47104,t=3,p=1"
    w.into_bytes()
}

/// A decoded client message ready to be relayed to all clients (server form).
#[derive(Debug, Clone)]
pub struct RelayedMessage {
    pub id: u64,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

impl RelayedMessage {
    /// Encode this message as a server→client `Data` packet.
    pub fn to_packet(&self) -> Vec<u8> {
        encode_data(self.id, self.timestamp, &self.payload)
    }
}

/// Server→client packet encoder.
pub struct ServerPacketEncoder;

impl ServerPacketEncoder {
    pub fn auth_result(ok: bool, message: Option<&str>) -> Vec<u8> {
        encode_auth_result(ok, message)
    }

    pub fn sync_response(messages: &[(u64, u64, Vec<u8>)]) -> Vec<u8> {
        encode_sync_response(messages)
    }

    pub fn heartbeat(client_timestamp: u64) -> Vec<u8> {
        encode_heartbeat(client_timestamp)
    }

    pub fn new_cert_hash(hash: &[u8; 32], expires_at: u64) -> Vec<u8> {
        encode_new_cert_hash(hash, expires_at)
    }
}

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
mod combined_key_exchange_tests {
    use crate::protocol::framing::{try_read_packet, TryReadResult};
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
    fn try_read_packet_length_covers_full_frame() {
        let kem = vec![0xAA; 1184];
        let dsa = vec![0xBB; 1952];

        let frame = build_client_combined_key_exchange(&kem, &dsa);

        assert_eq!(try_read_packet(&frame), TryReadResult::Packet(frame.len()));
    }

    // ── 2. try_read_packet length for various key sizes ────────────────────────
    #[test]
    fn try_read_packet_length_various_sizes() {
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
            assert_eq!(
                try_read_packet(&frame),
                TryReadResult::Packet(frame.len()),
                "Frame mismatch for kem_len={}, dsa_len={}",
                kem_len,
                dsa_len
            );
        }
    }

    // ── 3. server relay preserves the original client frame format ──────────────
    #[test]
    fn server_relay_preserves_original_format() {
        let kem = vec![0x11; 100];
        let dsa = vec![0x22; 200];

        let frame = build_client_combined_key_exchange(&kem, &dsa);
        let relayed = simulated_server_relay(&frame);

        // Relayed packet is identical to the original client frame
        assert_eq!(relayed, frame);
    }

    // ── 4. relayed packet parseable by receiving client ─────────────────────────
    #[test]
    fn relayed_packet_parseable_by_client() {
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
    fn no_orphan_bytes_after_try_read() {
        let kem = vec![0x55; 500];
        let dsa = vec![0x66; 600];

        let frame = build_client_combined_key_exchange(&kem, &dsa);

        assert_eq!(try_read_packet(&frame), TryReadResult::Packet(frame.len()));
    }

    // ── 6. outer u32 total_len equals inner content ────────────────────────────
    #[test]
    fn outer_u32_equals_inner_content() {
        let kem = vec![0x77; 300];
        let dsa = vec![0x88; 400];

        let frame = build_client_combined_key_exchange(&kem, &dsa);
        let outer_len = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;

        let expected_inner = 4 + kem.len() + 4 + dsa.len();
        assert_eq!(outer_len, expected_inner);
    }

    // ── 7. empty keys — edge case ──────────────────────────────────────────────
    #[test]
    fn empty_keys_roundtrip() {
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
    fn frame_length_consistency_through_relay() {
        let kem = vec![0xAB; 1184];
        let dsa = vec![0xCD; 1952];

        let frame = build_client_combined_key_exchange(&kem, &dsa);
        assert_eq!(frame[0], 0x0C);

        assert_eq!(try_read_packet(&frame), TryReadResult::Packet(frame.len()));

        let relayed = simulated_server_relay(&frame);
        assert_eq!(relayed, frame);
    }

    // ── 9. OP_DATA is NOT confused with 0x0C ──────────────────────────────────
    #[test]
    fn data_and_keyexchange_opcodes_distinguished() {
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
    fn stress_relay_cycles() {
        for i in 0..50 {
            let kem = vec![(i * 7 % 256) as u8; 32 + i * 10];
            let dsa = vec![(i * 13 % 256) as u8; 64 + i * 20];

            let frame = build_client_combined_key_exchange(&kem, &dsa);
            assert_eq!(frame[0], 0x0C);

            assert_eq!(try_read_packet(&frame), TryReadResult::Packet(frame.len()));

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
