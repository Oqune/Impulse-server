//! Binary wire protocol for the WebTransport relay.
//!
//! All frames are length-prefixed binary packets exchanged over a WebTransport
//! bidirectional stream. Every packet starts with a single opcode byte, followed
//! by opcode-specific binary fields (all integers little-endian).
//!
//! The server never decrypts payloads; it only forwards opaque bytes.
//!
//! Opcodes:
//! * `0x01` Auth          — client → server: password (UTF-8).
//! * `0x02` AuthResult    — server → client: status byte + optional message.
//! * `0x03` Sync          — client → server: `last_seen_id` (u64).
//! * `0x04` SyncResponse  — server → client: count (u32) + messages.
//! * `0x05` Data          — client → server: len (u32) + payload;
//!   server → client: id (u64) + timestamp (u64) + len + payload.
//! * `0x06` Heartbeat     — either direction: client timestamp (u64).
//! * `0x07` NewCertHash   — server → client: len (u32) + SHA-256 + expiry (u64).
//! * `0x08` KeyExchange   — either direction: len (u32) + public key.

use std::io::{self};

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
    KeyExchange = 0x08,
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
            0x08 => Some(Opcode::KeyExchange),
            _ => None,
        }
    }

    /// The wire byte for this opcode.
    pub fn as_u8(self) -> u8 {
        self as u8
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

impl From<ProtocolError> for io::Error {
    fn from(e: ProtocolError) -> Self {
        match e {
            ProtocolError::UnexpectedEof => {
                io::Error::new(io::ErrorKind::UnexpectedEof, "packet truncated")
            }
            ProtocolError::UnknownOpcode(b) => io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown opcode 0x{b:02x}"),
            ),
        }
    }
}

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
        self.write_u32(data.len() as u32);
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
    w.write_u8(if ok { 0x00 } else { 0x01 });
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
/// Wire format (per spec): `0x07` opcode, exactly 32 raw SHA-256 bytes, then
/// the `u64` unix-expiry — no length prefix.
pub fn encode_new_cert_hash(hash: &[u8; 32], expires_at: u64) -> Vec<u8> {
    let mut w = PacketWriter::with_opcode(Opcode::NewCertHash);
    w.buf.extend_from_slice(hash);
    w.write_u64(expires_at);
    w.into_bytes()
}

/// Build a `KeyExchange` packet (raw relay of the public key).
pub fn encode_key_exchange(public_key: &[u8]) -> Vec<u8> {
    let mut w = PacketWriter::with_opcode(Opcode::KeyExchange);
    w.write_len_prefixed(public_key);
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

/// Parsed client→server packets.
#[derive(Debug, Clone)]
pub enum ClientPacket {
    Auth { password: Vec<u8> },
    Sync { last_seen_id: u64 },
    Data { payload: Vec<u8> },
    Heartbeat { client_timestamp: u64 },
    KeyExchange { public_key: Vec<u8> },
}

/// Server→client packet encoder.
pub struct ServerPacketEncoder;

impl ServerPacketEncoder {
    pub fn auth_result(ok: bool, message: Option<&str>) -> Vec<u8> {
        encode_auth_result(ok, message)
    }

    pub fn data(id: u64, timestamp: u64, payload: &[u8]) -> Vec<u8> {
        encode_data(id, timestamp, payload)
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

    pub fn key_exchange(public_key: &[u8]) -> Vec<u8> {
        encode_key_exchange(public_key)
    }
}
