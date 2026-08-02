//! Length-prefixed packet framing over the WebTransport stream.
//!
//! `try_read_packet` inspects a byte buffer and reports whether a complete,
//! well-formed packet is available, how long it is, or why it must be skipped /
//! the session closed. This standalone module keeps the codec free of a
//! dependency on the relay.

use crate::protocol::limits::MAX_PACKET_LEN;

/// Result of [`try_read_packet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryReadResult {
    /// A full packet is available (consumable now). Inner is the packet length.
    Packet(usize),
    /// Buffer is incomplete; wait for more bytes.
    Incomplete,
    /// Leading byte is not a recognized client opcode — skip 1 byte and retry.
    UnknownOpcode,
    /// The declared payload length exceeds [`MAX_PACKET_LEN`] — the session
    /// must be closed because the stream is corrupted beyond recovery.
    OversizedPayload,
}

/// Try to read a complete packet length from the buffer.
pub fn try_read_packet(buf: &[u8]) -> TryReadResult {
    if buf.is_empty() {
        return TryReadResult::Incomplete;
    }
    let opcode = buf[0];
    let min_len = match opcode {
        0x01 => 1 + 4 + 32,  // Auth: opcode + len prefix + fixed 32-byte HMAC
        0x03 => 1 + 8,       // Sync: opcode + u64
        0x05 => 1 + 4,       // Data: opcode + len prefix
        0x06 => 1 + 8,       // Heartbeat: opcode + u64
        0x0C => 1 + 4,       // KeyExchangeKemDsa: opcode + len prefix
        _ => return TryReadResult::UnknownOpcode,
    };
    if buf.len() < min_len {
        return TryReadResult::Incomplete;
    }

    let len = match opcode {
        0x01 => {
            if buf.len() < 5 {
                return TryReadResult::Incomplete;
            }
            let pwd_len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            let total = 1 + 4 + pwd_len + 32;
            if total > MAX_PACKET_LEN {
                return TryReadResult::OversizedPayload;
            }
            return TryReadResult::Packet(total);
        }
        0x05 | 0x0C => {
            if buf.len() < 5 {
                return TryReadResult::Incomplete;
            }
            u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize
        }
        0x03 | 0x06 => {
            return TryReadResult::Packet(9);
        }
        _ => return TryReadResult::UnknownOpcode,
    };
    if len > MAX_PACKET_LEN {
        return TryReadResult::OversizedPayload;
    }
    TryReadResult::Packet(1 + 4 + len)
}

#[cfg(test)]
mod tests {
    use super::{TryReadResult, try_read_packet};
    use crate::protocol::{Opcode, PacketWriter};

    fn data_frame(payload_len: usize) -> Vec<u8> {
        let mut w = PacketWriter::with_opcode(Opcode::Data);
        w.write_len_prefixed(&vec![0u8; payload_len]);
        w.into_bytes()
    }

    #[test]
    fn packet_detection_for_each_opcode() {
        assert_eq!(try_read_packet(&[0x99]), TryReadResult::UnknownOpcode);
        assert_eq!(try_read_packet(&[]), TryReadResult::Incomplete);
        // Data: opcode + u32 len + payload
        assert_eq!(try_read_packet(&data_frame(10)), TryReadResult::Packet(1 + 4 + 10));
        // Truncated Data header
        assert_eq!(try_read_packet(&[0x05, 0x00]), TryReadResult::Incomplete);
        // Sync: opcode + u64
        assert_eq!(try_read_packet(&[0x03, 1, 2, 3, 4, 5, 6, 7, 8]), TryReadResult::Packet(9));
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let mut w = PacketWriter::with_opcode(Opcode::Data);
        w.write_u32(u32::MAX);
        assert_eq!(try_read_packet(&w.into_bytes()), TryReadResult::OversizedPayload);
    }

    #[test]
    fn auth_uses_minimum_length_with_hmac() {
        // 0x01 + len-prefixed pwd + 32 raw HMAC
        let mut w = PacketWriter::with_opcode(Opcode::Auth);
        w.write_len_prefixed(b"pw");
        w.write_raw(&[0u8; 32]);
        let bytes = w.into_bytes();
        assert_eq!(try_read_packet(&bytes), TryReadResult::Packet(bytes.len()));
    }
}
