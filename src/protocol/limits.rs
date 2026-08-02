//! Packet-size and buffering limits — single source of truth for the wire codec.

/// Max incoming message payload size (bytes) to bound memory.
pub const MAX_PAYLOAD_BYTES: usize = 1_000_000;

/// Max bytes buffered from a single stream before we give up (defensive).
pub const MAX_STREAM_BUFFER: usize = 8 * 1024 * 1024;

/// Largest acceptable full packet: opcode byte + u32 length + payload.
pub const MAX_PACKET_LEN: usize = 1 + 4 + MAX_PAYLOAD_BYTES;

/// Aggregate memory budget across all sessions. When total buffered bytes
/// across all reader tasks exceed this, new reads are rejected to prevent
/// memory exhaustion DoS (E4).
pub const MAX_TOTAL_BUFFERED_BYTES: usize = 512 * 1024 * 1024; // 512 MB
