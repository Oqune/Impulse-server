//! Per-session state and the session read/write task lifecycle.
//!
//! A `SessionMeta` is the registry value shown in the TUI sessions table.
//! The `Session` struct is created per accepted connection; it owns the
//! auth flag that the reader task flips on success.

use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use crate::protocol::framing::{TryReadResult, try_read_packet};
use crate::protocol::limits::{MAX_STREAM_BUFFER, MAX_TOTAL_BUFFERED_BYTES};
use crate::protocol::encode_auth_challenge;
use crate::relay::{NONCE_LEN, RelayServer, SESSION_IDLE_TIMEOUT, ServerStats, op_name};

/// Lightweight snapshot of a live session, stored in the relay's session
/// registry and displayed by the TUI.
#[derive(Clone, Debug)]
pub struct SessionMeta {
    pub ip: IpAddr,
    pub authenticated: bool,
    pub connected_at: Instant,
}

/// Mutable per-session state owned by the reader task.
#[derive(Debug)]
pub struct Session {
    pub key: u64,
    pub ip: IpAddr,
    pub authenticated: bool,
}

impl Session {
    pub fn new(key: u64, ip: IpAddr) -> Self {
        Self { key, ip, authenticated: false }
    }
}

/// Owns the reader task's buffered bytes and reconciles the shared aggregate
/// budget counter (`stats.buffered_bytes`) when dropped.
///
/// The reader task reconciles its residual buffer on the normal exit paths,
/// but when the task is aborted (e.g. the writer task finishes first with a
/// write/flush error, Bug 1) the future is dropped without running that
/// cleanup, which previously leaked the remaining bytes from the DoS budget
/// counter forever. Dropping a task's captured state runs `Drop`, so this
/// wrapper covers every exit path — natural EOF, read error, idle timeout,
/// oversized payload, and abort — returning the counter to its pre-session
/// value.
struct BudgetedBuffer<'a> {
    buf: Vec<u8>,
    budget: &'a AtomicUsize,
}

impl<'a> BudgetedBuffer<'a> {
    fn new(budget: &'a AtomicUsize) -> Self {
        Self {
            buf: Vec::with_capacity(4096),
            budget,
        }
    }

    /// Return the remaining bytes to the budget counter now and clear the
    /// buffer, so the subsequent `Drop` has nothing left to subtract. Keeps
    /// the normal end-of-loop cleanup prompt and prevents double subtraction.
    fn reconcile(&mut self) {
        if !self.buf.is_empty() {
            self.budget.fetch_sub(self.buf.len(), Ordering::Relaxed);
            self.buf.clear();
        }
    }
}

impl Deref for BudgetedBuffer<'_> {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.buf
    }
}

impl DerefMut for BudgetedBuffer<'_> {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }
}

impl Drop for BudgetedBuffer<'_> {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            self.budget.fetch_sub(self.buf.len(), Ordering::Relaxed);
        }
    }
}

impl RelayServer {
    // ------------------------------------------------------------------
    // WebTransport session entry point
    // ------------------------------------------------------------------

    pub(crate) async fn handle_wt_session(
        self: Arc<Self>,
        connection: wtransport::Connection,
        _permit: tokio::sync::OwnedSemaphorePermit,
        session_key: u64,
    ) {
        let remote_ip = connection.remote_address().ip();

        // Accept the bidirectional stream opened by the client. WebTransport uses
        // a client-initiated stream: the Android client calls
        // `createBidirectionalStream`, and the server must `accept_bi` the SAME
        // stream. Using `open_bi` here created a separate server-initiated stream,
        // so the two endpoints ended up on different streams and no data flowed
        // in either direction (session handshake succeeded, but auth/relay never
        // worked).
        let (mut send_stream, recv_stream) = match connection.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("[STREAM] Session {} accept_bi FAILED: {}", session_key, e);
                connection.close(wtransport::VarInt::from(0u32), b"stream");
                return;
            }
        };

        // Generate and send auth challenge nonce to prevent replay attacks.
        let nonce: Vec<u8> = (0..NONCE_LEN)
            .map(|_| rand::random::<u8>())
            .collect();
        self.auth_nonces
            .insert(session_key, (nonce.clone(), Instant::now()));
        self.auth_attempts
            .insert(session_key, AtomicU32::new(0));

        // Extract B64 salt from stored Argon2 hash for the challenge
        let argon2_salt_b64 = {
            use argon2::password_hash::PasswordHash;
            match PasswordHash::new(&self.password_hash) {
                Ok(parsed) => parsed.salt.map(|s| s.to_string()).unwrap_or_default(),
                Err(_) => String::new(),
            }
        };

        // Send challenge: [0x0B] + 16 raw nonce bytes + len-prefixed B64 salt.
        if let Err(e) = send_stream
            .write_all(&encode_auth_challenge(&nonce, &argon2_salt_b64))
            .await
        {
            warn!("[STREAM] Session {} failed to send challenge: {}", session_key, e);
            // Clean up auth entries to prevent memory leak
            self.auth_nonces.remove(&session_key);
            self.auth_attempts.remove(&session_key);
            connection.close(wtransport::VarInt::from(0u32), b"challenge");
            return;
        }
        if let Err(e) = send_stream.flush().await {
            warn!("[STREAM] Session {} failed to flush challenge: {}", session_key, e);
            self.auth_nonces.remove(&session_key);
            self.auth_attempts.remove(&session_key);
            connection.close(wtransport::VarInt::from(0u32), b"flush");
            return;
        }

        self.run_session(session_key, remote_ip, recv_stream, send_stream, _permit)
            .await;
    }

    // ------------------------------------------------------------------
    // Session loop
    // ------------------------------------------------------------------

    async fn run_session<R, W>(
        self: Arc<Self>,
        session_key: u64,
        remote_ip: std::net::IpAddr,
        mut reader: R,
        mut writer: W,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) where
        R: AsyncReadExt + Unpin + Send + 'static,
        W: AsyncWriteExt + Unpin + Send + 'static,
    {
        // Each session gets its own broadcast subscriptions.
        let mut data_sub = self.data_tx.subscribe();
        let mut control_sub = self.control_tx.subscribe();
        let mut keyexchange_sub = self.keyexchange_tx.subscribe();

        // Channel for direct responses (SyncResponse, Heartbeat, AuthResult)
        let (direct_tx, mut direct_rx) = mpsc::channel::<Vec<u8>>(32);

        // Register this session in the live-session registry (TUI session table).
        let meta = SessionMeta {
            ip: remote_ip,
            authenticated: false,
            connected_at: Instant::now(),
        };
        self.sessions.insert(session_key, meta);
        self.stats.bump_sessions();
        self.tui.set_stats(self.sessions.len());
        self.tui.set_sessions(self.session_rows());

        let relay = self.clone();

        // Task: forward broadcast messages AND direct responses to this session's send stream.
        let mut writer_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = data_sub.recv() => {
                        match result {
                            Ok((src_session, msg)) => {
                                if src_session == session_key {
                                    continue;
                                }
                                let packet = msg.to_packet();
                                let op = if packet.is_empty() { 0 } else { packet[0] };
                                debug!("[WRITER] Session {} <- DATA relay opcode=0x{:02x} ({}) len={}",
                                    session_key, op, op_name(op), packet.len());
                                if let Err(e) = writer.write_all(&packet).await {
                                    warn!("[WRITER] Session {} write error: {}", session_key, e);
                                    break;
                                }
                                if let Err(e) = writer.flush().await {
                                    warn!("[WRITER] Session {} flush error: {}", session_key, e);
                                    break;
                                }
                                relay.stats.relayed_msgs.fetch_add(1, Ordering::Relaxed);
                                relay.stats.relayed_bytes.fetch_add(packet.len(), Ordering::Relaxed);
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                warn!("[WRITER] Session {} lagged, missed {} messages, continuing",
                                    session_key, n);
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                break;
                            }
                        }
                    }
                    result = control_sub.recv() => {
                        match result {
                            Ok(packet) => {
                                let op = if packet.is_empty() { 0 } else { packet[0] };
                                debug!("[WRITER] Session {} <- CONTROL opcode=0x{:02x} ({}) len={}",
                                    session_key, op, op_name(op), packet.len());
                                if let Err(e) = writer.write_all(&packet).await {
                                    warn!("[WRITER] Session {} control write error: {}", session_key, e);
                                    break;
                                }
                                if let Err(e) = writer.flush().await {
                                    warn!("[WRITER] Session {} control flush error: {}", session_key, e);
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                warn!("[WRITER] Session {} control lagged, missed {}", session_key, n);
                            }
                            Err(_) => break,
                        }
                    }
                    result = keyexchange_sub.recv() => {
                        match result {
                            Ok((src_session, packet)) => {
                                if src_session == session_key {
                                    continue;
                                }
                                let op = if packet.is_empty() { 0 } else { packet[0] };
                                debug!("[WRITER] Session {} <- KEYEXCHANGE (from session {}) opcode=0x{:02x} ({}) len={}",
                                    session_key, src_session, op, op_name(op), packet.len());
                                if let Err(e) = writer.write_all(&packet).await {
                                    warn!("[WRITER] Session {} keyexchange write error: {}", session_key, e);
                                    break;
                                }
                                if let Err(e) = writer.flush().await {
                                    warn!("[WRITER] Session {} keyexchange flush error: {}", session_key, e);
                                    break;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                warn!("[WRITER] Session {} keyexchange lagged, missed {}", session_key, n);
                            }
                            Err(_) => break,
                        }
                    }
                    Some(packet) = direct_rx.recv() => {
                        let op = if packet.is_empty() { 0 } else { packet[0] };
                        debug!("[WRITER] Session {} <- DIRECT opcode=0x{:02x} ({}) len={}",
                            session_key, op, op_name(op), packet.len());
                        if let Err(e) = writer.write_all(&packet).await {
                            warn!("[WRITER] Session {} direct write error: {}", session_key, e);
                            break;
                        }
                        if let Err(e) = writer.flush().await {
                            warn!("[WRITER] Session {} direct flush error: {}", session_key, e);
                            break;
                        }
                    }
                    else => {
                        info!("[WRITER] Session {} all channels closed, stopping", session_key);
                        break;
                    }
                }
            }
            let _ = writer.flush().await;
            let _ = writer.shutdown().await;
        });

        // Task: read length-prefixed binary packets from the client.
        let mut reader_task = {
            let this = self.clone();
            let direct_tx = direct_tx.clone();
            let mut session = Session::new(session_key, remote_ip);
            tokio::spawn(async move {
                let mut buf = BudgetedBuffer::new(&this.stats.buffered_bytes);
                let mut chunk = [0u8; 8192];

                loop {
                    let read =
                        tokio::time::timeout(SESSION_IDLE_TIMEOUT, reader.read(&mut chunk)).await;
                    match read {
                        Ok(Ok(0)) => {
                            break; // EOF
                        }
                        Ok(Ok(n)) => {
                            if tracing::enabled!(tracing::Level::TRACE) {
                                trace!("[READER] Session {} raw chunk: {} bytes", session_key, n);
                            }
                            // Extend buffer first, then update aggregate budget.
                            buf.extend_from_slice(&chunk[..n]);
                            let new_total =
                                this.stats.buffered_bytes.fetch_add(n, Ordering::Relaxed) + n;
                            if new_total > MAX_TOTAL_BUFFERED_BYTES {
                                // Roll back: remove the bytes we just added.
                                let rollback = buf.len().min(n);
                                let remaining = buf.len() - rollback;
                                buf.truncate(remaining);
                                this.stats.buffered_bytes.fetch_sub(rollback, Ordering::Relaxed);
                                warn!(
                                    "[READER] Session {} AGGREGATE MEMORY BUDGET EXCEEDED ({} > {}), closing",
                                    session_key,
                                    new_total,
                                    MAX_TOTAL_BUFFERED_BYTES
                                );
                                break;
                            }
                            debug!(
                                "[READER] Session {} buffer now {} bytes (aggregate: {})",
                                session_key,
                                buf.len(),
                                new_total
                            );
                            if buf.len() > MAX_STREAM_BUFFER {
                                let buf_len = buf.len();
                                this.stats.buffered_bytes.fetch_sub(buf_len, Ordering::Relaxed);
                                buf.clear();
                                warn!(
                                    "[READER] Session {} BUFFER OVERFLOW ({} > {}), closing",
                                    session_key,
                                    buf_len,
                                    MAX_STREAM_BUFFER
                                );
                                break;
                            }
                            // Process all complete packets.
                            loop {
                                match try_read_packet(&buf) {
                                    TryReadResult::Packet(packet_len) => {
                                        if packet_len > buf.len() {
                                            info!(
                                                "[READER] Session {} partial packet: declared {} but buffer has {}, waiting",
                                                session_key,
                                                packet_len,
                                                buf.len()
                                            );
                                            break;
                                        }
                                        let packet_data: Vec<u8> =
                                            buf.drain(..packet_len).collect();
                                        this.stats.buffered_bytes.fetch_sub(packet_len, Ordering::Relaxed);
                                        let op = if packet_data.is_empty() {
                                            0
                                        } else {
                                            packet_data[0]
                                        };
                                        debug!(
                                            "[READER] Session {} -> opcode=0x{:02x} ({}) total_packet={} bytes",
                                            session_key,
                                            op,
                                            op_name(op),
                                            packet_len
                                        );
                                        if let Err(e) = crate::relay::auth::process_packet(
                                            &this,
                                            &mut session,
                                            &direct_tx,
                                            &packet_data,
                                        )
                                        .await
                                        {
                                            info!(
                                                "[READER] Session {} packet error: {} (authenticated={})",
                                                session_key, e, session.authenticated
                                            );
                                            break;
                                        }
                                    }
                                    TryReadResult::Incomplete => {
                                        debug!(
                                            "[READER] Session {} incomplete packet, waiting for more data (buf={} bytes)",
                                            session_key,
                                            buf.len()
                                        );
                                        break; // incomplete, wait for more data
                                    }
                                    TryReadResult::UnknownOpcode => {
                                        let bad = buf[0];
                                        warn!(
                                            "[READER] Session {} UNKNOWN BYTE 0x{:02x} at buffer start — skipping 1 byte (buf={} bytes remaining)",
                                            session_key, bad, buf.len()
                                        );
                                        buf.remove(0);
                                        this.stats.buffered_bytes.fetch_sub(1, Ordering::Relaxed);
                                    }
                                    TryReadResult::OversizedPayload => {
                                        warn!(
                                            "[READER] Session {} OVERSIZED PAYLOAD (first byte=0x{:02x}, buf={} bytes) — closing session",
                                            session_key,
                                            if buf.is_empty() { 0 } else { buf[0] },
                                            buf.len()
                                        );
                                        return; // fatal: stream is corrupted
                                    }
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            warn!("[READER] Session {} stream read error: {}", session_key, e);
                            break;
                        }
                        Err(_) => {
                            warn!(
                                "[READER] Session {} IDLE TIMEOUT ({}s, no data from client)",
                                session_key,
                                SESSION_IDLE_TIMEOUT.as_secs()
                            );
                            break;
                        }
                    }
                }
                // Release any remaining buffered bytes from the aggregate budget.
                // If this cleanup is never reached (task aborted), `Drop` on
                // `BudgetedBuffer` reconciles the same bytes.
                buf.reconcile();
            })
        };

        // Wait for the first task to finish, then abort the other so no task
        // is orphaned; the session-registry entry + semaphore permit are
        // released only after both have stopped (Bug 1).
        tokio::select! {
            _ = &mut writer_task => reader_task.abort(),
            _ = &mut reader_task => writer_task.abort(),
        }
        let _ = writer_task.await;
        let _ = reader_task.await;

        cleanup_session_state(
            &self.sessions,
            &self.stats,
            &self.auth_nonces,
            &self.auth_attempts,
            &self.key_exchange_store,
            session_key,
        );
        self.tui.set_stats(self.sessions.len());
    }
}

/// Remove all state belonging to a finished session. Kept separate so the
/// disconnect cleanup invariant can be regression-tested without a live QUIC
/// endpoint.
fn cleanup_session_state(
    sessions: &DashMap<u64, SessionMeta>,
    stats: &ServerStats,
    auth_nonces: &DashMap<u64, (Vec<u8>, Instant)>,
    auth_attempts: &DashMap<u64, AtomicU32>,
    key_exchange_store: &DashMap<u64, Vec<Vec<u8>>>,
    session_key: u64,
) {
    sessions.remove(&session_key);
    stats.drop_session();
    auth_nonces.remove(&session_key);
    auth_attempts.remove(&session_key);
    key_exchange_store.remove(&session_key);
}

#[cfg(test)]
mod tests {
    use super::{BudgetedBuffer, SessionMeta, cleanup_session_state};
    use crate::relay::ServerStats;
    use dashmap::DashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    #[test]
    fn session_meta_carries_auth_flag() {
        let mut m = SessionMeta {
            ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            authenticated: false,
            connected_at: Instant::now(),
        };
        assert!(!m.authenticated);
        m.authenticated = true;
        assert!(m.authenticated);
    }

    #[test]
    fn reconcile_then_drop_does_not_double_subtract() {
        let budget = AtomicUsize::new(0);
        {
            let mut buf = BudgetedBuffer::new(&budget);
            buf.extend_from_slice(&[0u8; 32]);
            budget.fetch_add(32, Ordering::Relaxed);

            buf.reconcile();
            assert_eq!(budget.load(Ordering::Relaxed), 0);
        }
        assert_eq!(budget.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn buffered_bytes_reconciled_when_reader_task_aborted() {
        let budget = Arc::new(AtomicUsize::new(0));
        let pre = budget.load(Ordering::Relaxed);

        // Reader task buffers a chunk (counted into the aggregate budget) and
        // then blocks awaiting the next read — it never runs its end-of-loop
        // cleanup. Mirrors a reader task killed mid-session by abort.
        let reader = {
            let budget = budget.clone();
            tokio::spawn(async move {
                let mut buf = BudgetedBuffer::new(&budget);
                buf.extend_from_slice(&[0u8; 1024]);
                budget.fetch_add(1024, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_secs(3600)).await;
            })
        };

        // Yield until the reader has accounted its buffered bytes.
        loop {
            if budget.load(Ordering::Relaxed) == 1024 {
                break;
            }
            tokio::task::yield_now().await;
        }

        // Abort as run_session does when the writer finishes first.
        reader.abort();
        let _ = reader.await;

        assert_eq!(budget.load(Ordering::Relaxed), pre);
    }

    #[test]
    fn session_cleanup_releases_registry_entry_and_session_counter() {
        // Regression for Bug 1: invoke the exact state-cleanup helper used by
        // `handle_wt_session` after a client drops mid-session.
        let sessions: DashMap<u64, SessionMeta> = DashMap::new();
        let stats = ServerStats::new();
        let auth_nonces = DashMap::new();
        let auth_attempts = DashMap::new();
        let key_exchange_store = DashMap::new();

        // Session connects: registry entry + counter bump (as run_session does).
        sessions.insert(
            7,
            SessionMeta {
                ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
                authenticated: false,
                connected_at: Instant::now(),
            },
        );
        stats.bump_sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(stats.sessions.load(Ordering::Relaxed), 1);

        // Client drops mid-session: the real teardown removes the entry and
        // decrements the counter; both must return to 0 together.
        cleanup_session_state(
            &sessions,
            &stats,
            &auth_nonces,
            &auth_attempts,
            &key_exchange_store,
            7,
        );
        assert_eq!(sessions.len(), 0);
        assert_eq!(stats.sessions.load(Ordering::Relaxed), 0);
    }
}
