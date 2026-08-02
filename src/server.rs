//! WebTransport (QUIC/HTTP3) relay server.
//!
//! Responsibilities:
//!   * Accept WebTransport sessions using the managed self-signed certificate.
//!   * For each session, run a bidirectional loop of length-prefixed binary
//!     [`Opcode`] packets.
//!   * The server never decrypts payloads; it only forwards opaque bytes.
//!   * Periodically sweep expired messages and rotate the certificate.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Semaphore, broadcast, mpsc};
use tracing::{debug, info, trace, warn};
use wtransport::endpoint::endpoint_side;
use wtransport::{Endpoint, ServerConfig};

use crate::cert::CertManager;
use crate::cert::DynamicCertResolver;
use crate::protocol::{
    Opcode, PacketReader, RelayedMessage, ServerPacketEncoder, encode_auth_challenge,
};
use crate::storage::MessageStore;
use crate::tui::TuiHandle;

fn opcode_name(b: u8) -> &'static str {
    match b {
        0x01 => "Auth",
        0x02 => "AuthResult",
        0x03 => "Sync",
        0x04 => "SyncResponse",
        0x05 => "Data",
        0x06 => "Heartbeat",
        0x07 => "NewCertHash",
        0x0B => "AuthChallenge",
        0x0C => "KeyExchangeKemDsa",
        _ => "UNKNOWN",
    }
}

fn hex_dump(bytes: &[u8], max: usize) -> String {
    let show = bytes.len().min(max);
    let hex: String = bytes[..show]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    if bytes.len() > max {
        format!("{}... ({} bytes total)", hex, bytes.len())
    } else {
        format!("{} ({} bytes)", hex, bytes.len())
    }
}

/// Max incoming message payload size (bytes) to bound memory.
pub(crate) const MAX_PAYLOAD_BYTES: usize = 1_000_000;

/// Max bytes buffered from a single stream before we give up (defensive).
const MAX_STREAM_BUFFER: usize = 8 * 1024 * 1024;

/// Aggregate memory budget across all sessions. When total buffered bytes
/// across all reader tasks exceed this, new reads are rejected to prevent
/// memory exhaustion DoS (E4).
const MAX_TOTAL_BUFFERED_BYTES: usize = 512 * 1024 * 1024; // 512 MB

/// How often to sweep expired messages / rotate certs.
const HOUSEKEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Idle timeout for a client stream. A session that sends nothing for this long
/// is considered dead/abandoned and is closed (S1) to avoid leaking tasks and
/// semaphore permits on hung connections.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum number of concurrent sessions. Beyond this, new sessions are
/// rejected to protect against resource exhaustion (DoS).
const MAX_CONCURRENT_SESSIONS: usize = 1024;

/// Max number of messages returned by a single `Sync` (C3). Late joiners get at
/// most this many; they should issue further `Sync` calls to catch up.
const MAX_SYNC_MESSAGES: usize = 2000;

/// Max connections per IP within the rate-limit window.
const MAX_CONNECTIONS_PER_IP: usize = 10;

/// Rate-limit window duration.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(10);

/// WebTransport handshake timeout.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Challenge nonce size (bytes).
const NONCE_LEN: usize = 16;

/// Maximum age of a challenge nonce before it expires.
const NONCE_MAX_AGE: Duration = Duration::from_secs(30);

/// Maximum auth attempts per session before forced disconnect.
const MAX_AUTH_ATTEMPTS: u32 = 5;

/// Prune rate limiter entries older than this.
const IP_PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// Shared server state.
pub struct RelayServer {
    config: crate::config::ServerSettings,
    cert_manager: Arc<tokio::sync::Mutex<CertManager>>,
    store: Arc<MessageStore>,
    /// Broadcast hub for relayed data messages, with sender session id for exclusion.
    data_tx: broadcast::Sender<(u64, RelayedMessage)>,
    /// Broadcast hub for control packets (NewCertHash).
    control_tx: broadcast::Sender<Vec<u8>>,
    /// KeyExchange packets with sender session id for exclusion.
    keyexchange_tx: broadcast::Sender<(u64, Vec<u8>)>,
    /// Active sessions registry for direct sends (keyed by session id).
    sessions: Arc<DashMap<u64, mpsc::Sender<Vec<u8>>>>,
    /// Dynamic TLS certificate resolver. Swapping its inner certificate set on
    /// rotation makes freshly-connecting WebTransport clients immediately see the
    /// new certificate without recreating the `Endpoint` (see E1).
    cert_resolver: Arc<DynamicCertResolver>,
    /// Pre-built WebTransport `Endpoint` (binds the `cert_resolver`). Built once
    /// in `new()`; the certificate resolver is swapped on rotation without
    /// recreating the endpoint (see E1). Taken out of the `Mutex` in `run`.
    endpoint: Arc<tokio::sync::Mutex<Option<wtransport::Endpoint<endpoint_side::Server>>>>,
    /// Optional second endpoint for IPv6 dual-stack.
    endpoint6: Arc<tokio::sync::Mutex<Option<wtransport::Endpoint<endpoint_side::Server>>>>,
    /// Bounds the number of concurrent sessions to protect against DoS (see E4).
    session_semaphore: Arc<Semaphore>,
    /// Per-IP rate limiter (connection attempts within sliding window).
    ip_connections: Arc<tokio::sync::Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    /// Per-session auth challenge nonces (session_id -> (nonce, created_at)).
    auth_nonces: Arc<DashMap<u64, (Vec<u8>, Instant)>>,
    /// Per-session auth attempt counters.
    auth_attempts: Arc<DashMap<u64, AtomicU32>>,
    tui: TuiHandle,
    /// Password hash for authentication (SHA-256 hex).
    password_hash: String,
    /// Atomic counter for unique session keys (wtransport session_id returns 0 for all connections).
    next_session_id: Arc<AtomicU64>,
    /// Aggregate bytes currently buffered across all reader tasks (DoS protection).
    total_buffered_bytes: Arc<AtomicUsize>,
    /// Stored key exchange packets per session, replayed to newly authenticated peers.
    key_exchange_store: Arc<DashMap<u64, Vec<Vec<u8>>>>,
}

impl RelayServer {
    pub async fn new(
        config: crate::config::ServerSettings,
        cert_manager: Arc<tokio::sync::Mutex<CertManager>>,
        tui: TuiHandle,
    ) -> anyhow::Result<Self> {
        let cert_manager = cert_manager.clone();
        let (tls_config, cert_resolver) = {
            let cm = cert_manager.lock().await;
            cm.build_dynamic_tls_config()
                .map_err(|e| anyhow::anyhow!("failed to build TLS config: {}", e))?
        };
        let session_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_SESSIONS));

        let server_config = ServerConfig::builder()
            .with_bind_address(config.address.parse()?)
            .with_custom_tls(tls_config.clone())
            .keep_alive_interval(Some(Duration::from_secs(15)))
            .build();
        let endpoint = Endpoint::server(server_config)?;

        // Optional IPv6 endpoint (separate socket).
        let endpoint6 = if !config.address6.is_empty() {
            let server_config6 = ServerConfig::builder()
                .with_bind_address(config.address6.parse()?)
                .with_custom_tls(tls_config)
                .keep_alive_interval(Some(Duration::from_secs(15)))
                .build();
            Some(Endpoint::server(server_config6)?)
        } else {
            None
        };

        let store = Arc::new(MessageStore::new());
        let (data_tx, _rx) = broadcast::channel(4096);
        let (control_tx, _crx) = broadcast::channel(64);
        let (keyexchange_tx, _krx) = broadcast::channel(512);

        let server = Self {
            config: config.clone(),
            cert_manager,
            store,
            data_tx,
            control_tx,
            keyexchange_tx,
            sessions: Arc::new(DashMap::new()),
            cert_resolver,
            endpoint: Arc::new(tokio::sync::Mutex::new(Some(endpoint))),
            endpoint6: Arc::new(tokio::sync::Mutex::new(endpoint6)),
            session_semaphore,
            ip_connections: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            auth_nonces: Arc::new(DashMap::new()),
            auth_attempts: Arc::new(DashMap::new()),
            tui: tui.clone(),
            password_hash: config.password_hash.clone(),
            next_session_id: Arc::new(AtomicU64::new(0)),
            total_buffered_bytes: Arc::new(AtomicUsize::new(0)),
            key_exchange_store: Arc::new(DashMap::new()),
        };

        // Publish static technical info for the TUI header block.
        let display_address = if config.address6.is_empty() {
            config.address.clone()
        } else {
            format!("{}, {}", config.address, config.address6)
        };
        tui.set_info(crate::tui::ServerInfo {
            address: display_address,
            san_count: config.san.len(),
            ttl_hours: crate::storage::MESSAGE_TTL.as_secs() / 3600,
            max_payload: MAX_PAYLOAD_BYTES,
            max_sessions: MAX_CONCURRENT_SESSIONS,
            version: env!("CARGO_PKG_VERSION").to_string(),
        });

        Ok(server)
    }

    pub async fn run(
        self: Arc<Self>,
        shutdown: std::sync::Arc<tokio::sync::Notify>,
    ) -> anyhow::Result<()> {
        let mut endpoint_guard = self.endpoint.lock().await;
        let server = endpoint_guard
            .take()
            .ok_or_else(|| anyhow::anyhow!("endpoint already taken"))?;
        drop(endpoint_guard);

        let mut endpoint6_guard = self.endpoint6.lock().await;
        let server6 = endpoint6_guard.take();
        drop(endpoint6_guard);

        // Spawn housekeeping (sweep + rotation + TUI cert refresh).
        self.clone().spawn_housekeeping();

        info!("WebTransport relay listening on {}", self.config.address);
        if !self.config.address6.is_empty() {
            info!(
                "WebTransport relay (IPv6) listening on {}",
                self.config.address6
            );
        }
        info!(
            "TOFU fingerprint: {}",
            self.cert_manager
                .lock()
                .await
                .current()
                .fingerprint_grouped()
        );

        // Run IPv4 accept loop; optionally run IPv6 in parallel.
        if let Some(server6) = server6 {
            let self2 = self.clone();
            let shutdown2 = shutdown.clone();
            tokio::join!(
                Self::accept_loop(self, server, shutdown),
                Self::accept_loop(self2, server6, shutdown2),
            );
        } else {
            Self::accept_loop(self, server, shutdown).await;
        }

        Ok(())
    }

    async fn accept_loop(
        self: Arc<Self>,
        server: wtransport::Endpoint<endpoint_side::Server>,
        shutdown: std::sync::Arc<tokio::sync::Notify>,
    ) {
        loop {
            #[allow(clippy::large_enum_variant)]
            enum Next {
                Session(wtransport::endpoint::IncomingSession),
                Shutdown,
            }
            let next = tokio::select! {
                incoming_session = server.accept() => Next::Session(incoming_session),
                () = shutdown.notified() => Next::Shutdown,
            };
            match next {
                Next::Shutdown => {
                    info!("Shutdown signal received, closing relay");
                    break;
                }
                Next::Session(incoming_session) => {
                    let incoming_request =
                        match tokio::time::timeout(HANDSHAKE_TIMEOUT, incoming_session).await {
                            Ok(r) => r,
                            Err(_) => {
                                warn!("Session handshake timed out");
                                continue;
                            }
                        };
                    let connection = match incoming_request {
                        Ok(r) => match r.accept().await {
                            Ok(c) => c,
                            Err(e) => {
                                warn!("Request rejected: {}", e);
                                continue;
                            }
                        },
                        Err(e) => {
                            warn!("Session handshake failed: {}", e);
                            continue;
                        }
                    };
                    info!(
                        "[CONNECT] New WebTransport session: {} from {} (cert SANs: {:?})",
                        connection.session_id().into_u64(),
                        connection.remote_address(),
                        self.config.san
                    );

                    // Per-IP rate limiting: reject if too many recent connections
                    // from the same address (within RATE_LIMIT_WINDOW).
                    let remote_ip = connection.remote_address().ip();
                    if !self.check_rate_limit(remote_ip).await {
                        connection.close(wtransport::VarInt::from(0u32), b"rate_limit");
                        continue;
                    }

                    // Bound concurrent sessions (E4): reject when at capacity to avoid
                    // unbounded memory growth / DoS. Acquire a permit for the session's
                    // lifetime; it is released when `handle_wt_session` returns.
                    let permit = match self.session_semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!(
                                "Session {} rejected: too many concurrent sessions ({})",
                                connection.session_id().into_u64(),
                                MAX_CONCURRENT_SESSIONS
                            );
                            connection.close(wtransport::VarInt::from(0u32), b"capacity");
                            continue;
                        }
                    };
                    // Generate a unique session key via atomic counter.
                    // wtransport's connection.session_id() returns 0 for all
                    // connections, so we must use our own counter to ensure
                    // each session gets a unique key for broadcast exclusion.
                    let session_key = self.next_session_id.fetch_add(1, Ordering::Relaxed);
                    info!(
                        "[CONNECT] Assigned session_key={} for remote {}",
                        session_key,
                        connection.remote_address()
                    );
                    // Spawn each session as its own task so the accept loop is never
                    // blocked by a single slow/abandoned client (K1/K2).
                    tokio::spawn(self.clone().handle_wt_session(connection, permit, session_key));
                }
            }
        }

        // Graceful shutdown: close the endpoint and let in-flight sessions
        // finish draining their writers.
        server.close(wtransport::VarInt::from(0u32), b"shutdown");
        self.sessions.clear();
        info!("Relay stopped");
    }

    /// Per-IP rate limiting shared by both transports. Returns `true` if the
    /// connection is allowed, `false` if it should be rejected.
    async fn check_rate_limit(&self, remote_ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut ip_map = self.ip_connections.lock().await;
        let times = ip_map.entry(remote_ip).or_default();
        times.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
        if times.len() >= MAX_CONNECTIONS_PER_IP {
            warn!(
                "Rate limit hit for {} ({} connections in {:?})",
                remote_ip,
                times.len(),
                RATE_LIMIT_WINDOW
            );
            return false;
        }
        times.push(now);
        true
    }

    /// Prune expired IP entries from the rate limiter to prevent memory leaks.
    async fn prune_rate_limiter(&self) {
        let now = Instant::now();
        let mut ip_map = self.ip_connections.lock().await;
        let before = ip_map.len();
        ip_map.retain(|_, times| {
            times.retain(|t| now.duration_since(*t) < RATE_LIMIT_WINDOW);
            !times.is_empty()
        });
        let pruned = before - ip_map.len();
        if pruned > 0 {
            debug!("Pruned {} expired IP rate-limiter entries", pruned);
        }
    }

    // ------------------------------------------------------------------
    // WebTransport session entry point
    // ------------------------------------------------------------------

    async fn handle_wt_session(
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
        info!(
            "[STREAM] Session {} waiting to accept bidirectional stream...",
            session_key
        );
        let (mut send_stream, recv_stream) = match connection.accept_bi().await {
            Ok(pair) => {
                info!("[STREAM] Session {} stream accepted OK", session_key);
                pair
            }
            Err(e) => {
                info!("[STREAM] Session {} accept_bi FAILED: {}", session_key, e);
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
        info!("[STREAM] Session {} sent auth challenge", session_key);

        self.run_session(session_key, remote_ip, recv_stream, send_stream, _permit)
            .await;
    }

    // ------------------------------------------------------------------
    // Session loop
    // ------------------------------------------------------------------

    async fn run_session<R, W>(
        self: Arc<Self>,
        session_key: u64,
        _remote_ip: std::net::IpAddr,
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

        // Register this session's direct sender.
        self.sessions.insert(session_key, direct_tx.clone());
        self.tui.set_stats(self.sessions.len(), self.store.len());

        // Task: forward broadcast messages AND direct responses to this session's send stream.
        let writer_task = {
            tokio::spawn(async move {
                info!("[WRITER] Session {} writer task started", session_key);
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
                                        session_key, op, opcode_name(op), packet.len());
                                            if let Err(e) = writer.write_all(&packet).await {
                                        warn!("[WRITER] Session {} write error: {}", session_key, e);
                                        break;
                                    }
                                    if let Err(e) = writer.flush().await {
                                        warn!("[WRITER] Session {} flush error: {}", session_key, e);
                                        break;
                                    }
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    warn!("[WRITER] Session {} lagged, missed {} messages, continuing",
                                        session_key, n);
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    info!("[WRITER] Session {} data channel closed", session_key);
                                    break;
                                }
                            }
                        }
                        result = control_sub.recv() => {
                            match result {
                                Ok(packet) => {
                                    let op = if packet.is_empty() { 0 } else { packet[0] };
                                    debug!("[WRITER] Session {} <- CONTROL opcode=0x{:02x} ({}) len={}",
                                        session_key, op, opcode_name(op), packet.len());
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
                                        session_key, src_session, op, opcode_name(op), packet.len());
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
                                session_key, op, opcode_name(op), packet.len());
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
                info!("[WRITER] Session {} writer task ended", session_key);
            })
        };

        // Task: read length-prefixed binary packets from the client.
        let reader_task = {
            let this = self.clone();
            let direct_tx = direct_tx.clone();
            let total_buffered = self.total_buffered_bytes.clone();
            tokio::spawn(async move {
                info!("[READER] Session {} reader task started", session_key);
                let mut buf: Vec<u8> = Vec::with_capacity(4096);
                let mut chunk = [0u8; 8192];
                let mut authenticated = false;

                loop {
                    let read =
                        tokio::time::timeout(SESSION_IDLE_TIMEOUT, reader.read(&mut chunk)).await;
                    match read {
                        Ok(Ok(0)) => {
                            info!("[READER] Session {} EOF (client disconnected)", session_key);
                            break; // EOF
                        }
                        Ok(Ok(n)) => {
                            if tracing::enabled!(tracing::Level::TRACE) {
                                trace!("[READER] Session {} raw chunk: {} bytes", session_key, n);
                                trace!(
                                    "[READER] Session {} hex: {}",
                                    session_key,
                                    hex_dump(&chunk[..n], 128)
                                );
                            }
                            // Extend buffer first, then update aggregate budget.
                            buf.extend_from_slice(&chunk[..n]);
                            let new_total = total_buffered.fetch_add(n, Ordering::Relaxed) + n;
                            if new_total > MAX_TOTAL_BUFFERED_BYTES {
                                // Roll back: remove the bytes we just added.
                                let rollback = buf.len().min(n);
                                buf.truncate(buf.len() - rollback);
                                total_buffered.fetch_sub(rollback, Ordering::Relaxed);
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
                                total_buffered.fetch_sub(buf_len, Ordering::Relaxed);
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
                                        total_buffered.fetch_sub(packet_len, Ordering::Relaxed);
                                        let op = if packet_data.is_empty() {
                                            0
                                        } else {
                                            packet_data[0]
                                        };
                                        debug!(
                                            "[READER] Session {} -> opcode=0x{:02x} ({}) total_packet={} bytes",
                                            session_key,
                                            op,
                                            opcode_name(op),
                                            packet_len
                                        );
                                        if let Err(e) = this
                                            .process_packet(
                                                session_key,
                                                &packet_data,
                                                &mut authenticated,
                                                &direct_tx,
                                            )
                                            .await
                                        {
                                            info!(
                                                "[READER] Session {} packet error: {} (authenticated={})",
                                                session_key, e, authenticated
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
                                        total_buffered.fetch_sub(1, Ordering::Relaxed);
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
                            info!("[READER] Session {} stream read error: {}", session_key, e);
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
                if !buf.is_empty() {
                    total_buffered.fetch_sub(buf.len(), Ordering::Relaxed);
                }
                info!(
                    "[READER] Session {} reader task ended (authenticated={})",
                    session_key, authenticated
                );
            })
        };

        // Wait for either task to finish, then abort the other to avoid orphaned tasks.
        info!(
            "[SESSION] Session {} waiting for writer/reader tasks to finish...",
            session_key
        );
        tokio::select! {
            _ = writer_task => {},
            _ = reader_task => {},
        }
        // Both tasks are now finished or about to be dropped. The JoinHandles
        // go out of scope here, which is fine — we don't need to abort because
        // the select! already resolved (one finished, the other was dropped).
        info!(
            "[SESSION] Session {} CLOSED (sessions_left={})",
            session_key,
            self.sessions.len().saturating_sub(1)
        );
        self.sessions.remove(&session_key);
        self.auth_nonces.remove(&session_key);
        self.auth_attempts.remove(&session_key);
        self.key_exchange_store.remove(&session_key);
        self.tui.set_stats(self.sessions.len(), self.store.len());
        info!(
            "[SESSION] Session {} cleanup complete, remaining sessions={}",
            session_key,
            self.sessions.len()
        );
    }

    async fn process_packet(
        self: &Arc<Self>,
        session_key: u64,
        packet_data: &[u8],
        authenticated: &mut bool,
        direct_tx: &mpsc::Sender<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let mut reader = PacketReader::new(packet_data);
        let opcode = reader.read_opcode().map_err(|e| anyhow::anyhow!("{}", e))?;

        match opcode {
            Opcode::Auth => {
                // Auth: [0x01] [len-prefixed: raw password bytes] [32 raw bytes: HMAC-SHA-256]
                // HMAC key = Argon2id(password) output bytes (32 bytes)
                // HMAC message = server nonce (16 bytes)
                let password_bytes = reader
                    .read_len_prefixed()
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                let password = String::from_utf8(password_bytes)
                    .map_err(|_| anyhow::anyhow!("invalid UTF-8 in password"))?;

                // Check brute-force limit.
                let attempts = self.auth_attempts.entry(session_key).or_insert_with(|| AtomicU32::new(0));
                if attempts.load(Ordering::Relaxed) >= MAX_AUTH_ATTEMPTS {
                    warn!("[AUTH] Session {} brute-force limit reached ({} attempts), closing",
                        session_key, MAX_AUTH_ATTEMPTS);
                    return Err(anyhow::anyhow!("brute-force limit exceeded"));
                }
                attempts.fetch_add(1, Ordering::Relaxed);

                // Verify password against stored Argon2 hash.
                let hash_ok = crate::config::argon2_verify(&password, &self.password_hash);
                if !hash_ok {
                    warn!("[AUTH] Session {} password verification failed", session_key);
                }

                // Derive HMAC key from Argon2 output for challenge-response.
                let argon2_key = if hash_ok {
                    use argon2::password_hash::PasswordHash;
                    use argon2::{Argon2, Algorithm, Version};
                    let parsed = PasswordHash::new(&self.password_hash)
                        .map_err(|e| anyhow::anyhow!("failed to parse stored hash: {}", e))?;
                    // Re-compute Argon2 with the SAME params stored in the hash.
                    if let Some(salt) = parsed.salt {
                        let mut raw_salt_buf = [0u8; 64];
                        let raw_salt = salt.decode_b64(&mut raw_salt_buf)
                            .map_err(|e| anyhow::anyhow!("failed to decode Argon2 salt: {}", e))?;
                        let params = argon2::Params::try_from(&parsed)
                            .map_err(|e| anyhow::anyhow!("failed to parse Argon2 params: {}", e))?;
                        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                        let mut output = [0u8; 32];
                        argon2.hash_password_into(password.as_bytes(), raw_salt, &mut output)
                            .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;
                        Some(output.to_vec())
                    } else {
                        warn!("[AUTH] Session {} Argon2 hash missing salt", session_key);
                        None
                    }
                } else {
                    None
                };

                // Verify challenge-response using HMAC-SHA-256.
                let nonce_entry = self.auth_nonces.get(&session_key);
                let nonce_valid = match nonce_entry {
                    Some(entry) => {
                        let (nonce, created_at) = entry.value();
                        let age = std::time::Instant::now().duration_since(*created_at);
                        if age > NONCE_MAX_AGE {
                            warn!("[AUTH] Session {} challenge nonce expired", session_key);
                            false
                        } else if reader.remaining().is_empty() {
                            warn!("[AUTH] Session {} missing challenge response", session_key);
                            false
                        } else {
                            // Fixed 32-byte HMAC (no length prefix).
                            let client_response = reader
                                .read_bytes(32)
                                .map_err(|e| anyhow::anyhow!("{}", e))?;

                            if let Some(ref key) = argon2_key {
                                // Verify HMAC-SHA-256(key=Argon2_output, message=nonce).
                                use hmac::{Hmac, Mac};
                                use sha2::Sha256;
                                type HmacSha256 = Hmac<Sha256>;
                                let mut mac = HmacSha256::new_from_slice(key)
                                    .map_err(|e| anyhow::anyhow!("HMAC key error: {}", e))?;
                                mac.update(nonce);
                                let ok: bool = mac.verify_slice(&client_response).is_ok();
                                if !ok {
                                    warn!("[AUTH] Session {} HMAC challenge response mismatch", session_key);
                                }
                                ok
                            } else {
                                // Password was wrong — HMAC check is irrelevant.
                                false
                            }
                        }
                    }
                    None => {
                        warn!("[AUTH] Session {} no challenge nonce found", session_key);
                        false
                    }
                };

                let ok = hash_ok && nonce_valid;
                debug!("[AUTH] Session {} hash_match={} challenge_valid={} → {}",
                    session_key, hash_ok, nonce_valid, ok);

                let response = ServerPacketEncoder::auth_result(
                    ok,
                    if ok { None } else { Some("Invalid password or challenge") },
                );
                info!(
                    "[AUTH] Session {} sending AuthResult: success={} packet_len={}",
                    session_key,
                    ok,
                    response.len()
                );

                direct_tx
                    .send(response)
                    .await
                    .map_err(|_| anyhow::anyhow!("direct channel closed"))?;

                *authenticated = ok;
                if !ok {
                    // Slow down brute-force attempts
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    info!("[AUTH] Session {} auth FAILED -> closing (authenticated was false)", session_key);
                    return Err(anyhow::anyhow!("authentication failed"));
                }
                info!(
                    "[AUTH] Session {} auth SUCCESS -> authenticated=true",
                    session_key
                );

                // Replay stored key exchanges from ALL OTHER sessions so this
                // newly-authenticated client can send messages to peers that
                // connected before it.
                let mut replayed = 0u32;
                for entry in self.key_exchange_store.iter() {
                    let src = *entry.key();
                    if src == session_key {
                        continue;
                    }
                    for packet in entry.value() {
                        if let Err(e) = direct_tx.send(packet.clone()).await {
                            warn!("[AUTH] Session {} failed to replay keyex from session {}: {}", session_key, src, e);
                        } else {
                            replayed += 1;
                        }
                    }
                }
                if replayed > 0 {
                    info!(
                        "[AUTH] Session {} replayed {} stored key exchanges from peers",
                        session_key, replayed
                    );
                }

                Ok(())
            }
            Opcode::Sync => {
                if !*authenticated {
                    info!("[SYNC] Session {} REJECTED: not authenticated", session_key);
                    return Err(anyhow::anyhow!("not authenticated"));
                }
                let last_seen_id = reader.read_u64().map_err(|e| anyhow::anyhow!("{}", e))?;
                debug!(
                    "[SYNC] Session {} sync request last_seen_id={}",
                    session_key, last_seen_id
                );

                let replay = self.store.since(last_seen_id, MAX_SYNC_MESSAGES);
                let messages: Vec<(u64, u64, Vec<u8>)> = replay
                    .into_iter()
                    .map(|m| (m.id, m.timestamp, m.payload))
                    .collect();
                debug!(
                    "[SYNC] Session {} returning {} messages",
                    session_key,
                    messages.len()
                );

                let response = ServerPacketEncoder::sync_response(&messages);
                direct_tx
                    .send(response)
                    .await
                    .map_err(|_| anyhow::anyhow!("direct channel closed"))?;
                Ok(())
            }
            Opcode::Data => {
                if !*authenticated {
                    info!("[DATA] Session {} REJECTED: not authenticated", session_key);
                    return Err(anyhow::anyhow!("not authenticated"));
                }
                let payload = reader
                    .read_len_prefixed()
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                debug!(
                    "[DATA] Session {} data payload={} bytes",
                    session_key,
                    payload.len()
                );

                if payload.len() > MAX_PAYLOAD_BYTES {
                    warn!(
                        "[DATA] Session {} OVERSIZED payload {} > {}, dropping",
                        session_key,
                        payload.len(),
                        MAX_PAYLOAD_BYTES
                    );
                    return Ok(());
                }

                let stored = self.store.push(payload.clone());
                debug!(
                    "[DATA] Session {} stored id={}, broadcasting",
                    session_key, stored.id
                );
                let relayed = RelayedMessage {
                    id: stored.id,
                    timestamp: stored.timestamp,
                    payload: stored.payload,
                };
                let subs = self.data_tx.send((session_key, relayed));
                match subs {
                    Ok(n) => debug!(
                        "[DATA] Session {} broadcast OK to {} receivers",
                        session_key, n
                    ),
                    Err(_) => debug!("[DATA] Session {} broadcast: no receivers", session_key),
                }
                Ok(())
            }
            Opcode::Heartbeat => {
                if !*authenticated {
                    info!("[HEARTBEAT] Session {} REJECTED: not authenticated", session_key);
                    return Err(anyhow::anyhow!("not authenticated"));
                }
                let client_ts = reader.read_u64().map_err(|e| anyhow::anyhow!("{}", e))?;
                debug!(
                    "[HEARTBEAT] Session {} client_ts={}",
                    session_key, client_ts
                );
                let response = ServerPacketEncoder::heartbeat(client_ts);
                direct_tx
                    .send(response)
                    .await
                    .map_err(|_| anyhow::anyhow!("direct channel closed"))?;
                Ok(())
            }
            Opcode::KeyExchangeKemDsa => {
                if !*authenticated {
                    info!(
                        "[KEYEX] Session {} REJECTED: not authenticated",
                        session_key
                    );
                    return Err(anyhow::anyhow!("not authenticated"));
                }
                let combined_payload = reader.remaining().to_vec();
                debug!(
                    "[KEYEX] Session {} combined KEM+DSA payload={} bytes",
                    session_key,
                    combined_payload.len()
                );

                // Build relay packet preserving the original client frame format:
                // [0x0C] [u32: total_inner] [u32: kem_len] [kem] [u32: dsa_len] [dsa]
                // combined_payload already contains everything after the opcode byte
                // (including the outer u32 total_inner), so just prepend the opcode.
                let mut packet = vec![opcode.as_u8()];
                packet.extend_from_slice(&combined_payload);
                let _ = self
                    .keyexchange_tx
                    .send((session_key, packet.clone()));
                self.key_exchange_store
                    .entry(session_key)
                    .or_default()
                    .push(packet);
                debug!("[KEYEX] Session {} relayed combined KEM+DSA to all peers", session_key);
                Ok(())
            }
            Opcode::AuthResult | Opcode::SyncResponse | Opcode::NewCertHash | Opcode::AuthChallenge => {
                info!(
                    "[IGNORE] Session {} received server->client opcode {:?}, ignoring",
                    session_key, opcode
                );
                Ok(())
            }
        }
    }

    fn spawn_housekeeping(self: Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(HOUSEKEEP_INTERVAL);
            let mut ip_prune_tick = tokio::time::interval(IP_PRUNE_INTERVAL);
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = ip_prune_tick.tick() => {
                        this.prune_rate_limiter().await;
                        // Prune expired auth nonces.
                        let now = Instant::now();
                        this.auth_nonces.retain(|_, (_, created_at)| {
                            now.duration_since(*created_at) < NONCE_MAX_AGE
                        });
                        // Prune orphaned auth_attempts (no matching nonce).
                        this.auth_attempts.retain(|k, _| this.auth_nonces.contains_key(k));
                        continue;
                    }
                }

                // Rotate certificate if needed and refresh TUI.
                let rotated = {
                    let mut cm = self.cert_manager.lock().await;
                    let r = cm.maybe_rotate();
                    cm.prune_previous();
                    r
                };
                if rotated {
                    // E1: apply the new certificate to the live TLS resolver so
                    // that freshly-connecting WebTransport clients immediately see
                    // it without recreating the Endpoint. Trust continuity for
                    // clients still pinned to the old fingerprint is handled at
                    // the application layer via the `NewCertHash` (0x07) broadcast.
                    let (cert, has_previous) = {
                        let cm = self.cert_manager.lock().await;
                        let provider = Arc::new(crate::cert::default_crypto_provider());
                        match cm.current().certified_key(&provider) {
                            Ok(key) => self.cert_resolver.update(key),
                            Err(e) => {
                                warn!("Failed to rebuild certified key after rotation: {}", e)
                            }
                        }
                        let cert = cm.current().clone();
                        let has_previous = cm.previous().is_some();
                        (cert, has_previous)
                    };
                    let mut view = crate::tui::CertView::from_cert(&cert);
                    view.rotating = has_previous;
                    self.tui.set_cert(view);
                    info!(
                        "Certificate rotated; new fingerprint {}",
                        cert.fingerprint_grouped()
                    );

                    // E2: announce the new fingerprint to connected clients so
                    // they can pin it before the old certificate expires (the
                    // 2-day overlap window).
                    let hash_bytes = cert.fingerprint_bytes();
                    let expires_at = cert
                        .not_after
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if let Err(e) = self
                        .control_tx
                        .send(ServerPacketEncoder::new_cert_hash(&hash_bytes, expires_at))
                    {
                        warn!("Failed to broadcast NewCertHash: {}", e);
                    }
                    info!("Applied rotated certificate to live TLS resolver");
                }

                let removed = self.store.sweep();
                if removed > 0 {
                    debug!("Swept {} expired messages", removed);
                }
                self.tui.set_stats(self.sessions.len(), self.store.len());
            }
        });
    }
}

/// Result of [`try_read_packet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TryReadResult {
    /// A full packet is available (consumable now). Inner is the packet length.
    Packet(usize),
    /// Buffer is incomplete; wait for more bytes.
    Incomplete,
    /// Leading byte is not a recognized client opcode — skip 1 byte and retry.
    UnknownOpcode,
    /// The declared payload length exceeds `MAX_PACKET_LEN` — the session
    /// must be closed because the stream is corrupted beyond recovery.
    OversizedPayload,
}

/// Try to read a complete packet length from the buffer.
pub(crate) fn try_read_packet(buf: &[u8]) -> TryReadResult {
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

    const MAX_PACKET_LEN: usize = 1 + 4 + MAX_PAYLOAD_BYTES;

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
