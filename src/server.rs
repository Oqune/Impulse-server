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
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Semaphore, broadcast, mpsc};
use tracing::{debug, info, warn};
use wtransport::endpoint::endpoint_side;
use wtransport::{Endpoint, ServerConfig};

use crate::cert::CertManager;
use crate::cert::DynamicCertResolver;
use crate::protocol::{
    Opcode, PacketReader, RelayedMessage, ServerPacketEncoder, encode_key_exchange,
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
        0x08 => "KeyExchange",
        0x09 => "KeyExchangeKem",
        0x0A => "KeyExchangeDsa",
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
const MAX_PAYLOAD_BYTES: usize = 1_000_000;

/// Max bytes buffered from a single stream before we give up (defensive).
const MAX_STREAM_BUFFER: usize = 8 * 1024 * 1024;

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
const MAX_SYNC_MESSAGES: usize = 500;

/// Max connections per IP within the rate-limit window.
const MAX_CONNECTIONS_PER_IP: usize = 10;

/// Rate-limit window duration.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(10);

/// WebTransport handshake timeout.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Shared server state.
pub struct RelayServer {
    config: crate::config::ServerSettings,
    cert_manager: Arc<std::sync::Mutex<CertManager>>,
    store: Arc<MessageStore>,
    /// Broadcast hub for relayed data messages.
    data_tx: broadcast::Sender<RelayedMessage>,
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
    /// Bounds the number of concurrent sessions to protect against DoS (see E4).
    session_semaphore: Arc<Semaphore>,
    /// Per-IP rate limiter (connection attempts within sliding window).
    ip_connections: Arc<std::sync::Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    tui: TuiHandle,
    /// Password hash for authentication (SHA-256 hex).
    password_hash: String,
}

impl RelayServer {
    pub fn new(
        config: crate::config::ServerSettings,
        cert_manager: Arc<std::sync::Mutex<CertManager>>,
        tui: TuiHandle,
    ) -> anyhow::Result<Self> {
        let cert_manager = cert_manager.clone();
        let (tls_config, cert_resolver) = cert_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .build_dynamic_tls_config()
            .map_err(|e| anyhow::anyhow!("failed to build TLS config: {}", e))?;
        let session_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_SESSIONS));

        let server_config = ServerConfig::builder()
            .with_bind_address(config.address.parse()?)
            .with_custom_tls(tls_config)
            .keep_alive_interval(Some(Duration::from_secs(15)))
            .build();
        let endpoint = Endpoint::server(server_config)?;

        let store = Arc::new(MessageStore::new());
        let (data_tx, _rx) = broadcast::channel(1024);
        let (control_tx, _crx) = broadcast::channel(32);
        let (keyexchange_tx, _krx) = broadcast::channel(256);

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
            session_semaphore,
            ip_connections: Arc::new(std::sync::Mutex::new(HashMap::new())),
            tui: tui.clone(),
            password_hash: config.password_hash.clone(),
        };

        // Publish static technical info for the TUI header block.
        tui.set_info(crate::tui::ServerInfo {
            address: config.address.clone(),
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

        // Spawn housekeeping (sweep + rotation + TUI cert refresh).
        self.clone().spawn_housekeeping();

        info!("WebTransport relay listening on {}", self.config.address);
        info!(
            "TOFU fingerprint: {}",
            self.cert_manager
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .current()
                .fingerprint_grouped()
        );

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
                    if !self.check_rate_limit(remote_ip) {
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
                    // Spawn each session as its own task so the accept loop is never
                    // blocked by a single slow/abandoned client (K1/K2).
                    tokio::spawn(self.clone().handle_wt_session(connection, permit));
                }
            }
        }

        // Graceful shutdown: close the endpoint and let in-flight sessions
        // finish draining their writers.
        server.close(wtransport::VarInt::from(0u32), b"shutdown");
        self.sessions.clear();
        info!("Relay stopped");
        Ok(())
    }

    /// Per-IP rate limiting shared by both transports. Returns `true` if the
    /// connection is allowed, `false` if it should be rejected.
    fn check_rate_limit(&self, remote_ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut ip_map = self
            .ip_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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

    // ------------------------------------------------------------------
    // WebTransport session entry point
    // ------------------------------------------------------------------

    async fn handle_wt_session(
        self: Arc<Self>,
        connection: wtransport::Connection,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        let session_key: u64 = connection.session_id().into_u64();
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
        let (send_stream, recv_stream) = match connection.accept_bi().await {
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

        self.run_session(session_key, remote_ip, recv_stream, send_stream, _permit)
            .await;
    }

    // ------------------------------------------------------------------
    // Session loop
    // ------------------------------------------------------------------

    async fn run_session<R, W>(
        self: Arc<Self>,
        session_key: u64,
        _remote_ip: IpAddr,
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
                                Ok(msg) => {
                                    let packet = msg.to_packet();
                                    let op = if packet.is_empty() { 0 } else { packet[0] };
                                    info!("[WRITER] Session {} <- DATA relay opcode=0x{:02x} ({}) len={}",
                                        session_key, op, opcode_name(op), packet.len());
                                    if let Err(e) = writer.write_all(&packet).await {
                                        info!("[WRITER] Session {} write error: {}", session_key, e);
                                        break;
                                    }
                                    if let Err(e) = writer.flush().await {
                                        info!("[WRITER] Session {} flush error: {}", session_key, e);
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
                                    info!("[WRITER] Session {} <- CONTROL opcode=0x{:02x} ({}) len={}",
                                        session_key, op, opcode_name(op), packet.len());
                                    if let Err(e) = writer.write_all(&packet).await {
                                        info!("[WRITER] Session {} control write error: {}", session_key, e);
                                        break;
                                    }
                                    if let Err(e) = writer.flush().await {
                                        info!("[WRITER] Session {} control flush error: {}", session_key, e);
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
                                    info!("[WRITER] Session {} <- KEYEXCHANGE (from session {}) opcode=0x{:02x} ({}) len={}",
                                        session_key, src_session, op, opcode_name(op), packet.len());
                                    if let Err(e) = writer.write_all(&packet).await {
                                        info!("[WRITER] Session {} keyexchange write error: {}", session_key, e);
                                        break;
                                    }
                                    if let Err(e) = writer.flush().await {
                                        info!("[WRITER] Session {} keyexchange flush error: {}", session_key, e);
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
                            info!("[WRITER] Session {} <- DIRECT opcode=0x{:02x} ({}) len={}",
                                session_key, op, opcode_name(op), packet.len());
                            if let Err(e) = writer.write_all(&packet).await {
                                info!("[WRITER] Session {} direct write error: {}", session_key, e);
                                break;
                            }
                            if let Err(e) = writer.flush().await {
                                info!("[WRITER] Session {} direct flush error: {}", session_key, e);
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
                            debug!("[READER] Session {} raw chunk: {} bytes", session_key, n);
                            debug!(
                                "[READER] Session {} hex: {}",
                                session_key,
                                hex_dump(&chunk[..n], 128)
                            );
                            buf.extend_from_slice(&chunk[..n]);
                            debug!(
                                "[READER] Session {} buffer now {} bytes",
                                session_key,
                                buf.len()
                            );
                            if buf.len() > MAX_STREAM_BUFFER {
                                info!(
                                    "[READER] Session {} BUFFER OVERFLOW ({} > {}), closing",
                                    session_key,
                                    buf.len(),
                                    MAX_STREAM_BUFFER
                                );
                                break;
                            }
                            // Process all complete packets.
                            loop {
                                match try_read_packet(&buf) {
                                    Ok(Some(packet_len)) => {
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
                                        let op = if packet_data.is_empty() {
                                            0
                                        } else {
                                            packet_data[0]
                                        };
                                        info!(
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
                                    Ok(None) => {
                                        info!(
                                            "[READER] Session {} incomplete packet, waiting for more data (buf={} bytes)",
                                            session_key,
                                            buf.len()
                                        );
                                        break; // incomplete, wait for more data
                                    }
                                    Err(()) => {
                                        info!(
                                            "[READER] Session {} UNKNOWN OPCODE in buffer (first byte=0x{:02x}), closing",
                                            session_key,
                                            if buf.is_empty() { 0 } else { buf[0] }
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            info!("[READER] Session {} stream read error: {}", session_key, e);
                            break;
                        }
                        Err(_) => {
                            info!(
                                "[READER] Session {} IDLE TIMEOUT ({}s, no data from client)",
                                session_key,
                                SESSION_IDLE_TIMEOUT.as_secs()
                            );
                            break;
                        }
                    }
                }
                info!(
                    "[READER] Session {} reader task ended (authenticated={})",
                    session_key, authenticated
                );
            })
        };

        // Wait for either task to finish, then clean up.
        info!(
            "[SESSION] Session {} waiting for writer/reader tasks to finish...",
            session_key
        );
        tokio::select! {
            _ = writer_task => {
                info!("[SESSION] Session {} writer task finished first", session_key);
            },
            _ = reader_task => {
                info!("[SESSION] Session {} reader task finished first", session_key);
            },
        }
        info!(
            "[SESSION] Session {} CLOSED (sessions_left={})",
            session_key,
            self.sessions.len().saturating_sub(1)
        );
        self.sessions.remove(&session_key);
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
                // Auth: [0x01] [SHA-256(password) as lowercase hex UTF-8]
                let password_hash = reader
                    .read_len_prefixed()
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                let password_hash_str = String::from_utf8(password_hash)
                    .map_err(|_| anyhow::anyhow!("invalid UTF-8 in password"))?;

                info!(
                    "[AUTH] Session {} got password_hash='{}' ({} hex chars)",
                    session_key,
                    &password_hash_str[..8],
                    password_hash_str.len()
                );
                info!(
                    "[AUTH] Session {} stored hash='{}' ({} hex chars)",
                    session_key,
                    &self.password_hash[..8],
                    self.password_hash.len()
                );

                use subtle::ConstantTimeEq;
                let ok = password_hash_str
                    .as_bytes()
                    .ct_eq(self.password_hash.as_bytes())
                    .into();
                info!("[AUTH] Session {} passwords MATCH={}", session_key, ok);

                let response = ServerPacketEncoder::auth_result(
                    ok,
                    if ok { None } else { Some("Invalid password") },
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
                    info!("[AUTH] Session {} auth FAILED -> closing", session_key);
                    return Err(anyhow::anyhow!("authentication failed"));
                }
                info!(
                    "[AUTH] Session {} auth SUCCESS -> authenticated=true",
                    session_key
                );
                Ok(())
            }
            Opcode::Sync => {
                if !*authenticated {
                    info!("[SYNC] Session {} REJECTED: not authenticated", session_key);
                    return Err(anyhow::anyhow!("not authenticated"));
                }
                let last_seen_id = reader.read_u64().map_err(|e| anyhow::anyhow!("{}", e))?;
                info!(
                    "[SYNC] Session {} sync request last_seen_id={}",
                    session_key, last_seen_id
                );

                let replay = self.store.since(last_seen_id, MAX_SYNC_MESSAGES);
                let messages: Vec<(u64, u64, Vec<u8>)> = replay
                    .into_iter()
                    .map(|m| (m.id, m.timestamp, m.payload))
                    .collect();
                info!(
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
                info!(
                    "[DATA] Session {} data payload={} bytes",
                    session_key,
                    payload.len()
                );

                if payload.len() > MAX_PAYLOAD_BYTES {
                    info!(
                        "[DATA] Session {} OVERSIZED payload {} > {}, dropping",
                        session_key,
                        payload.len(),
                        MAX_PAYLOAD_BYTES
                    );
                    return Ok(());
                }

                let stored = self.store.push(payload.clone());
                info!(
                    "[DATA] Session {} stored id={}, broadcasting",
                    session_key, stored.id
                );
                let relayed = RelayedMessage {
                    id: stored.id,
                    timestamp: stored.timestamp,
                    payload: stored.payload,
                };
                let subs = self.data_tx.send(relayed);
                match subs {
                    Ok(n) => info!(
                        "[DATA] Session {} broadcast OK to {} receivers",
                        session_key, n
                    ),
                    Err(_) => info!("[DATA] Session {} broadcast: no receivers", session_key),
                }
                Ok(())
            }
            Opcode::Heartbeat => {
                let client_ts = reader.read_u64().map_err(|e| anyhow::anyhow!("{}", e))?;
                info!(
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
            Opcode::KeyExchange => {
                if !*authenticated {
                    info!(
                        "[KEYEX] Session {} REJECTED: not authenticated",
                        session_key
                    );
                    return Err(anyhow::anyhow!("not authenticated"));
                }
                let public_key = reader
                    .read_len_prefixed()
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                info!(
                    "[KEYEX] Session {} public_key={} bytes",
                    session_key,
                    public_key.len()
                );

                let _ = self
                    .keyexchange_tx
                    .send((session_key, encode_key_exchange(&public_key)));
                info!("[KEYEX] Session {} relayed to all peers", session_key);
                Ok(())
            }
            Opcode::KeyExchangeKem | Opcode::KeyExchangeDsa => {
                if !*authenticated {
                    info!(
                        "[KEYEX] Session {} REJECTED: not authenticated",
                        session_key
                    );
                    return Err(anyhow::anyhow!("not authenticated"));
                }
                let public_key = reader
                    .read_len_prefixed()
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                info!(
                    "[KEYEX] Session {} {} public_key={} bytes",
                    session_key,
                    opcode_name(opcode as u8),
                    public_key.len()
                );

                let _ = self
                    .keyexchange_tx
                    .send((session_key, encode_key_exchange(&public_key)));
                info!("[KEYEX] Session {} relayed to all peers", session_key);
                Ok(())
            }
            Opcode::AuthResult | Opcode::SyncResponse | Opcode::NewCertHash => {
                info!(
                    "[IGNORE] Session {} received server->client opcode {:?}, ignoring",
                    session_key, opcode
                );
                Ok(())
            }
        }
    }

    fn spawn_housekeeping(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(HOUSEKEEP_INTERVAL);
            loop {
                tick.tick().await;

                // Rotate certificate if needed and refresh TUI.
                let rotated = {
                    let mut cm = self.cert_manager.lock().unwrap_or_else(|e| e.into_inner());
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
                    {
                        let cm = self.cert_manager.lock().unwrap_or_else(|e| e.into_inner());
                        let provider = Arc::new(crate::cert::default_crypto_provider());
                        match cm.current().certified_key(&provider) {
                            Ok(key) => self.cert_resolver.update(key),
                            Err(e) => {
                                warn!("Failed to rebuild certified key after rotation: {}", e)
                            }
                        }
                    }

                    let cert = self
                        .cert_manager
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .current()
                        .clone();
                    // During the overlap window the previous cert is still valid;
                    // surface that in the TUI.
                    let mut view = crate::tui::CertView::from_cert(&cert);
                    view.rotating = self
                        .cert_manager
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .previous()
                        .is_some();
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
                    let _ = self
                        .control_tx
                        .send(ServerPacketEncoder::new_cert_hash(&hash_bytes, expires_at));
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

/// Try to read a complete packet length from the buffer.
///
/// * `Ok(Some(packet_len))` — a full packet is available (consumable now).
/// * `Ok(None)` — buffer is incomplete; wait for more bytes.
/// * `Err(())` — the leading opcode is unknown. This is a fatal protocol
///   violation, not "incomplete": the caller should close the connection.
///   Returning `Ok(None)` here would let a single stray byte freeze parsing
///   and grow the buffer unboundedly (DoS, E3).
fn try_read_packet(buf: &[u8]) -> Result<Option<usize>, ()> {
    if buf.is_empty() {
        return Ok(None);
    }
    let opcode = buf[0];
    // Only client→server opcodes are accepted on the inbound stream. Opcodes
    // 0x02/0x04/0x07 are server→client only; receiving them from a client is a
    // protocol violation (and 0x04 in particular would otherwise make the
    // length parser iterate up to `count` times — a CPU-DoS, see C1).
    let min_len = match opcode {
        0x01 => 1 + 4,       // Auth: opcode + len prefix (min)
        0x03 => 1 + 8,       // Sync: opcode + u64
        0x05 => 1 + 4,       // Data: opcode + len prefix
        0x06 => 1 + 8,       // Heartbeat: opcode + u64
        0x08 => 1 + 4,       // KeyExchange: opcode + len prefix
        0x09 => 1 + 4,       // KeyExchangeKem: opcode + len prefix
        0x0A => 1 + 4,       // KeyExchangeDsa: opcode + len prefix
        _ => return Err(()), // Unknown opcode / server-only opcode -> violation
    };
    if buf.len() < min_len {
        return Ok(None);
    }

    // For length-prefixed packets, read the length field. Only client→server
    // opcodes remain here (server→client ones already returned Err above).
    let len = match opcode {
        0x01 | 0x05 | 0x08 | 0x09 | 0x0A => {
            if buf.len() < 5 {
                return Ok(None);
            }
            // payload length is the u32 right after the opcode
            u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize
        }
        0x03 | 0x06 => {
            // Sync / Heartbeat: fixed 1 (opcode) + 8 (u64)
            return Ok(Some(9));
        }
        _ => return Err(()),
    };
    // Bound the declared payload length to match the maximum accepted payload
    // (MAX_PAYLOAD_BYTES = 1_000_000) so a malicious `len` cannot make us
    // reserve an absurd buffer or report a huge "incomplete" packet (C1).
    const MAX_PACKET_LEN: usize = 1 + 4 + MAX_PAYLOAD_BYTES; // opcode + len + payload
    if len > MAX_PACKET_LEN {
        return Err(());
    }
    // Full packet = opcode (1) + length field (4) + payload (len).
    Ok(Some(1 + 4 + len))
}
