//! WebTransport (QUIC/HTTP3) relay server.
//!
//! Responsibilities:
//!   * Accept WebTransport sessions using the managed self-signed certificate.
//!   * For each session, open a bidirectional stream of length-prefixed binary
//!     [`Opcode`] packets.
//!   * The server never decrypts payloads; it only forwards opaque bytes.
//!   * Periodically sweep expired messages and rotate the certificate.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Semaphore, broadcast, mpsc};
use tracing::{debug, info, warn};
use wtransport::endpoint::endpoint_side;
use wtransport::{Endpoint, ServerConfig, SessionId};

use crate::cert::CertManager;
use crate::cert::DynamicCertResolver;
use crate::protocol::{Opcode, PacketReader, RelayedMessage, ServerPacketEncoder};
use crate::storage::MessageStore;
use crate::tui::TuiHandle;

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
    keyexchange_tx: broadcast::Sender<(SessionId, Vec<u8>)>,
    /// Active sessions registry for direct sends.
    sessions: Arc<DashMap<SessionId, mpsc::Sender<Vec<u8>>>>,
    /// Dynamic TLS certificate resolver. Swapping its inner certificate set on
    /// rotation makes freshly-connecting clients immediately see the new
    /// certificate without recreating the `Endpoint` (see E1).
    cert_resolver: Arc<DynamicCertResolver>,
    /// Pre-built WebTransport `Endpoint` (binds the `cert_resolver`). Built once
    /// in `new()`; the certificate resolver is swapped on rotation without
    /// recreating the endpoint (see E1). Taken out of the `Mutex` in `run`.
    endpoint: Arc<tokio::sync::Mutex<Option<wtransport::Endpoint<endpoint_side::Server>>>>,
    /// Bounds the number of concurrent sessions to protect against DoS (see E4).
    session_semaphore: Arc<Semaphore>,
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
        let (tls_config, cert_resolver) =
            cert_manager
                .lock()
                .unwrap()
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
                .unwrap()
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
                    let incoming_request = incoming_session.await;
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
                    info!("New WebTransport session: {}", connection.session_id());

                    // Bound concurrent sessions (E4): reject when at capacity to avoid
                    // unbounded memory growth / DoS. Acquire a permit for the session's
                    // lifetime; it is released when `handle_session` returns.
                    let permit = match self.session_semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!(
                                "Session {} rejected: too many concurrent sessions ({})",
                                connection.session_id(),
                                MAX_CONCURRENT_SESSIONS
                            );
                            connection.close(wtransport::VarInt::from(0u32), b"capacity");
                            continue;
                        }
                    };
                    // Spawn each session as its own task so the accept loop is never
                    // blocked by a single slow/abandoned client (K1/K2). `SessionId` is
                    // `Send + Sync` (it is a `u64` wrapper shared via broadcast channels),
                    // and the `OwnedSemaphorePermit` is `Send`, so this is sound.
                    tokio::spawn(self.clone().handle_session(connection, permit));
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

    async fn handle_session(
        self: Arc<Self>,
        connection: wtransport::Connection,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        let session_id: SessionId = connection.session_id();

        // Each session gets its own broadcast subscriptions.
        let mut data_sub = self.data_tx.subscribe();
        let mut control_sub = self.control_tx.subscribe();
        let mut keyexchange_sub = self.keyexchange_tx.subscribe();

        // Channel for direct responses (SyncResponse, Heartbeat, AuthResult)
        let (direct_tx, mut direct_rx) = mpsc::channel::<Vec<u8>>(32);

        // Register this session's direct sender.
        self.sessions.insert(session_id, direct_tx.clone());
        self.tui.set_stats(self.sessions.len(), self.store.len());

        // Open a bidirectional stream for the control/data channel.
        let (send_stream, recv_stream) = match connection.clone().open_bi().await {
            Ok(opening) => match opening.await {
                Ok(pair) => pair,
                Err(e) => {
                    warn!("Failed to open stream for session {}: {}", session_id, e);
                    connection.close(wtransport::VarInt::from(0u32), b"stream");
                    self.sessions.remove(&session_id);
                    self.tui.set_stats(self.sessions.len(), self.store.len());
                    return;
                }
            },
            Err(e) => {
                warn!("Failed to open stream for session {}: {}", session_id, e);
                connection.close(wtransport::VarInt::from(0u32), b"stream");
                self.sessions.remove(&session_id);
                self.tui.set_stats(self.sessions.len(), self.store.len());
                return;
            }
        };

        let (mut send_stream, mut recv_stream) = (send_stream, recv_stream);

        // Task: forward broadcast messages AND direct responses to this session's send stream.
        let writer_task = {
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        Ok(msg) = data_sub.recv() => {
                            let packet = msg.to_packet();
                            if let Err(e) = send_stream.write_all(&packet).await {
                                debug!("Send error to session {}: {}", session_id, e);
                                break;
                            }
                            if let Err(e) = send_stream.flush().await {
                                debug!("Flush error to session {}: {}", session_id, e);
                                break;
                            }
                        }
                        Ok(packet) = control_sub.recv() => {
                            if let Err(e) = send_stream.write_all(&packet).await {
                                debug!("Control send error to session {}: {}", session_id, e);
                                break;
                            }
                            if let Err(e) = send_stream.flush().await {
                                debug!("Control flush error to session {}: {}", session_id, e);
                                break;
                            }
                        }
                        Ok((src_session, packet)) = keyexchange_sub.recv() => {
                            if src_session == session_id {
                                continue; // skip own key exchange
                            }
                            if let Err(e) = send_stream.write_all(&packet).await {
                                debug!("KeyExchange send error to session {}: {}", session_id, e);
                                break;
                            }
                            if let Err(e) = send_stream.flush().await {
                                debug!("KeyExchange flush error to session {}: {}", session_id, e);
                                break;
                            }
                        }
                        Some(packet) = direct_rx.recv() => {
                            if let Err(e) = send_stream.write_all(&packet).await {
                                debug!("Direct send error to session {}: {}", session_id, e);
                                break;
                            }
                            if let Err(e) = send_stream.flush().await {
                                debug!("Direct flush error to session {}: {}", session_id, e);
                                break;
                            }
                        }
                        else => break,
                    }
                }
                let _ = send_stream.finish().await;
            })
        };

        // Task: read length-prefixed binary packets from the client.
        let reader_task = {
            let this = self.clone();
            let direct_tx = direct_tx.clone();
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::with_capacity(4096);
                let mut chunk = [0u8; 8192];
                let mut authenticated = false;

                loop {
                    let read =
                        tokio::time::timeout(SESSION_IDLE_TIMEOUT, recv_stream.read(&mut chunk))
                            .await;
                    match read {
                        Ok(Ok(Some(n))) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.len() > MAX_STREAM_BUFFER {
                                warn!("Session {} stream buffer overflow", session_id);
                                break;
                            }
                            // Process all complete packets.
                            loop {
                                match try_read_packet(&buf) {
                                    Ok(Some(packet_len)) => {
                                        if packet_len > buf.len() {
                                            break; // incomplete packet, need more data
                                        }
                                        let packet_data: Vec<u8> =
                                            buf.drain(..packet_len).collect();
                                        if let Err(e) = this
                                            .process_packet(
                                                session_id,
                                                &packet_data,
                                                &mut authenticated,
                                                &direct_tx,
                                            )
                                            .await
                                        {
                                            warn!("Session {} packet error: {}", session_id, e);
                                            break;
                                        }
                                    }
                                    Ok(None) => break, // incomplete, wait for more data
                                    Err(()) => {
                                        // Unknown opcode: treat as a fatal protocol
                                        // violation (not "incomplete"), close the
                                        // connection to prevent buffer-exhaustion DoS
                                        // (E3).
                                        warn!("Session {} unknown opcode, closing", session_id);
                                        break;
                                    }
                                }
                            }
                        }
                        Ok(Ok(None)) => break, // EOF
                        Ok(Err(e)) => {
                            debug!("Receive error from session {}: {}", session_id, e);
                            break;
                        }
                        Err(_) => {
                            warn!(
                                "Session {} idle timeout ({}s)",
                                session_id,
                                SESSION_IDLE_TIMEOUT.as_secs()
                            );
                            break;
                        }
                    }
                }
            })
        };

        // Wait for either task to finish, then clean up.
        tokio::select! {
            _ = writer_task => {},
            _ = reader_task => {},
        }
        info!("WebTransport session {} closed", session_id);
        self.sessions.remove(&session_id);
        self.tui.set_stats(self.sessions.len(), self.store.len());
        connection.close(wtransport::VarInt::from(0u32), b"bye");
    }

    async fn process_packet(
        self: &Arc<Self>,
        session_id: SessionId,
        packet_data: &[u8],
        authenticated: &mut bool,
        direct_tx: &mpsc::Sender<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let mut reader = PacketReader::new(packet_data);
        let opcode = reader.read_opcode().map_err(|e| anyhow::anyhow!("{}", e))?;

        match opcode {
            Opcode::Auth => {
                // Auth: [0x01] [password UTF-8]
                let password_bytes = reader
                    .read_len_prefixed()
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                let password = String::from_utf8(password_bytes)
                    .map_err(|_| anyhow::anyhow!("invalid UTF-8 in password"))?;

                // Verify password hash (SHA-256), compared in constant time to
                // avoid timing side-channels (C2).
                use sha2::{Digest, Sha256};
                use subtle::ConstantTimeEq;
                let mut hasher = Sha256::new();
                hasher.update(password.as_bytes());
                let hash = hex::encode(hasher.finalize());

                let ok = hash.as_bytes().ct_eq(self.password_hash.as_bytes()).into();
                let response = ServerPacketEncoder::auth_result(
                    ok,
                    if ok { None } else { Some("Invalid password") },
                );

                direct_tx
                    .send(response)
                    .await
                    .map_err(|_| anyhow::anyhow!("direct channel closed"))?;

                *authenticated = ok;
                if !ok {
                    return Err(anyhow::anyhow!("authentication failed"));
                }
                Ok(())
            }
            Opcode::Sync => {
                if !*authenticated {
                    return Err(anyhow::anyhow!("not authenticated"));
                }
                // Sync: [0x03] [8 bytes last_seen_id]
                let last_seen_id = reader.read_u64().map_err(|e| anyhow::anyhow!("{}", e))?;

                debug!(
                    "Session {} sync request last_seen_id={}",
                    session_id, last_seen_id
                );
                let replay = self.store.since(last_seen_id, MAX_SYNC_MESSAGES);
                let messages: Vec<(u64, u64, Vec<u8>)> = replay
                    .into_iter()
                    .map(|m| (m.id, m.timestamp, m.payload))
                    .collect();

                let response = ServerPacketEncoder::sync_response(&messages);
                direct_tx
                    .send(response)
                    .await
                    .map_err(|_| anyhow::anyhow!("direct channel closed"))?;
                Ok(())
            }
            Opcode::Data => {
                if !*authenticated {
                    return Err(anyhow::anyhow!("not authenticated"));
                }
                // Data (client→server): [0x05] [4 bytes len] [len bytes payload]
                let payload = reader
                    .read_len_prefixed()
                    .map_err(|e| anyhow::anyhow!("{}", e))?;

                if payload.len() > MAX_PAYLOAD_BYTES {
                    warn!(
                        "Session {} sent oversized payload ({} bytes), dropping",
                        session_id,
                        payload.len()
                    );
                    return Ok(());
                }

                let stored = self.store.push(payload.clone());
                let relayed = RelayedMessage {
                    id: stored.id,
                    timestamp: stored.timestamp,
                    payload: stored.payload,
                };
                let _ = self.data_tx.send(relayed);
                Ok(())
            }
            Opcode::Heartbeat => {
                // Heartbeat: [0x06] [8 bytes client_timestamp]
                let client_ts = reader.read_u64().map_err(|e| anyhow::anyhow!("{}", e))?;
                let response = ServerPacketEncoder::heartbeat(client_ts);
                direct_tx
                    .send(response)
                    .await
                    .map_err(|_| anyhow::anyhow!("direct channel closed"))?;
                Ok(())
            }
            Opcode::KeyExchange => {
                if !*authenticated {
                    return Err(anyhow::anyhow!("not authenticated"));
                }
                // KeyExchange: [0x08] [4 bytes len] [len bytes public_key]
                let public_key = reader
                    .read_len_prefixed()
                    .map_err(|e| anyhow::anyhow!("{}", e))?;

                // Relay to all OTHER clients via keyexchange channel
                let _ = self.keyexchange_tx.send((session_id, public_key));
                Ok(())
            }
            Opcode::AuthResult | Opcode::SyncResponse | Opcode::NewCertHash => {
                // Server→client only, ignore if received from client
                debug!(
                    "Received server→client opcode {:?} from client, ignoring",
                    opcode
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
                    let mut cm = self.cert_manager.lock().unwrap();
                    let r = cm.maybe_rotate();
                    cm.prune_previous();
                    r
                };
                if rotated {
                    // E1: apply the new certificate to the live TLS resolver so
                    // that freshly-connecting clients immediately see it without
                    // recreating the Endpoint. Trust continuity for clients still
                    // pinned to the old fingerprint is handled at the application
                    // layer via the `NewCertHash` (0x07) broadcast below.
                    {
                        let cm = self.cert_manager.lock().unwrap();
                        let provider = Arc::new(crate::cert::default_crypto_provider());
                        match cm.current().certified_key(&provider) {
                            Ok(key) => self.cert_resolver.update(key),
                            Err(e) => {
                                warn!("Failed to rebuild certified key after rotation: {}", e)
                            }
                        }
                    }

                    let cert = self.cert_manager.lock().unwrap().current().clone();
                    // During the overlap window the previous cert is still valid;
                    // surface that in the TUI.
                    let mut view = crate::tui::CertView::from_cert(&cert);
                    view.rotating = self.cert_manager.lock().unwrap().previous().is_some();
                    self.tui.set_cert(view);
                    info!(
                        "Certificate rotated; new fingerprint {}",
                        cert.fingerprint_grouped()
                    );

                    // E2: broadcast the 32-byte SHA-256 fingerprint (TOFU hash),
                    // matching what a WebTransport client compares against
                    // `serverCertificateHashes`, not the full DER cert.
                    let hash_bytes = cert.fingerprint_bytes();
                    let expires_at = cert
                        .not_after
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let packet = ServerPacketEncoder::new_cert_hash(&hash_bytes, expires_at);
                    let _ = self.control_tx.send(packet);
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
        _ => return Err(()), // Unknown opcode / server-only opcode -> violation
    };
    if buf.len() < min_len {
        return Ok(None);
    }

    // For length-prefixed packets, read the length field. Only client→server
    // opcodes remain here (server→client ones already returned Err above).
    let len = match opcode {
        0x01 | 0x05 | 0x08 => {
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
    // Bound the declared payload length so a malicious `len` cannot make us
    // reserve an absurd buffer or report a huge "incomplete" packet (C1).
    const MAX_PACKET_LEN: usize = 16 * 1024 * 1024;
    if len > MAX_PACKET_LEN {
        return Err(());
    }
    // Full packet = opcode (1) + length field (4) + payload (len).
    Ok(Some(1 + 4 + len))
}
