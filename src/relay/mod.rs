//! WebTransport (QUIC/HTTP3) relay server.
//!
//! Responsibilities:
//!   * Accept WebTransport sessions using the managed self-signed certificate.
//!   * For each session, run a bidirectional loop of length-prefixed binary
//!     [`Opcode`] packets.
//!   * The server never decrypts payloads; it only forwards opaque bytes.
//!   * Periodically sweep expired messages and rotate the certificate.
//!   * Publish live [`ServerStats`] for the TUI.

pub mod auth;
pub mod housekeeping;
pub mod session;
pub mod stats;

pub use session::SessionMeta;
pub use stats::ServerStats;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::{Semaphore, broadcast};
use tracing::{debug, info, warn};
use wtransport::endpoint::endpoint_side;
use wtransport::{Endpoint, ServerConfig};

use crate::cert::CertManager;
use crate::cert::DynamicCertResolver;
use crate::protocol::limits::MAX_PAYLOAD_BYTES;
use crate::protocol::{Opcode, RelayedMessage};
use crate::storage::MessageStore;
use crate::ui::TuiHandle;

fn op_name(op: u8) -> &'static str {
    Opcode::from_u8(op).map(Opcode::display_name).unwrap_or("UNKNOWN")
}

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
    /// Live-session registry keyed by session id, feeding the TUI session table.
    sessions: Arc<DashMap<u64, SessionMeta>>,
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
    /// Live counters shared with the TUI (spec §3 "Atomics shared with the relay").
    stats: Arc<ServerStats>,
    /// Stored key exchange packets per session, replayed to newly authenticated peers.
    key_exchange_store: Arc<DashMap<u64, Vec<Vec<u8>>>>,
    /// Maximum age of a challenge nonce before it is discarded.
    nonce_max_age: Duration,
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

        // The TUI and the relay MUST share the same `ServerStats` (spec §3
        // "Atomics shared with the relay") — a separate Arc would make the TUI
        // show only zeros for every counter the relay increments.
        let stats = tui.stats_handle();
        tui.set_stats(0);

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
            stats,
            key_exchange_store: Arc::new(DashMap::new()),
            nonce_max_age: NONCE_MAX_AGE,
        };

        // Publish static technical info for the TUI header block.
        let display_address = if config.address6.is_empty() {
            config.address.clone()
        } else {
            format!("{}, {}", config.address, config.address6)
        };
        tui.set_info(crate::ui::view::ServerInfo {
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
                        self.stats.rate_limited.fetch_add(1, Ordering::Relaxed);
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

    /// Snapshot the live-session registry as rows for the TUI sessions panel.
    fn session_rows(&self) -> Vec<crate::ui::view::SessionRow> {
        self.sessions
            .iter()
            .map(|entry| crate::ui::view::SessionRow {
                key: *entry.key(),
                ip: entry.value().ip,
                authenticated: entry.value().authenticated,
                // User binding lands in a later task; always None for now.
                user: None,
                connected_at: entry.value().connected_at,
            })
            .collect()
    }
}
