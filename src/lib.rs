//! Impulse server — a secure, ephemeral messenger relay over WebTransport (QUIC).
//!
//! Architecture overview:
//! * `cert` — self-signed ECDSA P-256 certificate generation, 14-day TTL,
//!   2-day overlap rotation, SHA-256 TOFU fingerprint.
//! * `storage` — ephemeral in-RAM message log with 72h TTL and sequence ids.
//! * `protocol` — binary wire frames (opcodes 0x01–0x0C) over WebTransport;
//!   framing and size limits live in `protocol::framing` / `protocol::limits`.
//! * `crypto` — Argon2id password hashing + verification (auth chain).
//! * `relay` — WebTransport endpoint, session handling, broadcast relay,
//!   auth handshake (`relay::auth`), and housekeeping (`relay::housekeeping`).
//!   `relay::users` tracks per-user stats keyed by the KEM public-key hash.
//! * `ui` — terminal UI: Server/Users/Sessions panels, TOFU QR, live stats,
//!   log view.
//! * `config` — configuration resolution (`mod`), CLI parsing (`cli`), file
//!   loading (`file`).
//! * `cli` — first-run / `--init` interactive wizards and config writing.
//! * `logging` — `tracing` → TUI / file bridge.

pub mod cert;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod logging;
pub mod protocol;
pub mod relay;
pub mod storage;
pub mod ui;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Notify;

use crate::cert::CertManager;
use crate::config::AppConfig;
use crate::logging::DEFAULT_LOG_FILTER;
use crate::ui::view::CertView;

/// High-level entry point used by `main.rs`.
///
/// 1. Creates required directories.
/// 2. Loads / generates the certificate.
/// 3. Spawns the TUI (logs + TOFU QR).
/// 4. Wires `tracing` into the TUI + rotating log file.
/// 5. Starts the WebTransport relay, shutting it down when `shutdown` fires.
pub async fn run(app_config: AppConfig, shutdown: Arc<Notify>) -> Result<()> {
    // Ensure certificate directory exists.
    std::fs::create_dir_all(&app_config.server.cert_dir)?;

    // Ensure logs directory exists.
    let _ = std::fs::create_dir_all("logs");

    let cert_manager = Arc::new(tokio::sync::Mutex::new(CertManager::load_or_create(
        std::path::Path::new(&app_config.server.cert_dir),
        app_config.server.san.clone(),
    )?));

    let initial_cert = cert_manager.lock().await.current().clone();
    let cert_view = CertView::from_cert(&initial_cert);
    let tofu_payload = cert_view.tofu_qr_string();

    // Spawn the TUI thread; it returns a handle to push logs and cert views.
    let tui = ui::spawn_tui(cert_view, shutdown.clone())?;

    // Route tracing output into the TUI + rotating log file.
    let env_filter = std::env::var("RUST_LOG").unwrap_or_else(|_| DEFAULT_LOG_FILTER.to_string());
    logging::init_tracing(tui.clone(), &env_filter);

    // Log the TOFU payload — it can be copied into the client's manual entry
    // when the QR code cannot be scanned.
    tracing::info!("TOFU payload: {}", tofu_payload);

    let relay = Arc::new(
        relay::RelayServer::new(app_config.server.clone(), cert_manager, tui).await?,
    );

    relay.run(shutdown).await
}
