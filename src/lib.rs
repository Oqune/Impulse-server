//! Impulse server — a secure, ephemeral messenger relay over WebTransport (QUIC).
//!
//! Architecture overview:
//! * `cert` — self-signed Ed25519 certificate generation, 14-day TTL,
//!   2-day overlap rotation, SHA-256 TOFU fingerprint.
//! * `storage` — ephemeral in-RAM message log with 72h TTL and sequence ids.
//! * `protocol` — binary wire frames (opcodes 0x01–0x08) over WebTransport.
//! * `server` — WebTransport endpoint, session handling and broadcast relay.
//! * `tui` — terminal UI: Server Info header, log stream, TOFU QR / fingerprint panel.
//! * `logging` — `tracing` → TUI / file bridge.

pub mod cert;
pub mod config;
pub mod logging;
pub mod protocol;
pub mod server;
pub mod storage;
pub mod tui;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Notify;

use crate::cert::CertManager;
use crate::config::AppConfig;
use crate::tui::CertView;

/// High-level entry point used by `main.rs`.
///
/// 1. Loads / generates the certificate.
/// 2. Spawns the TUI (logs + TOFU QR).
/// 3. Wires `tracing` into the TUI + rotating log file.
/// 4. Starts the WebTransport relay, shutting it down when `shutdown` fires.
pub async fn run(app_config: AppConfig, shutdown: Arc<Notify>) -> Result<()> {
    let cert_manager = Arc::new(std::sync::Mutex::new(CertManager::load_or_create(
        std::path::Path::new(&app_config.server.cert_dir),
        app_config.server.san.clone(),
    )?));

    let initial_cert = cert_manager.lock().unwrap().current().clone();
    let cert_view = CertView::from_cert(&initial_cert);

    // Spawn the TUI thread; it returns a handle to push logs and cert views.
    let tui = tui::spawn_tui(cert_view, shutdown.clone())?;

    // Route tracing output into the TUI + rotating log file.
    logging::init_tracing(tui.clone(), "info");

    let relay = Arc::new(server::RelayServer::new(
        app_config.server.clone(),
        cert_manager,
        tui,
    )?);

    relay.run(shutdown).await
}
