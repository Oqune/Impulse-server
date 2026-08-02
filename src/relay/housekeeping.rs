//! Background housekeeping: certificate rotation, expired-message sweep,
//! rate-limiter / nonce pruning, and the periodic stats tick for the TUI.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use tracing::{debug, info, warn};

use crate::relay::{HOUSEKEEP_INTERVAL, IP_PRUNE_INTERVAL, NONCE_MAX_AGE, RelayServer};

impl RelayServer {
    pub(crate) fn spawn_housekeeping(self: Arc<Self>) {
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
                    let mut view = crate::ui::view::CertView::from_cert(&cert);
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
                        .send(crate::protocol::ServerPacketEncoder::new_cert_hash(
                            &hash_bytes, expires_at,
                        ))
                    {
                        warn!("Failed to broadcast NewCertHash: {}", e);
                    }
                    info!("Applied rotated certificate to live TLS resolver");
                }

                let removed = self.store.sweep();
                if removed > 0 {
                    debug!("Swept {} expired messages", removed);
                }
                let (sessions, messages) = (self.sessions.len(), self.store.len());
                self.stats.sessions.store(sessions, Ordering::Relaxed);
                self.stats.messages.store(messages, Ordering::Relaxed);
                self.tui.set_stats(sessions, messages);
                self.tui.set_sessions(self.session_rows());
            }
        });
    }
}
