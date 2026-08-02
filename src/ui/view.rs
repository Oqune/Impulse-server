//! Data types shared between the TUI and the relay (view models).
//!
//! `ServerInfo`, `CertView`, and `LogRecord` are display-oriented snapshots;
//! `ServerStats` is the shared live counter block produced by the relay.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cert::Cert;
pub use crate::relay::stats::ServerStats;

/// Static technical information about the running server (safe to display).
#[derive(Clone, Default)]
pub struct ServerInfo {
    pub address: String,
    pub san_count: usize,
    pub ttl_hours: u64,
    pub max_payload: usize,
    pub max_sessions: usize,
    pub version: String,
}

/// Snapshot of certificate state shown in the certificate panel.
#[derive(Clone, Default)]
pub struct CertView {
    pub fingerprint_grouped: String,
    pub fingerprint_raw: String,
    pub issued_at: u64,
    pub expires_in: u64,
    /// True while a previous cert is still valid (overlap window).
    pub rotating: bool,
}

impl CertView {
    pub fn from_cert(cert: &Cert) -> Self {
        Self {
            fingerprint_grouped: cert.fingerprint_grouped(),
            fingerprint_raw: cert.fingerprint.clone(),
            issued_at: cert
                .not_before
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            expires_in: cert.expires_in(),
            rotating: false,
        }
    }

    /// The QR payload: `impulse-cert:<fp>` — the SHA-256 fingerprint the client
    /// pins via WebTransport `serverCertificateHashes` (TOFU).
    pub fn tofu_qr_string(&self) -> String {
        format!("impulse-cert:{}", self.fingerprint_raw)
    }
}

/// Log record forwarded from the `tracing` subscriber.
#[derive(Clone)]
pub struct LogRecord {
    pub level: tracing::Level,
    pub target: String,
    pub message: String,
    pub timestamp: SystemTime,
}

/// Scroll helper: computes the rendered scroll offset (0 = bottom is the newest
/// line; line 0 is the oldest) and whether live auto-scroll stays engaged.
///
/// `total` = number of lines, `usable` = number of viewport rows available for
/// lines (the caller must already exclude borders), `scroll_offset` = rows
/// scrolled up from the bottom (0 = bottom), `auto` = live auto-scroll engaged.
pub fn compute_scroll(total: usize, usable: u16, scroll_offset: u16, auto: bool) -> (u16, bool) {
    let usable = usable as usize;
    if total <= usable {
        return (0, auto || scroll_offset == 0);
    }
    let max_scroll = (total - usable) as u16;
    if auto {
        return (max_scroll, true);
    }
    let y = scroll_offset.min(max_scroll);
    // Re-engage live when the user scrolls back to the very bottom.
    let re_pinned = y >= max_scroll;
    (y, re_pinned)
}

/// Format seconds as `d h m s` (only components that are nonzero; always seconds).
pub fn fmt_duration(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    match (d, h, m) {
        (0, 0, 0) => format!("{s}s"),
        (0, 0, _) => format!("{m}m {s}s"),
        (0, _, _) => format!("{h}h {m}m {s}s"),
        _ => format!("{d}d {h}h {m}m {s}s"),
    }
}

/// Snapshot of a live session for the sessions table.
#[derive(Clone, Debug)]
pub struct SessionRow {
    pub key: u64,
    pub ip: std::net::IpAddr,
    pub authenticated: bool,
    pub age: Duration,
}

#[cfg(test)]
mod tests {
    use super::{compute_scroll, fmt_duration};

    #[test]
    fn compute_scroll_pins_when_auto() {
        // Auto-scroll: 100 lines, 10 usable rows → pinned at bottom (offset 90).
        let (y, auto) = compute_scroll(100, 10, 0, true);
        assert_eq!(y, 90);
        assert!(auto);
    }

    #[test]
    fn compute_scroll_manual_disengages_auto() {
        let (y, auto) = compute_scroll(100, 10, 5, false);
        assert_eq!(y, 5);
        assert!(!auto);
    }

    #[test]
    fn compute_scroll_clamps_at_top() {
        let (y, _) = compute_scroll(50, 10, u16::MAX, false);
        assert_eq!(y, 40); // 50 - 10 usable
    }

    #[test]
    fn compute_scroll_no_scroll_when_fits() {
        let (y, _) = compute_scroll(5, 10, 0, false);
        assert_eq!(y, 0);
    }

    #[test]
    fn fmt_duration_renders_components() {
        assert_eq!(fmt_duration(90), "1m 30s");
        assert_eq!(fmt_duration(2 * 86400 + 3600 + 120), "2d 1h 2m 0s");
    }
}
