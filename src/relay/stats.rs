//! Live counters shared between the relay and the TUI.
//!
//! All fields are atomics so the relay can increment from many tasks
//! concurrently and the TUI can read a cheap snapshot every second.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

#[derive(Debug)]
pub struct ServerStats {
    /// Active session count (mirrors the session registry length).
    pub sessions: AtomicUsize,
    /// Highest concurrent session count observed.
    pub peak_sessions: AtomicUsize,
    /// Messages accepted into the store.
    pub messages: AtomicUsize,
    /// Relay messages forwarded to at least one receiver.
    pub relayed_msgs: AtomicUsize,
    /// Payload bytes relayed.
    pub relayed_bytes: AtomicUsize,
    /// Successful authentications.
    pub auth_ok: AtomicUsize,
    /// Failed authentication attempts.
    pub auth_fail: AtomicUsize,
    /// Connections rejected by the per-IP rate limiter.
    pub rate_limited: AtomicUsize,
    /// Aggregate buffered bytes across all reader tasks (DoS budget).
    pub buffered_bytes: AtomicUsize,
    /// Process start instant, for the TUI uptime display.
    pub uptime_start: Instant,
}

impl Default for ServerStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerStats {
    pub fn new() -> Self {
        Self {
            uptime_start: Instant::now(),
            sessions: AtomicUsize::new(0),
            peak_sessions: AtomicUsize::new(0),
            messages: AtomicUsize::new(0),
            relayed_msgs: AtomicUsize::new(0),
            relayed_bytes: AtomicUsize::new(0),
            auth_ok: AtomicUsize::new(0),
            auth_fail: AtomicUsize::new(0),
            rate_limited: AtomicUsize::new(0),
            buffered_bytes: AtomicUsize::new(0),
        }
    }

    pub fn bump_sessions(&self) {
        let n = self.sessions.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak_sessions.fetch_max(n, Ordering::Relaxed);
    }

    pub fn drop_session(&self) {
        self.sessions.fetch_sub(1, Ordering::Relaxed);
    }
}
