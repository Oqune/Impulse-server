//! Bridge between `tracing` and the TUI.
//!
//! We implement a minimal `tracing::Subscriber` that forwards every log event
//! to the TUI's log channel. A standard `fmt` layer is also added for
//! debugging when running outside the TUI.

use std::time::SystemTime;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::tui::TuiHandle;

/// A `tracing`-style timer that formats the timestamp as `[HH:MM:SS]` for the
/// stderr/log file layer (mirrors the TUI log styling).
struct BracketTimer;

impl tracing_subscriber::fmt::time::FormatTime for BracketTimer {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs();
        write!(
            w,
            "[{:02}:{:02}:{:02}]",
            (secs / 3600) % 24,
            (secs / 60) % 60,
            secs % 60
        )
    }
}

/// A `tracing` layer that pushes records into the TUI log channel.
struct TuiLogLayer {
    tui: TuiHandle,
}

impl<S: tracing::Subscriber> Layer<S> for TuiLogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let level = *event.metadata().level();
        let target = event.metadata().target().to_string();

        // Render the message fields into a single string.
        let mut message = String::new();
        let mut visitor = MessageVisitor(&mut message);
        event.record(&mut visitor);

        let timestamp = SystemTime::now();

        self.tui.push_log(crate::tui::LogRecord {
            level,
            target,
            message,
            timestamp,
        });
    }
}

struct MessageVisitor<'a>(&'a mut String);

impl<'a> tracing::field::Visit for MessageVisitor<'a> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0.push_str(&format!("{:?}", value));
        } else {
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            self.0.push_str(&format!("{}={:?}", field.name(), value));
        }
    }
}

/// Install the global tracing subscriber, sending events to the TUI, stderr, and
/// a rolling daily log file under `logs/`. Must be called once before logging.
pub fn init_tracing(tui: TuiHandle, env_filter: &str) {
    let tui_layer = TuiLogLayer { tui };

    use tracing_appender::rolling;
    let file_layer = rolling::never("logs", "impulse-server.log");

    let registry = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_timer(BracketTimer)
                .with_filter(LevelFilter::from_level(tracing::Level::INFO))
                .with_filter(
                    tracing_subscriber::EnvFilter::try_new(env_filter)
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                ),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(file_layer)
                .with_timer(BracketTimer)
                .with_ansi(false)
                .with_filter(
                    tracing_subscriber::EnvFilter::try_new(env_filter)
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                ),
        );

    // Try to set as global default; ignore error if already set.
    let _ = registry.with(tui_layer).try_init();
}
