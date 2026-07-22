//! Terminal UI for the Impulse server.
//!
//! A **horizontal** two-panel layout: the **left** panel shows live `tracing` log
//! output with timestamps, the **right** panel shows a centered QR code containing
//! the TOFU trust payload (`impulse-cert:<fingerprint>`), the grouped fingerprint
//! and a countdown to the next certificate rotation.
//!
//! The TUI owns its own thread and communicates with the rest of the app via
//! channels: log records flow in through a `crossbeam_channel`, and the current
//! certificate view is pushed in through a shared `Arc<Mutex<CertView>>`.

use std::io::Stdout;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{self};
use copypasta::{ClipboardContext, ClipboardProvider};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use tracing::Level;

use crate::cert::Cert;

/// Max number of log lines retained for the TUI.
const MAX_LOG_LINES: usize = 500;

/// Preferred width of the right TOFU panel. The layout adapts gracefully when
/// the terminal is smaller (see `draw`), so there is no minimum size.
/// 72 cols fits the v4 QR code (`impulse-cert:<64-hex>` = 77 bytes → 33x33
/// modules → 66 cols + quiet zone + borders).
const TOFU_PANEL_WIDTH: u16 = 72;

/// Below this terminal width we drop the TOFU panel entirely and show only
/// logs, since there is not enough room for a readable QR code.
const MIN_SPLIT_WIDTH: u16 = 40;

/// Snapshot of certificate state shown in the right panel.
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
    pub level: Level,
    pub target: String,
    pub message: String,
    pub timestamp: SystemTime,
}

/// Static technical information about the running server (safe to display).
/// Populated once at startup and refreshed for the few live fields.
#[derive(Clone, Default)]
pub struct ServerInfo {
    /// Bind address, e.g. `0.0.0.0:4433`.
    pub address: String,
    /// Number of configured SANs on the certificate.
    pub san_count: usize,
    /// Message TTL in hours.
    pub ttl_hours: u64,
    /// Max payload size in bytes.
    pub max_payload: usize,
    /// Max concurrent sessions.
    pub max_sessions: usize,
    /// Crate version (from CARGO_PKG_VERSION).
    pub version: String,
}

/// Handle returned to the caller to feed the TUI.
#[derive(Clone)]
pub struct TuiHandle {
    pub log_tx: crossbeam_channel::Sender<LogRecord>,
    pub cert: Arc<Mutex<CertView>>,
    /// Live count of active sessions, updated by the server.
    pub session_count: Arc<AtomicUsize>,
    /// Live count of stored messages, updated by the server.
    pub message_count: Arc<AtomicUsize>,
    /// Static (and semi-live) server technical info shown above the logs.
    pub info: Arc<Mutex<ServerInfo>>,
    /// Triggered when the user requests shutdown ('q' / Ctrl+C) from the TUI.
    pub shutdown: std::sync::Arc<tokio::sync::Notify>,
}

impl TuiHandle {
    pub fn push_log(&self, rec: LogRecord) {
        // Non-blocking: if the TUI is saturated we drop the line rather than
        // block the async runtime.
        let _ = self.log_tx.try_send(rec);
    }

    /// Update the certificate view (e.g. after a rotation).
    pub fn set_cert(&self, view: CertView) {
        *self.cert.lock().unwrap() = view;
    }

    /// Refresh the static server technical info shown above the logs.
    pub fn set_info(&self, info: ServerInfo) {
        *self.info.lock().unwrap() = info;
    }

    /// Refresh the live session / message counters shown in the TUI.
    pub fn set_stats(&self, sessions: usize, messages: usize) {
        self.session_count.store(sessions, Ordering::Relaxed);
        self.message_count.store(messages, Ordering::Relaxed);
    }
}

/// Run the TUI loop on the current thread until the user quits (Ctrl+C / 'q').
///
/// Returns when the UI should close; the server is expected to shut down too.
pub fn run_tui(
    log_rx: crossbeam_channel::Receiver<LogRecord>,
    cert: Arc<Mutex<CertView>>,
    stats: (Arc<AtomicUsize>, Arc<AtomicUsize>),
    info: Arc<Mutex<ServerInfo>>,
    shutdown: Arc<tokio::sync::Notify>,
) -> anyhow::Result<()> {
    let mut stdout: Stdout = std::io::stdout();
    terminal::enable_raw_mode()?;
    crossterm::execute!(
        stdout,
        terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut logs: Vec<LogRecord> = Vec::with_capacity(MAX_LOG_LINES);
    let mut last_tick = std::time::Instant::now();
    let mut last_copy: Option<SystemTime> = None;
    let clipboard_result = ClipboardContext::new();
    let has_clipboard = clipboard_result.is_ok();
    let mut clipboard = clipboard_result.ok();

    loop {
        while let Ok(rec) = log_rx.try_recv() {
            logs.push(rec);
            if logs.len() > MAX_LOG_LINES {
                let drop = logs.len() - MAX_LOG_LINES;
                logs.drain(0..drop);
            }
        }

        let stats = (
            stats.0.load(Ordering::Relaxed),
            stats.1.load(Ordering::Relaxed),
        );
        let info = info.lock().unwrap().clone();
        draw(&mut terminal, &logs, &cert.lock().unwrap(), &stats, &info, has_clipboard, &mut last_copy)?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)
                || key.code == KeyCode::Char('q')
            {
                shutdown.notify_one();
                break;
            }
            if has_clipboard
                && key.code == KeyCode::Char('C')
                && key.modifiers.contains(KeyModifiers::SHIFT)
            {
                copy_logs_to_clipboard(&logs, &mut clipboard);
                last_copy = Some(SystemTime::now());
            }
        }
        if last_tick.elapsed() >= Duration::from_millis(250) {
            last_tick = std::time::Instant::now();
        }
    }

    terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn draw(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    logs: &[LogRecord],
    cert: &CertView,
    stats: &(usize, usize),
    info: &ServerInfo,
    has_clipboard: bool,
    last_copy: &mut Option<SystemTime>,
) -> anyhow::Result<()> {
    terminal.draw(|f| {
        let area = f.area();

        let left = |f: &mut ratatui::Frame, area: Rect| {
            let info_h = 7u16.min(area.height);
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(info_h), // server info
                    Constraint::Min(3),         // logs
                ])
                .split(area);
            draw_info(f, chunks[0], info, cert, stats, has_clipboard, last_copy);
            draw_logs(f, chunks[1], logs);
        };

        if area.width >= MIN_SPLIT_WIDTH + TOFU_PANEL_WIDTH {
            let tofu_w = TOFU_PANEL_WIDTH.min(area.width.saturating_sub(MIN_SPLIT_WIDTH));
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Min(MIN_SPLIT_WIDTH), // logs panel
                    Constraint::Length(tofu_w),       // TOFU panel
                ])
                .split(area);

            left(f, chunks[0]);
            draw_tofu(f, chunks[1], cert);
        } else {
            left(f, area);
        }
    })?;
    Ok(())
}

/// Compact technical-information block rendered above the logs.
fn draw_info(
    f: &mut ratatui::Frame,
    area: Rect,
    info: &ServerInfo,
    cert: &CertView,
    stats: &(usize, usize),
    has_clipboard: bool,
    last_copy: &Option<SystemTime>,
) {
    let fp = if cert.fingerprint_raw.len() >= 16 {
        &cert.fingerprint_raw[..16]
    } else {
        &cert.fingerprint_raw
    };
    let expires = cert.expires_in;
    let (d, h, m, s) = (
        expires / 86400,
        (expires % 86400) / 3600,
        (expires % 3600) / 60,
        expires % 60,
    );
    let mut lines = vec![
        Line::from(vec![
            Span::styled("Listen: ", Style::default().fg(Color::Gray)),
            Span::styled(
                info.address.clone(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("   Transport: ", Style::default().fg(Color::Gray)),
            Span::styled(
                "WebTransport/QUIC TLS1.3 (h3)",
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled("Version: ", Style::default().fg(Color::Gray)),
            Span::raw(info.version.clone()),
            Span::styled("   SANS: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}", info.san_count)),
            Span::styled("   Max sessions: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}/{}", stats.0, info.max_sessions)),
        ]),
        Line::from(vec![
            Span::styled("Messages: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}", stats.1)),
            Span::styled("   TTL: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}h", info.ttl_hours)),
            Span::styled("   Max payload: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{} KB", info.max_payload / 1024)),
        ]),
        Line::from(vec![
            Span::styled("Cert fingerprint: ", Style::default().fg(Color::Gray)),
            Span::styled(
                fp.to_string(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Cert expires in: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}d {}h {}m {}s", d, h, m, s)),
            if cert.rotating {
                Span::styled("   ⚠ rotating", Style::default().fg(Color::Yellow))
            } else {
                Span::raw("")
            },
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Press 'q' / Ctrl+C to stop", Style::default().fg(Color::DarkGray)),
            if has_clipboard {
                Span::raw("   ")
            } else {
                Span::raw("")
            },
            if has_clipboard {
                Span::styled("Shift+C to copy logs", Style::default().fg(Color::DarkGray))
            } else {
                Span::raw("")
            },
        ]),
    ];
    if let Some(t) = last_copy {
        if t.elapsed().unwrap_or_default() < Duration::from_secs(2) {
            lines.push(Line::from(Span::styled(
                "✓ Logs copied to clipboard",
                Style::default().fg(Color::Green),
            )));
        }
    }

    let block = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Server Info ")
                .border_style(Style::default().fg(Color::Gray))
                .padding(ratatui::widgets::Padding::uniform(1)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(block, area);
}

fn draw_logs(f: &mut ratatui::Frame, area: Rect, logs: &[LogRecord]) {
    let lines: Vec<Line> = logs
        .iter()
        .map(|rec| {
            let color = match rec.level {
                Level::ERROR => Color::Red,
                Level::WARN => Color::Yellow,
                Level::INFO => Color::Cyan,
                Level::DEBUG => Color::Magenta,
                Level::TRACE => Color::DarkGray,
            };
            let lvl = match rec.level {
                Level::ERROR => "ERR",
                Level::WARN => "WRN",
                Level::INFO => "INF",
                Level::DEBUG => "DBG",
                Level::TRACE => "TRC",
            };
            // Format timestamp: [HH:MM:SS.mmm]
            let ts = rec.timestamp.duration_since(UNIX_EPOCH).unwrap_or_default();
            let secs = ts.as_secs();
            let millis = ts.subsec_millis();
            let ts_str = format!(
                "[{:02}:{:02}:{:02}.{:03}]",
                (secs / 3600) % 24,
                (secs / 60) % 60,
                secs % 60,
                millis
            );

            Line::from(vec![
                Span::styled(ts_str, Style::default().fg(Color::DarkGray)),
                Span::styled(format!(" [{}] ", lvl), Style::default().fg(color)),
                Span::styled(
                    format!("{}: ", rec.target),
                    Style::default()
                        .fg(Color::Blue)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(&rec.message),
            ])
        })
        .collect();

    // Paragraph (not List) so long messages wrap inside the panel instead of
    // being truncated.
    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Impulse Server — Logs ")
                .border_style(Style::default().fg(Color::Gray))
                .padding(ratatui::widgets::Padding::uniform(1)),
        )
        .wrap(Wrap { trim: false })
        .scroll((scroll_for_logs(area, logs.len()), 0));
    f.render_widget(paragraph, area);
}

/// Keep the view pinned to the newest log lines when there are more than fit.
fn scroll_for_logs(area: Rect, total: usize) -> u16 {
    let usable = area.height.saturating_sub(2) as usize; // minus borders/padding
    if total > usable {
        (total - usable) as u16
    } else {
        0
    }
}

fn copy_logs_to_clipboard(logs: &[LogRecord], clipboard: &mut Option<ClipboardContext>) {
    if let Some(ctx) = clipboard {
        let text: String = logs
            .iter()
            .map(|rec| {
                let ts = rec.timestamp.duration_since(UNIX_EPOCH).unwrap_or_default();
                let secs = ts.as_secs();
                let millis = ts.subsec_millis();
                let ts_str = format!(
                    "[{:02}:{:02}:{:02}.{:03}]",
                    (secs / 3600) % 24,
                    (secs / 60) % 60,
                    secs % 60,
                    millis
                );
                let lvl = match rec.level {
                    Level::ERROR => "ERR",
                    Level::WARN => "WRN",
                    Level::INFO => "INF",
                    Level::DEBUG => "DBG",
                    Level::TRACE => "TRC",
                };
                format!("{} [{}] {}: {}", ts_str, lvl, rec.target, rec.message)
            })
            .collect::<Vec<_>>()
            .join("\n");
        let _ = ctx.set_contents(text);
    }
}

fn draw_tofu(f: &mut ratatui::Frame, area: Rect, cert: &CertView) {
    // The right panel is split vertically: QR on top (centered), info below.
    // The payload `impulse-cert:<64-hex>` (77 bytes) encodes as a v4 QR code
    // with error-correction level L: 33x33 modules → 66 cols x 33 rows.
    // When the terminal is too small for that, the QR block collapses to a
    // hint and the fingerprint below remains the manual fallback.
    const QR_WIDGET_COLS: u16 = 66;
    const QR_WIDGET_ROWS: u16 = 33;

    let qr_fits = area.width >= QR_WIDGET_COLS + 2 && area.height >= QR_WIDGET_ROWS + 12;
    let qr_rows = if qr_fits {
        QR_WIDGET_ROWS + 2
    } else {
        5 // collapsed hint block
    }
    .min(area.height);
    let info_rows = area.height.saturating_sub(qr_rows);
    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(qr_rows),          // QR code area (with border)
            Constraint::Length(info_rows.max(1)), // info area
        ])
        .split(area);

    // QR code with border - center it within the allocated rect.
    let qr_outer_block = Block::default()
        .borders(Borders::ALL)
        .title(" Scan to trust (TOFU) ")
        .border_style(Style::default().fg(Color::Gray));
    let qr_inner = qr_outer_block.inner(inner[0]);
    f.render_widget(qr_outer_block, inner[0]);

    if qr_fits {
        let qr_widget_area = centered_rect(
            QR_WIDGET_COLS.min(qr_inner.width),
            QR_WIDGET_ROWS.min(qr_inner.height),
            qr_inner,
        );
        let qr_string = cert.tofu_qr_string();
        // ECL::L keeps the code at v4 (77 bytes fit); the default ECL::M would
        // bump it to v5, which no longer fits the panel. Quiet zone is skipped —
        // the dark block border already separates the code from the frame.
        match qrcode::QrCode::with_error_correction_level(&qr_string, qrcode::EcLevel::L) {
            Ok(qr) => {
                let widget = tui_qrcode::QrCodeWidget::new(qr)
                    .quiet_zone(tui_qrcode::QuietZone::Disabled);
                f.render_widget(widget, qr_widget_area);
            }
            Err(_) => {
                let p = Paragraph::new("QR encode error")
                    .style(Style::default().fg(Color::Red))
                    .alignment(Alignment::Center);
                f.render_widget(p, qr_widget_area);
            }
        }
    } else {
        let p = Paragraph::new("Terminal too small for QR —\nenter the fingerprint below\nmanually in the client.")
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center);
        f.render_widget(p, qr_inner);
    }

    // Right side: full grouped fingerprint + issue time + rotation status.
    let expires = cert.expires_in;
    let (d, h, m, s) = (
        expires / 86400,
        (expires % 86400) / 3600,
        (expires % 3600) / 60,
        expires % 60,
    );
    let mut lines = vec![
        Line::from(vec![
            Span::styled("Fingerprint: ", Style::default().fg(Color::Gray)),
            Span::styled(
                cert.fingerprint_grouped.clone(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Cert valid for: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}d {}h {}m {}s", d, h, m, s)),
        ]),
        Line::from(vec![
            Span::styled("Issued at: ", Style::default().fg(Color::Gray)),
            Span::raw(format_unix(cert.issued_at)),
        ]),
    ];
    if cert.rotating {
        lines.push(Line::from(Span::styled(
            "⚠ Rotating (overlap active)",
            Style::default().fg(Color::Yellow),
        )));
    }
    lines.push(Line::from(""));

    let info = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Trust & Rotation ")
                .border_style(Style::default().fg(Color::Gray))
                .padding(ratatui::widgets::Padding::uniform(1)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(info, inner[1]);
}

/// Helper to create a centered rect of given width/height within `r`.
fn centered_rect(width: u16, height: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(popup_layout[1])[1]
}

fn format_unix(secs: u64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs as i64) {
        Ok(dt) => dt
            .format(&time::format_description::well_known::Rfc2822)
            .unwrap_or_else(|_| secs.to_string()),
        Err(_) => secs.to_string(),
    }
}

/// Build the TUI channels and spawn the TUI thread. Returns a [`TuiHandle`].
pub fn spawn_tui(
    initial: CertView,
    shutdown: Arc<tokio::sync::Notify>,
) -> anyhow::Result<TuiHandle> {
    let (log_tx, log_rx) = crossbeam_channel::unbounded::<LogRecord>();
    let cert = Arc::new(Mutex::new(initial));
    let session_count = Arc::new(AtomicUsize::new(0));
    let message_count = Arc::new(AtomicUsize::new(0));
    let info = Arc::new(Mutex::new(ServerInfo::default()));

    let cert_clone = cert.clone();
    let s_clone = (session_count.clone(), message_count.clone());
    let info_clone = info.clone();
    let shutdown_clone = shutdown.clone();
    std::thread::spawn(move || {
        if let Err(e) = run_tui(log_rx, cert_clone, s_clone, info_clone, shutdown_clone) {
            eprintln!("TUI error: {}", e);
        }
    });

    Ok(TuiHandle {
        log_tx,
        cert,
        session_count,
        message_count,
        info,
        shutdown,
    })
}
