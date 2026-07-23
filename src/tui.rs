//! Terminal UI for the Impulse server.
//!
//! 2‑column layout: a narrow **left** column with Info / QR square / Certificate,
//! and the full‑height **right** column dedicated to live `tracing` log output.
//! The QR code widget is centered **inside** a square card/block (its own quadrant),
//! not having the card itself centered in the panel.
//!
//! The TUI owns its own thread and communicates with the rest of the app via
//! channels: log records flow in through a `crossbeam_channel`, and the current
//! certificate view is pushed in through a shared `Arc<Mutex<CertView>>`.

use std::collections::HashSet;
use std::io::Stdout;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use copypasta::{ClipboardContext, ClipboardProvider};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{self};
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

/// Mutable TUI state for scrolling and log filtering.
struct TuiState {
    /// Current scroll offset (lines from bottom). 0 = pinned to bottom.
    scroll_offset: u16,
    /// When true, new logs auto-scroll to bottom (default).
    auto_scroll: bool,
    /// Active log level filters. Empty = show all levels.
    active_filters: HashSet<Level>,
}

impl TuiState {
    fn new() -> Self {
        Self {
            scroll_offset: 0,
            auto_scroll: true,
            active_filters: HashSet::new(),
        }
    }

    /// Returns true if the given level passes the current filter.
    fn level_visible(&self, level: &Level) -> bool {
        self.active_filters.is_empty() || self.active_filters.contains(level)
    }

    /// Toggle a log level filter on/off (pure toggle, no side effects).
    fn toggle_filter(&mut self, level: Level) {
        if !self.active_filters.insert(level) {
            self.active_filters.remove(&level);
        }
    }

    /// Scroll to the very bottom (manual call from End key).
    fn scroll_to_bottom(&mut self) {
        self.scroll_offset = 0;
    }

    /// Scroll up by `amount` lines.
    fn scroll_up(&mut self, amount: u16) {
        self.scroll_offset = self.scroll_offset.saturating_add(amount);
    }

    /// Scroll down by `amount` lines (clamps at 0).
    fn scroll_down(&mut self, amount: u16) {
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);
    }

    /// Jump to top of logs.
    fn scroll_to_top(&mut self) {
        self.scroll_offset = u16::MAX; // draw_logs will clamp
    }
}

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
        let _ = self.log_tx.try_send(rec);
    }

    pub fn set_cert(&self, view: CertView) {
        *self.cert.lock().unwrap_or_else(|e| e.into_inner()) = view;
    }

    pub fn set_info(&self, info: ServerInfo) {
        *self.info.lock().unwrap_or_else(|e| e.into_inner()) = info;
    }

    pub fn set_stats(&self, sessions: usize, messages: usize) {
        self.session_count.store(sessions, Ordering::Relaxed);
        self.message_count.store(messages, Ordering::Relaxed);
    }
}

/// Run the TUI loop on the current thread until the user quits (Ctrl+C / 'q').
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
    let mut last_copy: Option<SystemTime> = None;
    let clipboard_result = ClipboardContext::new();
    let has_clipboard = clipboard_result.is_ok();
    let mut clipboard = clipboard_result.ok();
    let mut state = TuiState::new();

    loop {
        while let Ok(rec) = log_rx.try_recv() {
            logs.push(rec);
            if logs.len() > MAX_LOG_LINES {
                let drop = logs.len() - MAX_LOG_LINES;
                logs.drain(0..drop);
            }
        }

        let filtered: Vec<&LogRecord> = logs
            .iter()
            .filter(|r| state.level_visible(&r.level))
            .collect();

        let stats = (
            stats.0.load(Ordering::Relaxed),
            stats.1.load(Ordering::Relaxed),
        );
        let info = info.lock().unwrap_or_else(|e| e.into_inner()).clone();
        draw(
            &mut terminal,
            &filtered,
            &cert.lock().unwrap_or_else(|e| e.into_inner()),
            &stats,
            &info,
            has_clipboard,
            &mut last_copy,
            &state,
        )?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            // Ctrl+C / q — quit
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)
                || key.code == KeyCode::Char('q')
            {
                shutdown.notify_one();
                break;
            }
            // Shift+C — copy all logs to clipboard
            if has_clipboard
                && key.code == KeyCode::Char('C')
                && key.modifiers.contains(KeyModifiers::SHIFT)
            {
                copy_logs_to_clipboard(&logs, &mut clipboard);
                last_copy = Some(SystemTime::now());
            }
            match key.code {
                // Scrolling
                KeyCode::Up => state.scroll_up(1),
                KeyCode::Down => state.scroll_down(1),
                KeyCode::PageUp => state.scroll_up(20),
                KeyCode::PageDown => state.scroll_down(20),
                KeyCode::Home => state.scroll_to_top(),
                KeyCode::End => state.scroll_to_bottom(),
                // Log level filter toggles
                KeyCode::Char('1') => state.toggle_filter(Level::TRACE),
                KeyCode::Char('2') => state.toggle_filter(Level::DEBUG),
                KeyCode::Char('3') => state.toggle_filter(Level::INFO),
                KeyCode::Char('4') => state.toggle_filter(Level::WARN),
                KeyCode::Char('5') => state.toggle_filter(Level::ERROR),
                _ => {}
            }
        }
    }

    terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        terminal::LeaveAlternateScreen,
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn draw(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    filtered: &[&LogRecord],
    cert: &CertView,
    stats: &(usize, usize),
    info: &ServerInfo,
    has_clipboard: bool,
    last_copy: &mut Option<SystemTime>,
    state: &TuiState,
) -> anyhow::Result<()> {
    terminal.draw(|f| {
        let area = f.area();

        if area.width < 80 || area.height < 10 {
            draw_compact(f, area, filtered, state);
            return;
        }

        if area.width < 112 || area.height < 30 {
            // Medium: help bar + logs only
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(1), Constraint::Min(5)])
                .split(area);
            draw_help_bar(f, rows[0], state, has_clipboard, last_copy);
            draw_logs(f, rows[1], filtered, state);
            return;
        }

        // Full layout: left column (info+QR+cert) + right column (help bar + logs)
        let left_w = 60u16.min(area.width.saturating_sub(40));

        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(left_w), Constraint::Min(40)])
            .split(area);

        let left_h = cols[0].height;
        let info_h = 8u16.min(left_h / 3);
        let cert_h = 7u16.min(left_h / 3);
        let qr_h = left_h.saturating_sub(info_h + cert_h);
        let qr_side = left_w.min(qr_h);

        let left_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(info_h),
                Constraint::Length(qr_side),
                Constraint::Length(cert_h),
            ])
            .split(cols[0]);

        let right_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(5)])
            .split(cols[1]);

        draw_info(f, left_rows[0], info, cert, stats, has_clipboard, last_copy);
        draw_qr(f, left_rows[1], cert);
        draw_cert_info(f, left_rows[2], cert);
        draw_help_bar(f, right_rows[0], state, has_clipboard, last_copy);
        draw_logs(f, right_rows[1], filtered, state);
    })?;
    Ok(())
}

/// Compact view for very small terminals.
fn draw_compact(f: &mut ratatui::Frame, area: Rect, filtered: &[&LogRecord], state: &TuiState) {
    draw_logs(f, area, filtered, state);
}

/// Top help bar: shows keybindings and active filter state on a single line.
fn draw_help_bar(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &TuiState,
    has_clipboard: bool,
    last_copy: &Option<SystemTime>,
) {
    let mut spans = Vec::new();

    // Filter indicators — colored pills showing which levels are on
    let all_active = state.active_filters.is_empty();
    let filter_defs: &[(Level, &str, Color)] = &[
        (Level::TRACE, "1:TRC", Color::DarkGray),
        (Level::DEBUG, "2:DBG", Color::Magenta),
        (Level::INFO,  "3:INF", Color::Cyan),
        (Level::WARN,  "4:WRN", Color::Yellow),
        (Level::ERROR, "5:ERR", Color::Red),
    ];

    spans.push(Span::styled(
        " Filters: ",
        Style::default().fg(Color::Gray),
    ));

    for (level, label, color) in filter_defs {
        let active = all_active || state.active_filters.contains(level);
        let style = if active {
            Style::default().fg(*color).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        spans.push(Span::styled(format!("[{}]", label), style));
        spans.push(Span::raw(" "));
    }

    if all_active {
        spans.push(Span::styled(
            "all ON",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ));
    } else {
        let count = state.active_filters.len();
        spans.push(Span::styled(
            format!("{} on", count),
            Style::default().fg(Color::Green),
        ));
    }

    // Separator
    spans.push(Span::styled("  │  ", Style::default().fg(Color::DarkGray)));

    // Scroll hint
    let scroll_txt = if state.auto_scroll {
        Span::styled(
            "↑↓ scroll (End=bottom)",
            Style::default().fg(Color::DarkGray),
        )
    } else {
        Span::styled(
            "↑↓ scrolling  End=back to live",
            Style::default().fg(Color::Yellow),
        )
    };
    spans.push(scroll_txt);

    // Separator
    spans.push(Span::styled("  │  ", Style::default().fg(Color::DarkGray)));

    // Copy / quit
    if has_clipboard {
        spans.push(Span::styled(
            "Shift+C=copy logs",
            Style::default().fg(Color::DarkGray),
        ));
        spans.push(Span::raw("  "));
    }
    spans.push(Span::styled(
        "Ctrl+C quit",
        Style::default().fg(Color::DarkGray),
    ));

    // Copy confirmation flash
    if let Some(t) = last_copy {
        if t.elapsed().unwrap_or_default() < Duration::from_secs(2) {
            spans.push(Span::styled(
                "  ✓ copied",
                Style::default().fg(Color::Green),
            ));
        }
    }

    let bar = Paragraph::new(Line::from(spans));
    f.render_widget(bar, area);
}

fn draw_info(
    f: &mut ratatui::Frame,
    area: Rect,
    info: &ServerInfo,
    cert: &CertView,
    stats: &(usize, usize),
    _has_clipboard: bool,
    _last_copy: &Option<SystemTime>,
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
    let lines = vec![
        Line::from(vec![
            Span::styled("Listen: ", Style::default().fg(Color::Gray)),
            Span::styled(
                info.address.clone(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Transport: ", Style::default().fg(Color::Gray)),
            Span::styled("WebTransport/QUIC", Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("Version: ", Style::default().fg(Color::Gray)),
            Span::raw(info.version.clone()),
        ]),
        Line::from(vec![
            Span::styled("Sessions: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}/{}", stats.0, info.max_sessions)),
            Span::styled("  Msgs: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}", stats.1)),
        ]),
        Line::from(vec![
            Span::styled("TTL: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}h", info.ttl_hours)),
            Span::styled("  Payload: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}KB", info.max_payload / 1024)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Cert: ", Style::default().fg(Color::Gray)),
            Span::styled(
                fp.to_string(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            if cert.rotating {
                Span::styled("⚠", Style::default().fg(Color::Yellow))
            } else {
                Span::raw("")
            },
        ]),
        Line::from(vec![
            Span::styled("Exp: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}d {}h {}m {}s", d, h, m, s)),
        ]),
    ];

    let block = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(" Info ")
                .border_style(Style::default().fg(Color::Gray))
                .padding(ratatui::widgets::Padding::uniform(1)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(block, area);
}

fn draw_logs(f: &mut ratatui::Frame, area: Rect, filtered: &[&LogRecord], state: &TuiState) {
    let lines: Vec<Line> = filtered
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

    // Scroll: auto_scroll = always pinned to bottom; manual = use scroll_offset
    let usable = area.height.saturating_sub(2) as usize; // borders = 2
    let total = filtered.len();
    let scroll_y = if state.auto_scroll {
        if total > usable {
            (total - usable) as u16
        } else {
            0
        }
    } else {
        let max_scroll = if total > usable { (total - usable) as u16 } else { 0 };
        state.scroll_offset.min(max_scroll)
    };

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(" Logs ")
                .border_style(Style::default().fg(Color::Gray))
                .padding(ratatui::widgets::Padding::uniform(1)),
        )
        .wrap(Wrap { trim: false })
        .scroll((scroll_y, 0));
    f.render_widget(paragraph, area);
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

fn draw_qr(f: &mut ratatui::Frame, area: Rect, cert: &CertView) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .title(" QR — TOFU ")
        .border_style(Style::default().fg(Color::Gray));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let qr_string = cert.tofu_qr_string();
    match qrcode::QrCode::with_error_correction_level(&qr_string, qrcode::EcLevel::L) {
        Ok(qr) => {
            let cols = qr.width() as u16;
            let rows = ((qr.width() + 1) / 2) as u16;

            let widget_w = cols.min(inner.width);
            let widget_h = rows.min(inner.height);

            let centered = centered_rect(widget_w, widget_h, inner);

            let widget = tui_qrcode::QrCodeWidget::new(qr)
                .quiet_zone(tui_qrcode::QuietZone::Disabled);
            f.render_widget(widget, centered);
        }
        Err(_) => {
            let p = Paragraph::new("QR encode error")
                .style(Style::default().fg(Color::Red))
                .alignment(Alignment::Center);
            f.render_widget(p, inner);
        }
    }
}

/// Certificate fingerprint info rendered in the bottom‑left slot.
fn draw_cert_info(f: &mut ratatui::Frame, area: Rect, cert: &CertView) {
    let expires = cert.expires_in;
    let (d, h, m, s) = (
        expires / 86400,
        (expires % 86400) / 3600,
        (expires % 3600) / 60,
        expires % 60,
    );

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Fingerprint:", Style::default().fg(Color::Gray)),
        ]),
        Line::from(Span::styled(
            cert.fingerprint_grouped.clone(),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Valid for: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}d {}h {}m {}s", d, h, m, s),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Issued: ", Style::default().fg(Color::Gray)),
            Span::raw(format_unix(cert.issued_at)),
        ]),
    ];
    if cert.rotating {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "⚠ Rotating (overlap)",
            Style::default().fg(Color::Yellow),
        )));
    }

    let info = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(" Certificate ")
                .border_style(Style::default().fg(Color::Gray))
                .padding(ratatui::widgets::Padding::uniform(1)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(info, area);
}

/// Helper to create a centered rect of given width/height within `r`.
fn centered_rect(width: u16, height: u16, r: Rect) -> Rect {
    let width = width.min(r.width);
    let height = height.min(r.height);
    Rect {
        x: r.x + (r.width - width) / 2,
        y: r.y + (r.height - height) / 2,
        width,
        height,
    }
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
