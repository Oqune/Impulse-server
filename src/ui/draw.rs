//! TUI rendering: layout, panels, log viewport, QR, status bar.
//!
//! Responsive layout (spec: three-column redesign):
//! * at least 125 cols and 24 rows: Server/QR/Cert | Users + Sessions | Logs
//! * 90..124 cols and 24 rows: Server/QR/Cert | Users + Sessions + Logs
//! * otherwise: logs + status bar only

use std::io::Stdout;
use std::time::{SystemTime, UNIX_EPOCH};

use copypasta::{ClipboardContext, ClipboardProvider};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use tracing::Level;

use crate::ui::view::{CertView, LogRecord, ServerInfo, SessionRow, UserRow, ServerStats};
use crate::ui::view::{compute_scroll, fmt_duration, live_total_online};
use crate::ui::{PanelMode, TuiState};

/// Left column width (Server/QR/Cert) in the full layout.
const LEFT_COL_WIDTH: u16 = 42;
/// Middle column width (Users + Sessions) in the three-column layout.
const MIDDLE_COL_WIDTH: u16 = 44;
/// Minimum width for the three-column layout (two-column below this).
const THREE_COL_MIN_WIDTH: u16 = 125;
/// Minimum width for the full (non-compact) layout.
const FULL_MIN_WIDTH: u16 = 90;
/// Minimum height for the full (non-compact) layout.
const FULL_MIN_HEIGHT: u16 = 24;

/// Which column tier to render for a given terminal size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutTier {
    /// Logs + status bar only (< 90 cols or < 24 rows).
    Compact,
    /// Left column + right column (Users + Sessions + Logs).
    TwoColumn,
    /// Left + middle (Users + Sessions) + right (Logs).
    ThreeColumn,
}

/// Pure decision helper so the responsive thresholds are unit-testable.
pub fn layout_tier(width: u16, height: u16) -> LayoutTier {
    if width < FULL_MIN_WIDTH || height < FULL_MIN_HEIGHT {
        LayoutTier::Compact
    } else if width >= THREE_COL_MIN_WIDTH {
        LayoutTier::ThreeColumn
    } else {
        LayoutTier::TwoColumn
    }
}

pub struct UiTheme {
    pub border: Color,
    pub border_focus: Color,
    pub header: Color,
    pub label: Color,
    pub value: Color,
    pub ok: Color,
    pub warn: Color,
    pub err: Color,
    pub dim: Color,
    pub title: Color,
}

impl UiTheme {
    pub const fn dark() -> Self {
        Self {
            border: Color::Gray,
            border_focus: Color::Cyan,
            header: Color::Cyan,
            label: Color::Gray,
            value: Color::White,
            ok: Color::Green,
            warn: Color::Yellow,
            err: Color::Red,
            dim: Color::DarkGray,
            title: Color::White,
        }
    }
}

/// Single palette for the whole UI (spec §3 Appearance).
pub const THEME: UiTheme = UiTheme::dark();

pub fn level_style(level: Level) -> (Color, &'static str) {
    match level {
        Level::ERROR => (Color::Red, "ERR"),
        Level::WARN => (Color::Yellow, "WRN"),
        Level::INFO => (Color::Cyan, "INF"),
        Level::DEBUG => (Color::Magenta, "DBG"),
        Level::TRACE => (Color::DarkGray, "TRC"),
    }
}

pub fn format_timestamp(ts: SystemTime) -> String {
    let dur = ts.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    format!(
        "[{:02}:{:02}:{:02}.{:03}]",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60,
        millis
    )
}

pub fn format_unix(secs: u64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs as i64) {
        Ok(dt) => dt
            .format(&time::format_description::well_known::Rfc2822)
            .unwrap_or_else(|_| secs.to_string()),
        Err(_) => secs.to_string(),
    }
}

pub fn copy_logs_to_clipboard(logs: &[LogRecord], clipboard: &mut Option<ClipboardContext>) {
    if let Some(ctx) = clipboard {
        let text: String = logs
            .iter()
            .map(|rec| {
                let ts_str = format_timestamp(rec.timestamp);
                let (_, lvl) = level_style(rec.level);
                format!("{} [{}] {}: {}", ts_str, lvl, rec.target, rec.message)
            })
            .collect::<Vec<_>>()
            .join("\n");
        let _ = ctx.set_contents(text);
    }
}

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

/// Bundled per-frame rendering inputs, kept together so `draw` and
/// `draw_status_bar` stay under clippy's argument-count limit.
pub(crate) struct UiContext<'a> {
    pub logs: &'a [LogRecord],
    pub cert: &'a CertView,
    pub info: &'a ServerInfo,
    pub stats: &'a ServerStats,
    pub sessions: &'a [SessionRow],
    pub users: &'a [UserRow],
    pub state: &'a TuiState,
    pub has_clipboard: bool,
    pub throughput: u64,
}

pub(crate) fn draw(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    ctx: &UiContext<'_>,
) -> anyhow::Result<()> {
    terminal.draw(|f| {
        let area = f.area();
        let filtered: Vec<&LogRecord> = ctx.logs.iter().filter(|r| ctx.state.level_visible(&r.level)).collect();
        let filtered_total = filtered.len();

        // `f` — QR full-screen (spec §3): QR over everything except the status bar.
        if ctx.state.qr_focus {
            let v = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(1)])
                .split(area);
            draw_qr(f, v[0], ctx.cert);
            draw_status_bar(f, v[1], ctx, filtered_total);
            return;
        }

        // Split off the status bar at the bottom.
        let v = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(1)])
            .split(area);
        let main_area = v[0];
        let status_area = v[1];

        if ctx.state.panel_mode == PanelMode::Hidden {
            // Left column hidden: logs span full width.
            draw_logs(f, main_area, &filtered, ctx.state);
        } else {
            match layout_tier(area.width, area.height) {
                LayoutTier::ThreeColumn => {
                    // Server/QR/Cert | Users + Sessions | Logs
                    let cols = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([
                            Constraint::Length(LEFT_COL_WIDTH),
                            Constraint::Length(MIDDLE_COL_WIDTH),
                            Constraint::Min(30),
                        ])
                        .split(main_area);
                    draw_left_column(f, cols[0], ctx.state, ctx.info, ctx.stats, ctx.cert);
                    draw_middle_column(f, cols[1], ctx.users, ctx.sessions);
                    draw_logs(f, cols[2], &filtered, ctx.state);
                }
                LayoutTier::TwoColumn => {
                    // Server/QR/Cert | Users + Sessions + Logs
                    let cols = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([Constraint::Length(LEFT_COL_WIDTH), Constraint::Min(30)])
                        .split(main_area);
                    draw_left_column(f, cols[0], ctx.state, ctx.info, ctx.stats, ctx.cert);
                    draw_right_column(f, cols[1], ctx.users, ctx.sessions, &filtered, ctx.state);
                }
                LayoutTier::Compact => {
                    // logs + status bar only
                    draw_logs(f, main_area, &filtered, ctx.state);
                }
            }
        }

        draw_status_bar(f, status_area, ctx, filtered_total);
    })?;
    Ok(())
}

fn draw_info(f: &mut ratatui::Frame, area: Rect, info: &ServerInfo, stats: &ServerStats) {
    let uptime = fmt_duration(stats.uptime_start.elapsed().as_secs());
    let lines = vec![
        Line::from(vec![
            Span::styled("Listen: ", Style::default().fg(THEME.label)),
            Span::styled(info.address.clone(), Style::default().fg(THEME.value).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Transport: ", Style::default().fg(THEME.label)),
            Span::styled("WebTransport/QUIC · TLS 1.3", Style::default().fg(THEME.header)),
        ]),
        Line::from(vec![
            Span::styled("Version: ", Style::default().fg(THEME.label)),
            Span::raw(info.version.clone()),
            Span::styled("  MIT © oqune", Style::default().fg(THEME.dim)),
        ]),
        Line::from(vec![
            Span::styled("Uptime: ", Style::default().fg(THEME.label)),
            Span::raw(uptime),
        ]),
        Line::from(vec![
            Span::styled("Sessions: ", Style::default().fg(THEME.label)),
            Span::styled(
                format!("{}/{}", stats.sessions.load(std::sync::atomic::Ordering::Relaxed), info.max_sessions),
                Style::default().fg(THEME.ok),
            ),
            Span::styled("  Msgs: ", Style::default().fg(THEME.label)),
            Span::raw(format!("{}", stats.relayed_msgs.load(std::sync::atomic::Ordering::Relaxed))),
        ]),
        Line::from(vec![
            Span::styled("TTL: ", Style::default().fg(THEME.label)),
            Span::raw(format!("{}h", info.ttl_hours)),
            Span::styled("  Payload: ", Style::default().fg(THEME.label)),
            Span::raw(format!("{}KB", info.max_payload / 1024)),
        ]),
        Line::from(vec![
            Span::styled("Peak: ", Style::default().fg(THEME.label)),
            Span::raw(format!("{}", stats.peak_sessions.load(std::sync::atomic::Ordering::Relaxed))),
        ]),
    ];
    let block = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(" Server ")
                .border_style(Style::default().fg(THEME.border)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(block, area);
}

fn draw_qr(f: &mut ratatui::Frame, area: Rect, cert: &CertView) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .title(" QR — TOFU ")
        .border_style(Style::default().fg(THEME.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let qr_string = cert.tofu_qr_string();
    match qrcode::QrCode::with_error_correction_level(&qr_string, qrcode::EcLevel::L) {
        Ok(qr) => {
            let cols = qr.width() as u16;
            let rows = qr.width().div_ceil(2) as u16;
            // Never render a truncated QR: if it cannot fit, show a hint instead.
            if cols <= inner.width && rows <= inner.height {
                let centered = centered_rect(cols, rows, inner);
                let widget = tui_qrcode::QrCodeWidget::new(qr).quiet_zone(tui_qrcode::QuietZone::Disabled);
                f.render_widget(widget, centered);
            } else {
                let p = Paragraph::new(Line::from(Span::styled(
                    "QR: enlarge terminal / press f",
                    Style::default().fg(THEME.dim),
                )))
                .alignment(Alignment::Center);
                f.render_widget(p, inner);
            }
        }
        Err(_) => {
            let p = Paragraph::new("QR encode error").style(Style::default().fg(THEME.err)).alignment(Alignment::Center);
            f.render_widget(p, inner);
        }
    }
}

fn draw_cert_info(f: &mut ratatui::Frame, area: Rect, cert: &CertView) {
    let mut lines = vec![
        Line::from(vec![Span::styled("Fingerprint:", Style::default().fg(THEME.label))]),
        Line::from(Span::styled(cert.fingerprint_grouped.clone(), Style::default().fg(THEME.ok).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(vec![
            Span::styled("Valid for: ", Style::default().fg(THEME.label)),
            Span::styled(fmt_duration(cert.expires_in), Style::default().fg(THEME.header).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Issued: ", Style::default().fg(THEME.label)),
            Span::raw(format_unix(cert.issued_at)),
        ]),
    ];
    if cert.rotating {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("⚠ Rotating (overlap)", Style::default().fg(THEME.warn))));
    }
    let info = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(" Certificate ")
                .border_style(Style::default().fg(THEME.border)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(info, area);
}

fn draw_left_column(
    f: &mut ratatui::Frame,
    area: Rect,
    state: &TuiState,
    info: &ServerInfo,
    stats: &ServerStats,
    cert: &CertView,
) {
    if state.panel_mode == PanelMode::Full {
        let left_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Min(7), Constraint::Min(5)])
            .split(area);
        draw_info(f, left_rows[0], info, stats);
        draw_qr(f, left_rows[1], cert);
        draw_cert_info(f, left_rows[2], cert);
    } else {
        // QrOnly: QR takes the whole left column.
        draw_qr(f, area, cert);
    }
}

/// Middle column (three-column mode): Users and Sessions split the column
/// evenly.
fn draw_middle_column(
    f: &mut ratatui::Frame,
    area: Rect,
    users: &[UserRow],
    sessions: &[SessionRow],
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    draw_users(f, rows[0], users);
    draw_sessions(f, rows[1], sessions);
}

/// Users panel: every user ever seen, with live online state and totals.
fn draw_users(f: &mut ratatui::Frame, area: Rect, users: &[UserRow]) {
    let now = std::time::Instant::now();
    let mut lines: Vec<Line> = Vec::new();
    for row in users.iter().take(100) {
        let dot = if row.online {
            Span::styled("●", Style::default().fg(THEME.ok))
        } else {
            Span::styled("○", Style::default().fg(THEME.dim))
        };
        // Live online time: accumulated + the delta of the active session,
        // recomputed each frame so it ticks without extra pushes.
        let online = live_total_online(row.total_online, row.connected_at, now);
        let fp8 = row.fingerprint.get(..8).unwrap_or(&row.fingerprint);
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:<4}", row.alias),
                Style::default().fg(THEME.header).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{fp8}  "), Style::default().fg(THEME.dim)),
            dot,
            Span::styled(
                format!(" {:>12} ", fmt_duration(online.as_secs())),
                Style::default().fg(THEME.value),
            ),
            Span::styled(format!("{} msgs", row.msgs_sent), Style::default().fg(THEME.dim)),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "no users yet",
            Style::default().fg(THEME.dim),
        )));
    }
    let block = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(" Users ")
                .border_style(Style::default().fg(THEME.border)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(block, area);
}

/// Right column (two-column fallback): Users + Sessions + Logs.
fn draw_right_column(
    f: &mut ratatui::Frame,
    area: Rect,
    users: &[UserRow],
    sessions: &[SessionRow],
    filtered: &[&LogRecord],
    state: &TuiState,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(8), Constraint::Min(5)])
        .split(area);
    draw_users(f, rows[0], users);
    draw_sessions(f, rows[1], sessions);
    draw_logs(f, rows[2], filtered, state);
}

fn draw_sessions(f: &mut ratatui::Frame, area: Rect, sessions: &[SessionRow]) {
    let now = std::time::Instant::now();
    let mut lines: Vec<Line> = Vec::new();
    for row in sessions.iter().take(100) {
        let auth = if row.authenticated {
            Span::styled("✓", Style::default().fg(THEME.ok))
        } else {
            Span::styled("·", Style::default().fg(THEME.dim))
        };
        // Age is computed live per frame so it never freezes between the 60 s
        // housekeeping pushes (spec §3 fix 2).
        let age = fmt_duration(now.saturating_duration_since(row.connected_at).as_secs());
        let user_tag = match &row.user {
            Some(alias) => Span::styled(format!("{alias} "), Style::default().fg(THEME.header)),
            None => Span::raw(""),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{:4}  ", row.key), Style::default().fg(THEME.dim)),
            Span::styled(format!("{:<16}", row.ip.to_string()), Style::default().fg(THEME.value)),
            Span::raw("  "),
            auth,
            user_tag,
            Span::styled(format!("  {:>8}", age), Style::default().fg(THEME.dim)),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "no sessions",
            Style::default().fg(THEME.dim),
        )));
    }
    let block = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(" Sessions ")
                .border_style(Style::default().fg(THEME.border)),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(block, area);
}

fn draw_logs(f: &mut ratatui::Frame, area: Rect, filtered: &[&LogRecord], state: &TuiState) {
    // Render only the visible window (spec §3 Performance). `filtered` was
    // already computed once in `draw`.
    let usable = area.height.saturating_sub(2) as usize;
    let (scroll_y, _auto) = compute_scroll(filtered.len(), area.height.saturating_sub(2), state.scroll_offset, state.auto_scroll);

    let search = state.search.as_ref().map(|s| s.query.as_str());
    let start = scroll_y as usize;
    let visible = filtered.iter().skip(start).take(usable.max(1)).map(|rec| {
        let (color, lvl) = level_style(rec.level);
        let mut spans = vec![
            Span::styled(format_timestamp(rec.timestamp), Style::default().fg(THEME.dim)),
            Span::styled(format!(" [{}] ", lvl), Style::default().fg(color)),
            Span::styled(format!("{}: ", rec.target), Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)),
        ];
        spans.extend(message_spans(rec, search, Style::default()));
        Line::from(spans)
    }).collect::<Vec<Line>>();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .title(" Logs ")
        .border_style(Style::default().fg(THEME.border));
    let paragraph = Paragraph::new(visible)
        .block(block)
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, area);
}

/// Split a log message into spans, highlighting every case-insensitive match of
/// the active search query (spec §3 `/` search).
fn message_spans(rec: &LogRecord, query: Option<&str>, base: Style) -> Vec<Span<'static>> {
    let query = match query {
        Some(q) if !q.is_empty() => q.to_lowercase(),
        _ => return vec![Span::styled(rec.message.clone(), base)],
    };
    let msg = &rec.message;
    let lower = msg.to_lowercase();
    let mut spans = Vec::new();
    let mut rest: &str = msg;
    let mut rest_lower: &str = lower.as_str();
    while let Some(idx) = rest_lower.find(&query) {
        // `idx` is a byte offset into the LOWERCASED remainder. A char whose
        // lowercase form has a different byte length than the original (e.g.
        // `İ` U+0130 → "i̇", 2 bytes → 3 bytes) shifts these offsets away from
        // char boundaries of the original, so `split_at` could panic. If either
        // split point is not a char boundary, stop highlighting and emit the
        // remainder as a single span.
        if !rest.is_char_boundary(idx) {
            break;
        }
        let (pre, tail) = rest.split_at(idx);
        let Some(matched) = tail.get(..query.len()) else {
            break;
        };
        let after = &tail[query.len()..];
        if !pre.is_empty() {
            spans.push(Span::styled(pre.to_string(), base));
        }
        spans.push(Span::styled(
            matched.to_string(),
            Style::default().bg(Color::Yellow).fg(Color::Black),
        ));
        rest = after;
        rest_lower = &rest_lower[idx + query.len()..];
        if rest.is_empty() {
            break;
        }
    }
    if !rest.is_empty() {
        spans.push(Span::styled(rest.to_string(), base));
    }
    spans
}

fn draw_status_bar(
    f: &mut ratatui::Frame,
    area: Rect,
    ctx: &UiContext<'_>,
    filtered_total: usize,
) {
    let relaxed = std::sync::atomic::Ordering::Relaxed;
    let state = ctx.state;
    let stats = ctx.stats;
    let info = ctx.info;
    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::styled("● LIVE  ", Style::default().fg(THEME.ok)));
    spans.push(Span::styled(
        format!("S {}/{}  ", stats.sessions.load(relaxed), info.max_sessions),
        Style::default().fg(THEME.value),
    ));
    spans.push(Span::styled(
        format!("Msgs {}  ", stats.relayed_msgs.load(relaxed)),
        Style::default().fg(THEME.value),
    ));
    spans.push(Span::styled(
        format!("Buf {}  ", fmt_bytes(stats.buffered_bytes.load(relaxed) as u64)),
        Style::default().fg(THEME.value),
    ));
    spans.push(Span::styled(
        format!("↑ {}/s  ", fmt_bytes(ctx.throughput)),
        Style::default().fg(THEME.ok),
    ));
    spans.push(Span::styled(
        format!("Auth {}✓ {}✗  ", stats.auth_ok.load(relaxed), stats.auth_fail.load(relaxed)),
        Style::default().fg(THEME.value),
    ));
    if state.paused {
        spans.push(Span::styled("⏸ paused  ", Style::default().fg(THEME.warn)));
    }
    spans.push(Span::styled("│  ", Style::default().fg(THEME.dim)));
    let all_active = state.active_filters.is_empty();
    let filter_keys: &[(Level, &str)] = &[
        (Level::ERROR, "1"),
        (Level::WARN, "2"),
        (Level::INFO, "3"),
        (Level::DEBUG, "4"),
        (Level::TRACE, "5"),
    ];
    for (level, key) in filter_keys {
        let (color, short) = level_style(*level);
        let active = all_active || state.active_filters.contains(level);
        let style = if active {
            Style::default().fg(color).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(THEME.dim)
        };
        spans.push(Span::styled(format!("[{key}:{short}] "), style));
    }
    if !state.auto_scroll {
        spans.push(Span::styled(
            format!("{}/{}  ", state.scroll_offset, filtered_total),
            Style::default().fg(THEME.dim),
        ));
    }
    if ctx.has_clipboard {
        spans.push(Span::styled("Shift+C copy", Style::default().fg(THEME.dim)));
    }
    if state.search_active() {
        let q = state.search.as_ref().map(|s| s.query.as_str()).unwrap_or("");
        spans.push(Span::styled(format!(" /{q}▏ (Esc / Enter)"), Style::default().fg(THEME.warn)));
    }

    let bar = Paragraph::new(Line::from(spans));
    f.render_widget(bar, area);
}

fn fmt_bytes(n: u64) -> String {
    if n >= 1024 * 1024 {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(message: &str) -> LogRecord {
        LogRecord {
            level: Level::INFO,
            target: "test".to_string(),
            message: message.to_string(),
            timestamp: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn message_spans_does_not_panic_on_utf8_case_fold_mismatch() {
        // `İ` (U+0130) lowercases to "i\u{307}" — 2 UTF-8 bytes become 3, so a
        // byte index taken from the lowercased copy lands mid-char in the
        // original. This used to panic inside `split_at`; it must now degrade
        // to a single unhighlighted span.
        let record = rec("aİb");
        let spans = message_spans(&record, Some("i"), Style::default());
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].content, "aİb");
        assert_eq!(spans[0].style, Style::default());
    }

    #[test]
    fn message_spans_highlights_match_before_utf8_char() {
        // The match precedes the `İ`, so no lowercase byte-offset shift has
        // happened yet and both split points are char boundaries: highlighting
        // must apply and the remainder must be preserved.
        let record = rec("bar İ foo");
        let spans = message_spans(&record, Some("bar"), Style::default());
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].content, "bar");
        assert_eq!(spans[0].style, Style::default().bg(Color::Yellow).fg(Color::Black));
        assert_eq!(spans[1].content, " İ foo");
        assert_eq!(spans[1].style, Style::default());
    }

    #[test]
    fn layout_tier_thresholds() {
        // Compact below 90 cols or below 24 rows.
        assert_eq!(layout_tier(89, 30), LayoutTier::Compact);
        assert_eq!(layout_tier(120, 23), LayoutTier::Compact);
        // Two columns in the 90..124 band.
        assert_eq!(layout_tier(90, 24), LayoutTier::TwoColumn);
        assert_eq!(layout_tier(124, 24), LayoutTier::TwoColumn);
        // Three columns at >= 125.
        assert_eq!(layout_tier(125, 24), LayoutTier::ThreeColumn);
        assert_eq!(layout_tier(300, 40), LayoutTier::ThreeColumn);
    }
}
