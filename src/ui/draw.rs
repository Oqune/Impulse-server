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
use ratatui::widgets::{Block, Borders, Paragraph, Wrap, Scrollbar, ScrollbarOrientation, ScrollbarState};
use tracing::Level;

use crate::ui::view::{CertView, LogRecord, ServerInfo, SessionRow, UserRow, ServerStats};
use crate::ui::view::{compute_scroll, fmt_duration, live_total_online};
use crate::ui::{PanelMode, TuiState};

/// Left column width (Server/QR/Cert) in the full layout (sized for full IPv6 [IPv6]:port).
const LEFT_COL_WIDTH: u16 = 45;
/// Middle column width (Users + Sessions) in the three-column layout.
const MIDDLE_COL_WIDTH: u16 = 48;
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
            border: Color::Rgb(60, 76, 105),
            border_focus: Color::Rgb(56, 121, 242),
            header: Color::Rgb(168, 198, 255),
            label: Color::Rgb(162, 174, 196),
            value: Color::Rgb(244, 246, 252),
            ok: Color::Rgb(114, 220, 176),
            warn: Color::Rgb(240, 199, 107),
            err: Color::Rgb(255, 133, 133),
            dim: Color::Rgb(139, 154, 179),
            title: Color::Rgb(244, 246, 252),
        }
    }
}

/// Single palette for the whole UI (spec §3 Appearance).
pub const THEME: UiTheme = UiTheme::dark();

pub fn level_style(level: Level) -> (Color, &'static str) {
    match level {
        Level::ERROR => (THEME.err, "ERR"),
        Level::WARN => (THEME.warn, "WRN"),
        Level::INFO => (THEME.header, "INF"),
        Level::DEBUG => (Color::Rgb(182, 162, 240), "DBG"),
        Level::TRACE => (THEME.dim, "TRC"),
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
    terminal.draw(|f| draw_frame(f, ctx))?;
    Ok(())
}

fn draw_frame(f: &mut ratatui::Frame, ctx: &UiContext<'_>) {
        let area = f.area();
        f.render_widget(Block::default().style(Style::default().fg(THEME.value).bg(Color::Rgb(8, 12, 18))), area);
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
            .constraints([Constraint::Length(9), Constraint::Min(7), Constraint::Length(8)])
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
            Span::styled(format!("{:<16}", row.ip.to_canonical().to_string()), Style::default().fg(THEME.value)),
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
    let usable = area.height.saturating_sub(2);
    let width = area.width.saturating_sub(2);
    let search = state.search.as_ref().map(|s| s.query.as_str());
    let lines = filtered.iter().map(|rec| {
        let (color, lvl) = level_style(rec.level);
        let mut spans = vec![
            Span::styled(format_timestamp(rec.timestamp), Style::default().fg(THEME.dim)),
            Span::styled(format!(" [{}] ", lvl), Style::default().fg(color)),
            Span::styled(format!("{}: ", rec.target), Style::default().fg(THEME.header).add_modifier(Modifier::BOLD)),
        ];
        spans.extend(message_spans(rec, search, Style::default().fg(THEME.value)));
        Line::from(spans)
    }).collect::<Vec<Line>>();

    let paragraph = Paragraph::new(lines.clone()).wrap(Wrap { trim: false });
    // Use ratatui's own wrapping engine: byte/character estimates disagree on
    // wide Unicode and word boundaries. Count without borders.
    let total = paragraph.line_count(width);
    state.log_rows.set(total);
    state.log_max_scroll.set(total.saturating_sub(usize::from(usable)).min(u16::MAX as usize) as u16);
    let appended = state.history_rows.map(|rows| total.saturating_sub(rows)).unwrap_or(0);
    let offset = usize::from(state.scroll_offset).saturating_add(appended).min(u16::MAX as usize) as u16;
    let (mut scroll_y, _) = compute_scroll(total, usable, offset, state.auto_scroll);
    if let Some(selected) = state.search.as_ref().and_then(|s| s.selected) {
        let before = Paragraph::new(lines.into_iter().take(selected).collect::<Vec<_>>())
            .wrap(Wrap { trim: false }).line_count(width);
        scroll_y = before.min(total.saturating_sub(usize::from(usable))).min(u16::MAX as usize) as u16;
    }
    let mode = if state.paused { "PAUSED" } else if state.auto_scroll { "LIVE" } else { "HISTORY" };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .title(format!(" Logs · {mode} "))
        .border_style(Style::default().fg(THEME.border));
    f.render_widget(paragraph.block(block).scroll((scroll_y, 0)), area);
    if total > usize::from(usable) && usable > 0 && width > 0 {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None).end_symbol(None)
            .thumb_style(Style::default().fg(THEME.border_focus))
            .track_style(Style::default().fg(THEME.border));
        let mut scrollbar_state = ScrollbarState::new(total.saturating_sub(usize::from(usable)))
            .position(usize::from(scroll_y)).viewport_content_length(usize::from(usable));
        f.render_stateful_widget(scrollbar, Rect { y: area.y.saturating_add(1), height: usable, ..area }, &mut scrollbar_state);
    }
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
    spans.push(Span::styled(
        if state.paused { "PAUSED  " } else { "● LIVE  " },
        Style::default().fg(if state.paused { THEME.warn } else { THEME.ok }),
    ));
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

    fn render_logs(logs: &[LogRecord], state: &TuiState, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        let filtered: Vec<_> = logs.iter().filter(|r| state.level_visible(&r.level)).collect();
        terminal.draw(|f| draw_logs(f, f.area(), &filtered, state)).unwrap();
        terminal.backend().buffer().content.iter().map(|cell| cell.symbol()).collect()
    }

    #[test]
    fn rendered_scroll_moves_back_one_row_and_home_end_work() {
        let logs: Vec<_> = (0..20).map(|i| rec(&format!("ROW{i:02}"))).collect();
        let mut state = TuiState { auto_scroll: true, ..Default::default() };
        let bottom = render_logs(&logs, &state, 60, 7);
        assert!(bottom.contains("ROW19"));
        state.scroll_up(1);
        let previous = render_logs(&logs, &state, 60, 7);
        assert!(previous.contains("ROW14"));
        assert!(!previous.contains("ROW19"));
        state.scroll_to_top();
        assert!(render_logs(&logs, &state, 60, 7).contains("ROW00"));
        state.scroll_to_bottom();
        assert!(render_logs(&logs, &state, 60, 7).contains("ROW19"));
    }

    #[test]
    fn wrapped_log_tail_remains_visible_and_scrollable() {
        let logs = vec![rec(&format!("{} TAILMARK", "word ".repeat(40)))];
        let mut state = TuiState { auto_scroll: true, ..Default::default() };
        assert!(render_logs(&logs, &state, 40, 6).contains("TAILMARK"));
        state.scroll_to_top();
        assert!(render_logs(&logs, &state, 40, 6).contains("[INF]"));
        assert!(!render_logs(&logs, &state, 40, 6).contains("TAILMARK"));
    }

    #[test]
    fn empty_and_tiny_log_viewports_render_without_panics() {
        for (width, height) in [(0, 0), (1, 1), (2, 2), (32, 5)] {
            render_logs(&[], &TuiState::default(), width, height);
        }
    }

    #[test]
    fn history_stays_put_when_new_logs_arrive_and_home_down_moves() {
        let mut logs: Vec<_> = (0..20).map(|i| rec(&format!("ROW{i:02}"))).collect();
        let mut state = TuiState { auto_scroll: true, ..Default::default() };
        render_logs(&logs, &state, 60, 7);
        state.scroll_up(3);
        let before = render_logs(&logs, &state, 60, 7);
        logs.push(rec("ROW20"));
        let after = render_logs(&logs, &state, 60, 7);
        assert_eq!(before, after);
        state.scroll_to_top();
        render_logs(&logs, &state, 60, 7);
        state.scroll_down(1);
        let next = render_logs(&logs, &state, 60, 7);
        assert!(!next.contains("ROW00"));
        assert!(next.contains("ROW01"));
    }

    #[test]
    fn full_dashboard_renders_all_tiers_and_exports_optional_snapshot() {
        let logs = vec![rec("Relay ready"), rec("Client authenticated"), rec("Opaque payload relayed")];
        let cert = CertView { fingerprint_raw: "ab".repeat(32), fingerprint_grouped: "ABCD ".repeat(16), expires_in: 86400, ..Default::default() };
        let info = ServerInfo { address: "[::]:4433".into(), version: "3.1.0".into(), ttl_hours: 72, max_payload: 1048576, max_sessions: 1024, ..Default::default() };
        let stats = ServerStats::new();
        let state = TuiState { auto_scroll: true, ..Default::default() };
        let ctx = UiContext { logs: &logs, cert: &cert, info: &info, stats: &stats, sessions: &[], users: &[], state: &state, has_clipboard: false, throughput: 0 };
        for (width, height) in [(1, 1), (80, 20), (90, 24), (124, 24), (125, 24), (150, 40)] {
            let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
            terminal.draw(|f| draw_frame(f, &ctx)).unwrap();
            let buffer = terminal.backend().buffer();
            let text: String = buffer.content.iter().map(|cell| cell.symbol()).collect();
            if width >= 90 && height >= 24 {
                assert!(text.contains("Server"));
                assert!(text.contains("Sessions"));
                assert!(text.contains("Logs"));
                assert!(text.contains("72h"), "configured TTL must not be clipped");
            }
            if (width, height) == (150, 40)
                && let Ok(path) = std::env::var("IMPULSE_TUI_SNAPSHOT") {
                    assert!(!text.contains("QR: enlarge"), "QR must fit in the full-size dashboard");
                    let mut svg = format!("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{}\" height=\"{}\" viewBox=\"0 0 {} {}\"><rect width=\"100%\" height=\"100%\" fill=\"#080C12\"/><g font-family=\"Consolas,monospace\" font-size=\"13\">", width*8, height*16, width*8, height*16);
                    for y in 0..height {
                        for x in 0..width {
                            let cell = &buffer[(x, y)];
                            let escaped = cell.symbol().replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
                            let colour = match cell.fg { Color::Rgb(r,g,b) => format!("#{r:02x}{g:02x}{b:02x}"), Color::Black => "#000000".into(), _ => "#F4F6FC".into() };
                            svg.push_str(&format!("<text x=\"{}\" y=\"{}\" fill=\"{colour}\">{escaped}</text>", x*8, y*16+13));
                        }
                    }
                    svg.push_str("</g></svg>");
                    std::fs::write(path, svg).unwrap();
            }
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
