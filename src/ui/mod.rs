//! Terminal UI: event loop, scrolling/filter state, and the [`TuiHandle`]
//! used by the relay to feed logs/cert/stats.

pub mod draw;
pub mod view;

use std::collections::HashSet;
use std::io::Stdout;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use copypasta::ClipboardContext;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseEventKind};
use crossterm::terminal::{self};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tracing::Level;

use crate::relay::ServerStats;
use crate::ui::draw::{copy_logs_to_clipboard, draw};
use crate::ui::view::{CertView, LogRecord, ServerInfo, SessionRow, UserRow};

/// Max number of log lines retained for the TUI (spec §3: 500 → 2000).
const MAX_LOG_LINES: usize = 2000;

/// Left-panel visibility, cycled with `Tab` (spec §3: full → QR-only → hidden).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PanelMode {
    #[default]
    Full,
    QrOnly,
    Hidden,
}

/// Active substring search opened with `/` (spec §3).
#[derive(Default)]
pub struct SearchState {
    pub query: String,
    /// Round-robin index over the match list, advanced by `Enter`.
    pub cursor: usize,
}

/// Scroll + filter + search + panel state for the log viewport.
#[derive(Default)]
pub struct TuiState {
    pub scroll_offset: u16,
    pub auto_scroll: bool,
    pub active_filters: HashSet<Level>,
    pub paused: bool,
    pub panel_mode: PanelMode,
    pub qr_focus: bool,
    pub search: Option<SearchState>,
}

impl TuiState {
    fn new() -> Self {
        Self { auto_scroll: true, ..Self::default() }
    }

    pub fn level_visible(&self, level: &Level) -> bool {
        self.active_filters.is_empty() || self.active_filters.contains(level)
    }

    pub fn toggle_filter(&mut self, level: Level) {
        if !self.active_filters.insert(level) {
            self.active_filters.remove(&level);
        }
    }

    pub fn scroll_up(&mut self, amount: u16) {
        self.auto_scroll = false;
        self.scroll_offset = self.scroll_offset.saturating_add(amount);
    }

    pub fn scroll_down(&mut self, amount: u16) {
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);
        if self.scroll_offset == 0 {
            self.auto_scroll = true;
        }
    }

    pub fn scroll_to_bottom(&mut self) {
        self.scroll_offset = 0;
        self.auto_scroll = true;
    }

    pub fn scroll_to_top(&mut self) {
        self.auto_scroll = false;
        self.scroll_offset = u16::MAX;
    }

    pub fn search_active(&self) -> bool {
        self.search.is_some()
    }
}

/// Handle returned to the caller to feed the TUI. Fields are private; the relay
/// interacts only through these methods.
#[derive(Clone)]
pub struct TuiHandle {
    log_tx: crossbeam_channel::Sender<LogRecord>,
    cert: Arc<Mutex<CertView>>,
    info: Arc<Mutex<ServerInfo>>,
    stats: Arc<ServerStats>,
    sessions: Arc<Mutex<Vec<SessionRow>>>,
    users: Arc<Mutex<Vec<UserRow>>>,
    shutdown: Arc<tokio::sync::Notify>,
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

    pub fn set_stats(&self, sessions: usize) {
        self.stats.sessions.store(sessions, Ordering::Relaxed);
    }

    pub fn set_sessions(&self, rows: Vec<SessionRow>) {
        *self.sessions.lock().unwrap_or_else(|e| e.into_inner()) = rows;
    }

    pub fn set_users(&self, rows: Vec<UserRow>) {
        *self.users.lock().unwrap_or_else(|e| e.into_inner()) = rows;
    }

    pub fn stats_handle(&self) -> Arc<ServerStats> {
        self.stats.clone()
    }

    pub fn shutdown(&self) -> &Arc<tokio::sync::Notify> {
        &self.shutdown
    }
}

/// Run the TUI loop on the current thread until the user quits (Ctrl+C / 'q').
pub(crate) fn run_tui(
    log_rx: crossbeam_channel::Receiver<LogRecord>,
    cert: Arc<Mutex<CertView>>,
    info: Arc<Mutex<ServerInfo>>,
    stats: Arc<ServerStats>,
    sessions: Arc<Mutex<Vec<SessionRow>>>,
    users: Arc<Mutex<Vec<UserRow>>>,
    shutdown: Arc<tokio::sync::Notify>,
    init_tx: crossbeam_channel::Sender<anyhow::Result<()>>,
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
    // Signal "ready" immediately so spawn_tui returns without a startup delay
    // (the final result after quit is sent again below; capacity is 1 so the
    // caller's recv_timeout gets this first message).
    let _ = init_tx.send(Ok(()));

    let mut logs: Vec<LogRecord> = Vec::with_capacity(MAX_LOG_LINES);
    let mut state = TuiState::new();
    let mut last_copy: Option<SystemTime> = None;
    let clipboard_result = ClipboardContext::new();
    let has_clipboard = clipboard_result.is_ok();
    let mut clipboard = clipboard_result.ok();

    let mut last_tick = std::time::Instant::now();
    let mut last_relayed_bytes = 0usize;
    let mut throughput: u64 = 0;
    let mut dirty = true;

    loop {
        // Drain log channel (event-driven redraw: only on new data / input / tick).
        let mut drained = false;
        while let Ok(rec) = log_rx.try_recv() {
            if !state.paused {
                logs.push(rec);
                if logs.len() > MAX_LOG_LINES {
                    let drop = logs.len() - MAX_LOG_LINES;
                    logs.drain(0..drop);
                }
                drained = true;
            }
        }

        if event::poll(Duration::from_millis(16))? {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    let quit = handle_key(
                        &key,
                        &mut state,
                        &mut logs,
                        &mut clipboard,
                        &mut last_copy,
                        has_clipboard,
                        shutdown.clone(),
                    );
                    if quit {
                        break;
                    }
                    dirty = true;
                }
                Event::Mouse(m) => {
                    if m.kind == MouseEventKind::ScrollUp {
                        state.scroll_up(3);
                        dirty = true;
                    } else if m.kind == MouseEventKind::ScrollDown {
                        state.scroll_down(3);
                        dirty = true;
                    }
                }
                Event::Resize(_, _) => dirty = true,
                _ => {}
            }
        }

        // 1-second tick: refresh stats-driven fields (uptime, throughput).
        if last_tick.elapsed() >= Duration::from_secs(1) {
            last_tick = std::time::Instant::now();
            // Throughput = relayed_bytes delta since the previous tick.
            let now = stats.relayed_bytes.load(Ordering::Relaxed);
            throughput = now.saturating_sub(last_relayed_bytes) as u64;
            last_relayed_bytes = now;
            dirty = true;
        }

        if dirty || drained {
            dirty = false;
            let cert = cert.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let info = info.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let sessions = sessions.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let users = users.lock().unwrap_or_else(|e| e.into_inner()).clone();
            draw(
                &mut terminal,
                &logs,
                &cert,
                &info,
                &stats,
                &sessions,
                &users,
                &state,
                has_clipboard,
                throughput,
            )?;
        }
    }

    // Cleanup: restore the terminal in all paths (Bug 5).
    terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    let _ = init_tx.send(Ok(()));
    Ok(())
}

fn handle_key(
    key: &crossterm::event::KeyEvent,
    state: &mut TuiState,
    logs: &mut Vec<LogRecord>,
    clipboard: &mut Option<ClipboardContext>,
    last_copy: &mut Option<SystemTime>,
    has_clipboard: bool,
    shutdown: Arc<tokio::sync::Notify>,
) -> bool {
    // Ctrl+C — quit from anywhere; `q` quits only outside search input.
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)
        || key.code == KeyCode::Char('q') && !state.search_active()
    {
        shutdown.notify_one();
        return true;
    }
    // Search input mode (`/`): printable keys edit the query, Enter jumps to the
    // next match, Esc closes, Backspace deletes (spec §3).
    if state.search_active() {
        match key.code {
            KeyCode::Esc => state.search = None,
            KeyCode::Backspace => {
                if let Some(s) = state.search.as_mut() {
                    s.query.pop();
                }
            }
            KeyCode::Enter => jump_to_next_match(state, logs),
            KeyCode::Char(c) => {
                if let Some(s) = state.search.as_mut() {
                    s.query.push(c);
                }
            }
            _ => {}
        }
        return false;
    }
    // Shift+C — copy all logs to clipboard
    if has_clipboard && key.code == KeyCode::Char('C') && key.modifiers.contains(KeyModifiers::SHIFT) {
        copy_logs_to_clipboard(logs, clipboard);
        *last_copy = Some(SystemTime::now());
    }
    match key.code {
        KeyCode::Up => state.scroll_up(1),
        KeyCode::Down => state.scroll_down(1),
        KeyCode::PageUp => state.scroll_up(20),
        KeyCode::PageDown => state.scroll_down(20),
        KeyCode::Home => state.scroll_to_top(),
        KeyCode::End => state.scroll_to_bottom(),
        // Filters: severity descending — [1]ERR [2]WRN [3]INF [4]DBG [5]TRC
        KeyCode::Char('1') => state.toggle_filter(Level::ERROR),
        KeyCode::Char('2') => state.toggle_filter(Level::WARN),
        KeyCode::Char('3') => state.toggle_filter(Level::INFO),
        KeyCode::Char('4') => state.toggle_filter(Level::DEBUG),
        KeyCode::Char('5') => state.toggle_filter(Level::TRACE),
        KeyCode::Char(' ') => state.paused = !state.paused,
        KeyCode::Char('c') => logs.clear(),
        KeyCode::Char('f') => state.qr_focus = !state.qr_focus,
        KeyCode::Tab => {
            state.panel_mode = match state.panel_mode {
                PanelMode::Full => PanelMode::QrOnly,
                PanelMode::QrOnly => PanelMode::Hidden,
                PanelMode::Hidden => PanelMode::Full,
            }
        }
        KeyCode::Char('/') => {
            state.search = Some(SearchState::default());
            state.auto_scroll = false;
        }
        _ => {}
    }
    false
}

/// Scroll so the next line matching the query is at the top of the viewport.
/// `scroll_offset` is the number of lines to skip from the oldest line (see
/// `draw_logs`), so the matched line index doubles as the offset; `compute_scroll`
/// clamps it to `total - usable`. If filters are active the indices are
/// approximate — recompute over the filtered slice if precision matters.
fn jump_to_next_match(state: &mut TuiState, logs: &[LogRecord]) {
    let Some(search) = state.search.as_mut() else { return };
    let query = search.query.to_lowercase();
    if query.is_empty() {
        return;
    }
    let matches: Vec<usize> = logs
        .iter()
        .enumerate()
        .filter(|(_, rec)| rec.message.to_lowercase().contains(&query))
        .map(|(i, _)| i)
        .collect();
    if matches.is_empty() {
        return;
    }
    let line = matches[search.cursor % matches.len()];
    search.cursor += 1;
    state.scroll_offset = line as u16;
    state.auto_scroll = false;
}

/// Build the TUI channels and spawn the TUI thread. Returns a [`TuiHandle`].
pub fn spawn_tui(initial: CertView, shutdown: Arc<tokio::sync::Notify>) -> anyhow::Result<TuiHandle> {
    let (log_tx, log_rx) = crossbeam_channel::unbounded::<LogRecord>();
    let cert = Arc::new(Mutex::new(initial));
    let info = Arc::new(Mutex::new(ServerInfo::default()));
    let stats = Arc::new(ServerStats::new());
    let sessions = Arc::new(Mutex::new(Vec::new()));
    let users = Arc::new(Mutex::new(Vec::new()));

    let cert_clone = cert.clone();
    let info_clone = info.clone();
    let stats_clone = stats.clone();
    let sessions_clone = sessions.clone();
    let users_clone = users.clone();
    let shutdown_clone = shutdown.clone();

    let (init_tx, init_rx) = crossbeam_channel::bounded::<anyhow::Result<()>>(1);
    std::thread::spawn(move || {
        // run_tui sends Ok(()) right after terminal setup, so spawn_tui below
        // returns immediately instead of waiting for the TUI loop to finish.
        // If run_tui fails before that point (raw mode / alternate screen setup),
        // no Ok(()) was sent; propagate the error so spawn_tui does not return a
        // live handle for a TUI that never started.
        let init_tx2 = init_tx.clone();
        if let Err(e) = run_tui(log_rx, cert_clone, info_clone, stats_clone, sessions_clone, users_clone, shutdown_clone, init_tx) {
            let _ = init_tx2.send(Err(e));
        }
    });

    match init_rx.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(anyhow::anyhow!("TUI failed to start: {}", e)),
        Err(_) => {}
    }

    Ok(TuiHandle {
        log_tx,
        cert,
        info,
        stats,
        sessions,
        users,
        shutdown,
    })
}
