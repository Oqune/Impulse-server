//! Modern console styling module optimized for log viewing with timestamps
//! Provides a beautiful CLI interface for the Impulse Server with structured log output

use std::fmt;

/// ANSI color codes for console styling
pub mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const ITALIC: &str = "\x1b[3m";
    
    // Foreground colors
    pub const BLACK: &str = "\x1b[30m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
    
    // Bright foreground colors
    pub const BRIGHT_BLUE: &str = "\x1b[94m";
    pub const BRIGHT_CYAN: &str = "\x1b[96m";
    pub const BRIGHT_GREEN: &str = "\x1b[92m";
    pub const BRIGHT_YELLOW: &str = "\x1b[93m";
    pub const BRIGHT_RED: &str = "\x1b[91m";
    pub const BRIGHT_WHITE: &str = "\x1b[97m";
    pub const BRIGHT_MAGENTA: &str = "\x1b[95m";
}

/// Timestamp helper for log formatting
pub struct Timestamp;

impl Timestamp {
    /// Get current timestamp in HH:MM:SS format
    pub fn now() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let total_secs = now.as_secs();
        let hours = (total_secs / 3600) % 24;
        let minutes = (total_secs / 60) % 60;
        let seconds = total_secs % 60;
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }

    /// Get current timestamp in HH:MM:SS.mmm format (milliseconds)
    pub fn now_ms() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let total_secs = now.as_secs();
        let millis = now.subsec_millis();
        let hours = (total_secs / 3600) % 24;
        let minutes = (total_secs / 60) % 60;
        let seconds = total_secs % 60;
        format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
    }

    /// Get current date and time in YYYY-MM-DD HH:MM:SS format
    pub fn now_full() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let total_secs = now.as_secs();
        let days_since_epoch = total_secs / 86400;
        
        // Calculate year, month, day (simplified)
        let mut year = 1970;
        let mut remaining_days = days_since_epoch as i64;
        
        loop {
            let days_in_year = if is_leap_year(year) { 366 } else { 365 };
            if remaining_days < days_in_year {
                break;
            }
            remaining_days -= days_in_year;
            year += 1;
        }
        
        let days_in_months: [i64; 12] = if is_leap_year(year) {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };
        
        let mut month = 1;
        for days in days_in_months.iter() {
            if remaining_days < *days {
                break;
            }
            remaining_days -= *days;
            month += 1;
        }
        let day = remaining_days + 1;
        
        let hours = (total_secs / 3600) % 24;
        let minutes = (total_secs / 60) % 60;
        let seconds = total_secs % 60;
        
        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, hours, minutes, seconds)
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// ANSI escaped colored string wrapper
pub struct Styled {
    text: String,
    prefix: String,
    suffix: String,
}

impl Styled {
    pub fn new<S: Into<String>>(text: S, prefix: &str, bold: bool) -> Self {
        let text = text.into();
        let prefix = if bold {
            format!("{}{}", colors::BOLD, prefix)
        } else {
            prefix.to_string()
        };
        Self {
            text,
            prefix,
            suffix: colors::RESET.to_string(),
        }
    }

    pub fn from_string<S: Into<String>>(text: S) -> Self {
        Self {
            text: text.into(),
            prefix: String::new(),
            suffix: colors::RESET.to_string(),
        }
    }
}

impl fmt::Display for Styled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.prefix.is_empty() {
            write!(f, "{}", self.text)
        } else {
            write!(f, "{}{}{}", self.prefix, self.text, self.suffix)
        }
    }
}

/// Trait for styling strings with ANSI colors
pub trait Style: Sized + fmt::Display {
    fn bold(self) -> Styled;
    fn dim(self) -> Styled;
    fn red(self) -> Styled;
    fn green(self) -> Styled;
    fn yellow(self) -> Styled;
    fn blue(self) -> Styled;
    fn cyan(self) -> Styled;
    fn magenta(self) -> Styled;
    fn white(self) -> Styled;
    fn bright_red(self) -> Styled;
    fn bright_green(self) -> Styled;
    fn bright_yellow(self) -> Styled;
    fn bright_blue(self) -> Styled;
    fn bright_cyan(self) -> Styled;
    fn bright_magenta(self) -> Styled;
    fn bright_white(self) -> Styled;
    fn italic(self) -> Styled;
}

impl Style for String {
    fn bold(self) -> Styled { Styled::new(self, "", true) }
    fn dim(self) -> Styled { Styled::new(self, colors::DIM, false) }
    fn red(self) -> Styled { Styled::new(self, colors::RED, false) }
    fn green(self) -> Styled { Styled::new(self, colors::GREEN, false) }
    fn yellow(self) -> Styled { Styled::new(self, colors::YELLOW, false) }
    fn blue(self) -> Styled { Styled::new(self, colors::BLUE, false) }
    fn cyan(self) -> Styled { Styled::new(self, colors::CYAN, false) }
    fn magenta(self) -> Styled { Styled::new(self, colors::MAGENTA, false) }
    fn white(self) -> Styled { Styled::new(self, colors::WHITE, false) }
    fn bright_red(self) -> Styled { Styled::new(self, colors::BRIGHT_RED, true) }
    fn bright_green(self) -> Styled { Styled::new(self, colors::BRIGHT_GREEN, true) }
    fn bright_yellow(self) -> Styled { Styled::new(self, colors::BRIGHT_YELLOW, false) }
    fn bright_blue(self) -> Styled { Styled::new(self, colors::BRIGHT_BLUE, true) }
    fn bright_cyan(self) -> Styled { Styled::new(self, colors::BRIGHT_CYAN, false) }
    fn bright_magenta(self) -> Styled { Styled::new(self, colors::BRIGHT_MAGENTA, false) }
    fn bright_white(self) -> Styled { Styled::new(self, colors::BRIGHT_WHITE, false) }
    fn italic(self) -> Styled { Styled::new(self, colors::ITALIC, false) }
}

impl Style for &str {
    fn bold(self) -> Styled { Styled::new(self, "", true) }
    fn dim(self) -> Styled { Styled::new(self, colors::DIM, false) }
    fn red(self) -> Styled { Styled::new(self, colors::RED, false) }
    fn green(self) -> Styled { Styled::new(self, colors::GREEN, false) }
    fn yellow(self) -> Styled { Styled::new(self, colors::YELLOW, false) }
    fn blue(self) -> Styled { Styled::new(self, colors::BLUE, false) }
    fn cyan(self) -> Styled { Styled::new(self, colors::CYAN, false) }
    fn magenta(self) -> Styled { Styled::new(self, colors::MAGENTA, false) }
    fn white(self) -> Styled { Styled::new(self, colors::WHITE, false) }
    fn bright_red(self) -> Styled { Styled::new(self, colors::BRIGHT_RED, true) }
    fn bright_green(self) -> Styled { Styled::new(self, colors::BRIGHT_GREEN, true) }
    fn bright_yellow(self) -> Styled { Styled::new(self, colors::BRIGHT_YELLOW, false) }
    fn bright_blue(self) -> Styled { Styled::new(self, colors::BRIGHT_BLUE, true) }
    fn bright_cyan(self) -> Styled { Styled::new(self, colors::BRIGHT_CYAN, false) }
    fn bright_magenta(self) -> Styled { Styled::new(self, colors::BRIGHT_MAGENTA, false) }
    fn bright_white(self) -> Styled { Styled::new(self, colors::BRIGHT_WHITE, false) }
    fn italic(self) -> Styled { Styled::new(self, colors::ITALIC, false) }
}

impl Style for Styled {
    fn bold(self) -> Styled { Styled::new(self.to_string(), "", true) }
    fn dim(self) -> Styled { Styled::new(self.to_string(), colors::DIM, false) }
    fn red(self) -> Styled { Styled::new(self.to_string(), colors::RED, false) }
    fn green(self) -> Styled { Styled::new(self.to_string(), colors::GREEN, false) }
    fn yellow(self) -> Styled { Styled::new(self.to_string(), colors::YELLOW, false) }
    fn blue(self) -> Styled { Styled::new(self.to_string(), colors::BLUE, false) }
    fn cyan(self) -> Styled { Styled::new(self.to_string(), colors::CYAN, false) }
    fn magenta(self) -> Styled { Styled::new(self.to_string(), colors::MAGENTA, false) }
    fn white(self) -> Styled { Styled::new(self.to_string(), colors::WHITE, false) }
    fn bright_red(self) -> Styled { Styled::new(self.to_string(), colors::BRIGHT_RED, true) }
    fn bright_green(self) -> Styled { Styled::new(self.to_string(), colors::BRIGHT_GREEN, true) }
    fn bright_yellow(self) -> Styled { Styled::new(self.to_string(), colors::BRIGHT_YELLOW, false) }
    fn bright_blue(self) -> Styled { Styled::new(self.to_string(), colors::BRIGHT_BLUE, true) }
    fn bright_cyan(self) -> Styled { Styled::new(self.to_string(), colors::BRIGHT_CYAN, false) }
    fn bright_magenta(self) -> Styled { Styled::new(self.to_string(), colors::BRIGHT_MAGENTA, false) }
    fn bright_white(self) -> Styled { Styled::new(self.to_string(), colors::BRIGHT_WHITE, false) }
    fn italic(self) -> Styled { Styled::new(self.to_string(), colors::ITALIC, false) }
}

/// Log level for structured logging
#[derive(Debug, Clone, Copy)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Success,
}

impl LogLevel {
    pub fn symbol(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DBG",
            LogLevel::Info => "INF",
            LogLevel::Warning => "WRN",
            LogLevel::Error => "ERR",
            LogLevel::Success => "OK ",
        }
    }

    pub fn color(&self) -> Styled {
        match self {
            LogLevel::Debug => "▸".magenta(),
            LogLevel::Info => "▸".cyan(),
            LogLevel::Warning => "⚠".yellow(),
            LogLevel::Error => "✗".red().bold(),
            LogLevel::Success => "✓".green().bold(),
        }
    }
}

/// Print a log entry with timestamp and level
pub fn log(level: LogLevel, component: &str, message: &str) {
    let timestamp = Timestamp::now();
    let level_str = level.symbol();
    let symbol = level.color();
    
    // Get color for level
    let level_colored = match level {
        LogLevel::Debug => level_str.magenta(),
        LogLevel::Info => level_str.cyan(),
        LogLevel::Warning => level_str.yellow(),
        LogLevel::Error => level_str.red().bold(),
        LogLevel::Success => level_str.green().bold(),
    };
    
    // Format: [HH:MM:SS] [LEVEL] [COMPONENT] Message
    println!(
        "[{}] [{}] [{}] {} {}",
        timestamp.dim(),
        level_colored,
        component.bright_blue().bold(),
        symbol,
        message
    );
}

/// Print a simple log entry
pub fn log_simple(component: &str, message: &str) {
    let timestamp = Timestamp::now();
    println!(
        "[{}] [{}] {}",
        timestamp.dim(),
        component.bright_blue().bold(),
        message
    );
}

/// Print a log entry with timestamp only
pub fn log_timestamp(component: &str, message: &str) {
    let timestamp = Timestamp::now();
    println!(
        "[{}] {} | {}",
        timestamp.bright_white().dim(),
        component.bright_cyan().bold(),
        message
    );
}

/// Print a styled banner at startup
pub fn print_banner(
    _version: &str,
    ws_address: &str,
    api_address: Option<&str>,
    api_enabled: bool,
) {
    // Calculate dynamic width based on content
    let ws_line = format!("WebSocket: {}", ws_address);
    let api_line = if api_enabled {
        format!("Config API: {}", api_address.unwrap_or(""))
    } else {
        "Config API: disabled".to_string()
    };
    
    let title = "SERVER CONFIGURATION";
    let max_len = ws_line.len().max(api_line.len()).max(title.len());
    // Width needs to accommodate content + padding
    let width = max_len + 4; // Extra padding for visual balance
    
    println!();
    
    // Title - full width
    let total_width = width + 4; // ║ + space + content + space + ║
    println!("{}{}{}", "╔", "═".repeat(total_width - 2), "╗");
    println!("║ {:^width$} ║", title);
    println!("{}{}{}", "╠", "═".repeat(total_width - 2), "╣");
    
    // WebSocket line - left aligned
    println!("║ {:width$} ║", ws_line);
    
    // Config API line
    println!("║ {:width$} ║", api_line);
    
    println!("{}{}{}", "╚", "═".repeat(total_width - 2), "╝");
    println!();
    
    // Status indicators
    log(LogLevel::Success, "SYSTEM", "Server ready");
    if api_enabled {
        log(LogLevel::Info, "CONFIG", &format!("API enabled on {}", api_address.unwrap_or("")));
    }
    
    println!();
}

/// Print a status message (deprecated, use log instead)
pub fn print_info(message: &str) {
    log(LogLevel::Info, "INFO", message);
}

/// Print error message (deprecated, use log instead)
pub fn print_error(message: &str) {
    log(LogLevel::Error, "ERROR", message);
}

/// Print warning message (deprecated, use log instead)
pub fn print_warning(message: &str) {
    log(LogLevel::Warning, "WARN", message);
}

/// Print success message (deprecated, use log instead)
pub fn print_success(message: &str) {
    log(LogLevel::Success, "OK", message);
}

/// Print debug message (deprecated, use log instead)
pub fn print_debug(message: &str) {
    log(LogLevel::Debug, "DEBUG", message);
}

/// Clear screen
#[allow(dead_code)]
pub fn clear_screen() {
    print!("\x1b[2J\x1b[1J");
}

/// Move cursor to top-left
#[allow(dead_code)]
pub fn cursor_home() {
    print!("\x1b[H");
}

/// Save cursor position
#[allow(dead_code)]
pub fn cursor_save() {
    print!("\x1b7");
}

/// Restore cursor position
#[allow(dead_code)]
pub fn cursor_restore() {
    print!("\x1b8");
}