use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

static COLORS_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_colors_enabled(enabled: bool) {
    COLORS_ENABLED.store(enabled, Ordering::Relaxed);
}

fn colors_enabled() -> bool {
    COLORS_ENABLED.load(Ordering::Relaxed)
}

pub mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const CYAN: &str = "\x1b[36m";
    pub const BLUE: &str = "\x1b[34m";
    pub const WHITE: &str = "\x1b[37m";
    pub const BRIGHT_BLUE: &str = "\x1b[94m";
    pub const BRIGHT_CYAN: &str = "\x1b[96m";
    pub const BRIGHT_GREEN: &str = "\x1b[92m";
    pub const BRIGHT_YELLOW: &str = "\x1b[93m";
    pub const BRIGHT_RED: &str = "\x1b[91m";
    pub const BRIGHT_WHITE: &str = "\x1b[97m";
    pub const BRIGHT_MAGENTA: &str = "\x1b[95m";
    pub const MAGENTA: &str = "\x1b[35m";
}

pub struct Timestamp;

impl Timestamp {
    pub fn now() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let t = now.as_secs();
        format!(
            "{:02}:{:02}:{:02}.{:03}",
            (t / 3600) % 24,
            (t / 60) % 60,
            t % 60,
            now.subsec_millis()
        )
    }
}

pub struct Styled {
    text: String,
    prefix: String,
    suffix: String,
}

impl Styled {
    pub fn new<S: Into<String>>(text: S, prefix: &str, bold: bool) -> Self {
        let text = text.into();
        let prefix = if bold && colors_enabled() {
            format!("{}{}", colors::BOLD, prefix)
        } else if colors_enabled() {
            prefix.to_string()
        } else {
            String::new()
        };
        let suffix = if colors_enabled() { colors::RESET.to_string() } else { String::new() };
        Self { text, prefix, suffix }
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
}

macro_rules! impl_style {
    ($($ty:ty),*) => {
        $(impl Style for $ty {
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
        })*
    }
}

impl_style!(String, &str);

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
}

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
}

pub fn log(level: LogLevel, component: &str, message: &str) {
    let ts = Timestamp::now();
    let sym = level.symbol();
    let sym_c = match level {
        LogLevel::Debug => sym.magenta(),
        LogLevel::Info => sym.cyan(),
        LogLevel::Warning => sym.yellow(),
        LogLevel::Error => sym.red().bold(),
        LogLevel::Success => sym.green().bold(),
    };

    println!(
        "[{}] [{}] [{}] {} {}",
        ts.dim(),
        sym_c,
        component.bright_blue().bold(),
        match level {
            LogLevel::Debug => "▸".magenta(),
            LogLevel::Info => "▸".cyan(),
            LogLevel::Warning => "⚠".yellow(),
            LogLevel::Error => "✗".red().bold(),
            LogLevel::Success => "✓".green().bold(),
        },
        message
    );
}

pub fn print_banner(version: &str, ws_address: &str) {
    println!();
    println!("  Impulse Server v{} by oqune", version);
    println!("  WebSocket: {}", ws_address);
    println!();
}
