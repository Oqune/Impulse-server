//! WebSocket Logging Module
//! Advanced logging system for WebSocket connections with timestamps, colors, and structured output

/// ISO 8601 timestamp with milliseconds
pub struct Timestamp;

impl Timestamp {
    /// Get current timestamp in ISO 8601 format with milliseconds and UTC timezone
    /// Format: YYYY-MM-DDTHH:MM:SS.mmmZ
    pub fn now_iso() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        
        let total_secs = now.as_secs();
        let millis = now.subsec_millis();
        
        let days_since_epoch = total_secs / 86400;
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
        
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", 
            year, month, day, hours, minutes, seconds, millis)
    }
    
    /// Short timestamp for log entries: HH:MM:SS.mmm
    pub fn now_short() -> String {
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
    
    /// Compact timestamp: HH:MM:SS
    pub fn now_compact() -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        
        let total_secs = now.as_secs();
        let hours = (total_secs / 3600) % 24;
        let minutes = (total_secs / 60) % 60;
        let seconds = total_secs % 60;
        
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// WebSocket message direction
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WsDirection {
    In,    // Incoming message
    Out,   // Outgoing message
}

impl WsDirection {
    pub fn label(&self) -> &'static str {
        match self {
            WsDirection::In => "IN",
            WsDirection::Out => "OUT",
        }
    }
}

/// WebSocket frame type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WsFrameType {
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl WsFrameType {
    pub fn label(&self) -> &'static str {
        match self {
            WsFrameType::Text => "TEXT",
            WsFrameType::Binary => "BIN",
            WsFrameType::Close => "CLOSE",
            WsFrameType::Ping => "PING",
            WsFrameType::Pong => "PONG",
        }
    }
}

/// Connection event type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionEvent {
    Connected,
    Disconnected,
    HandshakeError,
    AuthSuccess,
    AuthFailed,
}

impl ConnectionEvent {
    pub fn label(&self) -> &'static str {
        match self {
            ConnectionEvent::Connected => "CONNECT",
            ConnectionEvent::Disconnected => "DISCONNECT",
            ConnectionEvent::HandshakeError => "HS_ERR",
            ConnectionEvent::AuthSuccess => "AUTH_OK",
            ConnectionEvent::AuthFailed => "AUTH_FAIL",
        }
    }
}

/// ANSI colors for WebSocket logging
pub mod ws_colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    
    // WebSocket-specific colors
    pub const WS_GREEN: &str = "\x1b[32m";      // Success/Connect
    pub const WS_RED: &str = "\x1b[31m";        // Error/Disconnect
    pub const WS_YELLOW: &str = "\x1b[33m";     // Warning
    pub const WS_CYAN: &str = "\x1b[36m";       // Info/Meta
    pub const WS_MAGENTA: &str = "\x1b[35m";    // Service/Heartbeat
    pub const WS_WHITE: &str = "\x1b[37m";       // Regular text
    
    // Bright variants
    pub const WS_BRIGHT_GREEN: &str = "\x1b[92m";
    pub const WS_BRIGHT_RED: &str = "\x1b[91m";
    pub const WS_BRIGHT_YELLOW: &str = "\x1b[93m";
    pub const WS_BRIGHT_CYAN: &str = "\x1b[96m";
    pub const WS_BRIGHT_MAGENTA: &str = "\x1b[95m";
}

/// WebSocket log entry with full metadata
pub struct WsLogEntry {
    pub timestamp: String,
    pub direction: WsDirection,
    pub frame_type: WsFrameType,
    pub client_id: Option<u32>,
    pub message: String,
}

impl WsLogEntry {
    /// Create a new WebSocket log entry
    pub fn new(direction: WsDirection, frame_type: WsFrameType, client_id: Option<u32>, message: &str) -> Self {
        Self {
            timestamp: Timestamp::now_short(),
            direction,
            frame_type,
            client_id,
            message: message.to_string(),
        }
    }
    
    /// Format the log entry with colors
    pub fn format(&self) -> String {
        let ts = format!("[{}]", self.timestamp);
        let dir = format!("[{}]", self.direction.label());
        let frame = format!("[{}]", self.frame_type.label());
        
        // Color the components
        let ts_colored = format!("{}{}{}", ws_colors::WS_CYAN, ts, ws_colors::RESET);
        let dir_colored = match self.direction {
            WsDirection::In => format!("{}{}{}", ws_colors::WS_GREEN, dir, ws_colors::RESET),
            WsDirection::Out => format!("{}{}{}", ws_colors::WS_YELLOW, dir, ws_colors::RESET),
        };
        let frame_colored = format!("{}{}{}", ws_colors::WS_MAGENTA, frame, ws_colors::RESET);
        
        let client_str = if let Some(id) = self.client_id {
            format!("[CLIENT:{}]", id)
        } else {
            String::new()
        };
        let client_colored = if !client_str.is_empty() {
            format!("{}{}{}", ws_colors::WS_BRIGHT_CYAN, client_str, ws_colors::RESET)
        } else {
            client_str
        };
        
        format!("{} {} {} {}{}", ts_colored, dir_colored, frame_colored, client_colored, self.message)
    }
}

/// Log a connection event with timestamp
pub fn log_connection(event: ConnectionEvent, client_id: u32, details: &str) {
    let ts = Timestamp::now_short();
    let event_label = event.label();
    
    let (event_colored, symbol) = match event {
        ConnectionEvent::Connected => (format!("{}{}{}", ws_colors::WS_BRIGHT_GREEN, event_label, ws_colors::RESET), "●"),
        ConnectionEvent::Disconnected => (format!("{}{}{}", ws_colors::WS_BRIGHT_RED, event_label, ws_colors::RESET), "○"),
        ConnectionEvent::HandshakeError => (format!("{}{}{}", ws_colors::WS_BRIGHT_RED, event_label, ws_colors::RESET), "✗"),
        ConnectionEvent::AuthSuccess => (format!("{}{}{}", ws_colors::WS_BRIGHT_GREEN, event_label, ws_colors::RESET), "✓"),
        ConnectionEvent::AuthFailed => (format!("{}{}{}", ws_colors::WS_BRIGHT_RED, event_label, ws_colors::RESET), "✗"),
    };
    
    println!(
        "[{}] [WS] {} {} [CLIENT:{}] {}",
        ts,
        symbol,
        event_colored,
        client_id,
        details
    );
}

/// Log a WebSocket message
pub fn ws_log(direction: WsDirection, frame_type: WsFrameType, client_id: Option<u32>, message: &str) {
    let entry = WsLogEntry::new(direction, frame_type, client_id, message);
    println!("{}", entry.format());
}

/// Log incoming message
pub fn ws_in(client_id: u32, frame_type: WsFrameType, message: &str) {
    ws_log(WsDirection::In, frame_type, Some(client_id), message);
}

/// Log outgoing message
pub fn ws_out(client_id: u32, frame_type: WsFrameType, message: &str) {
    ws_log(WsDirection::Out, frame_type, Some(client_id), message);
}

/// Log heartbeat/keepalive
pub fn ws_heartbeat(client_id: u32, direction: WsDirection) {
    let ts = Timestamp::now_short();
    let dir_label = direction.label();
    println!(
        "[{}] [WS] [HEARTBEAT] {} [CLIENT:{}] PING/PONG",
        ts,
        dir_label,
        client_id
    );
}

/// Log an error
pub fn ws_error(client_id: u32, error: &str) {
    let ts = Timestamp::now_short();
    println!(
        "[{}] [WS] [ERROR] {} [CLIENT:{}] {}",
        ts,
        "[ERROR]",
        client_id,
        error
    );
}

/// Status dashboard showing active connections
pub fn print_status_dashboard(active_count: usize, total_messages: usize) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                      STATUS DASHBOARD                         ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Active Connections: {:<45} ║", format!("{}", active_count));
    println!("║  Total Messages: {:<48} ║", format!("{}", total_messages));
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
}

/// Print connection header (ASCII art style)
pub fn print_connection_header(client_id: u32, addr: &str) {
    println!();
    println!("┌────────────────────────────────────────────────────────────────┐");
    println!("│  [CONNECT] New WebSocket Connection                           │");
    println!("├────────────────────────────────────────────────────────────────┤");
    println!("│  Client ID: {:<53} │", client_id);
    println!("│  Address:   {:<53} │", addr);
    println!("└────────────────────────────────────────────────────────────────┘");
}

/// Print disconnection footer
pub fn print_disconnection_footer(client_id: u32, duration_secs: u64) {
    println!("┌────────────────────────────────────────────────────────────────┐");
    println!("│  [DISCONNECT] Connection Closed                               │");
    println!("├────────────────────────────────────────────────────────────────┤");
    println!("│  Client ID: {:<53} │", client_id);
    println!("│  Duration:  {:<53} │", format!("{} seconds", duration_secs));
    println!("└────────────────────────────────────────────────────────────────┘");
    println!();
}