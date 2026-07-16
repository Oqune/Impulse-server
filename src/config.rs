use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug, Clone)]
#[command(name = "impulse-server")]
#[command(about = "Secure WebSocket (WSS) chat server")]
pub struct CliArgs {
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    #[arg(short, long, default_value = "8443", help = "TLS listen port (WSS)")]
    pub port: u16,

    #[arg(short = 'P', long)]
    pub password: Option<String>,

    #[arg(long, help = "Disable colored output")]
    pub no_color: bool,

    #[arg(
        long,
        default_value = "cert.pem",
        help = "Path to TLS certificate (PEM)"
    )]
    pub tls_cert: String,

    #[arg(
        long,
        default_value = "key.pem",
        help = "Path to TLS private key (PEM)"
    )]
    pub tls_key: String,

    #[arg(long, num_args = 0.., help = "Extra SAN (DNS name or IP) for the generated self-signed certificate")]
    pub tls_san: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub address: String,
    pub password: String,
    #[serde(default = "default_auth_message")]
    pub auth_message: String,
    pub tls_cert: String,
    pub tls_key: String,
    #[serde(default)]
    pub tls_san: Vec<String>,
}

fn default_auth_message() -> String {
    "Authentication successful".to_string()
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:8443".to_string(),
            password: "your_secure_password_here".to_string(),
            auth_message: default_auth_message(),
            tls_cert: "cert.pem".to_string(),
            tls_key: "key.pem".to_string(),
            tls_san: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerSettings,
}

/// Resolve a possibly-relative certificate/key path against the directory of
/// the current executable, so that `cert.pem` placed next to the binary works
/// regardless of the working directory the server is launched from.
pub fn resolve_tls_path(path: &str) -> String {
    let path_buf = std::path::Path::new(path);
    if path_buf.is_absolute() {
        return path.to_string();
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let resolved = dir.join(path_buf);
        if let Some(s) = resolved.to_str() {
            return s.to_string();
        }
    }
    path.to_string()
}

pub fn load_config(cli_args: &CliArgs) -> AppConfig {
    let mut config = AppConfig::default();

    config.server.address = format!("{}:{}", cli_args.host, cli_args.port);

    if let Some(ref pwd) = cli_args.password {
        config.server.password = pwd.clone();
    }

    config.server.tls_cert = resolve_tls_path(&cli_args.tls_cert);
    config.server.tls_key = resolve_tls_path(&cli_args.tls_key);
    config.server.tls_san = cli_args.tls_san.clone();

    config
}
