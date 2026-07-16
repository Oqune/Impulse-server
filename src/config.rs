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

    #[arg(long, default_value = "cert.pem", help = "Path to TLS certificate (PEM)")]
    pub tls_cert: Option<String>,

    #[arg(long, default_value = "key.pem", help = "Path to TLS private key (PEM)")]
    pub tls_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub address: String,
    pub password: String,
    #[serde(default = "default_auth_message")]
    pub auth_message: String,
    pub tls_cert: String,
    pub tls_key: String,
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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerSettings,
}

pub fn load_config(cli_args: &CliArgs) -> AppConfig {
    let mut config = AppConfig::default();

    config.server.address = format!("{}:{}", cli_args.host, cli_args.port);

    if let Some(ref pwd) = cli_args.password {
        config.server.password = pwd.clone();
    }

    if let Some(cert) = cli_args.tls_cert.clone() {
        config.server.tls_cert = cert;
    }
    if let Some(key) = cli_args.tls_key.clone() {
        config.server.tls_key = key;
    }

    config
}
