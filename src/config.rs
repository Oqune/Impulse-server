//! Server configuration and CLI parsing.
//!
//! Configuration is resolved from (in increasing priority):
//!   1. built-in defaults,
//!   2. an optional `config.toml` next to the executable,
//!   3. command-line flags (which always win when provided).

use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug, Clone)]
#[command(name = "impulse-server")]
#[command(about = "Secure ephemeral messenger server over WebTransport (QUIC)")]
pub struct CliArgs {
    #[arg(long, help = "Bind host (overrides config file)")]
    pub host: Option<String>,

    #[arg(
        short,
        long,
        help = "WebTransport (QUIC) listen port (overrides config file)"
    )]
    pub port: Option<u16>,

    #[arg(
        long,
        help = "Directory to store the generated certificate/key (overrides config file)"
    )]
    pub cert_dir: Option<String>,

    #[arg(long, num_args = 0.., help = "Extra SAN (DNS name or IP) for the generated self-signed certificate")]
    pub san: Vec<String>,

    #[arg(
        long,
        help = "Password hash (SHA-256 hex) for authentication (overrides config file)"
    )]
    pub password_hash: Option<String>,

    #[arg(
        long,
        help = "Compute SHA-256 hex of a password (prints to stdout and exits). Use this to generate the password_hash value."
    )]
    pub hash_password: Option<String>,

    #[arg(long, help = "Path to a TOML config file")]
    pub config: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    /// Socket address the WebTransport endpoint binds to, e.g. `0.0.0.0:4433`.
    pub address: String,
    /// Directory where the self-signed certificate + key are persisted.
    pub cert_dir: String,
    /// Extra Subject Alternative Names for the certificate.
    #[serde(default)]
    pub san: Vec<String>,
    /// Password hash for authentication (SHA-256 hex). Required.
    pub password_hash: String,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:4433".to_string(),
            cert_dir: "cert_data".to_string(),
            san: Vec::new(),
            // No insecure default; callers must supply a real hash.
            password_hash: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerSettings,
}

impl AppConfig {
    /// Validate that the resolved configuration is usable. Returns an error if a
    /// required field (the password hash) is missing.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.server.password_hash.trim().is_empty() {
            anyhow::bail!(
                "no password hash configured: pass --password-hash <sha256-hex> or set \
                 `server.password_hash` in config.toml"
            );
        }
        if self.server.password_hash.len() != 64
            || !self
                .server
                .password_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            anyhow::bail!(
                "password_hash must be a 64-character lower/upper-case SHA-256 hex string, \
                 got {} chars",
                self.server.password_hash.len()
            );
        }
        Ok(())
    }
}

/// Resolve the effective configuration from a TOML file (if found) and CLI flags.
pub fn load_config(cli_args: &CliArgs) -> anyhow::Result<AppConfig> {
    if let Some(pw) = &cli_args.hash_password {
        let hash = sha256_hex(pw);
        println!("{hash}");
        std::process::exit(0);
    }
    let mut config = load_file_config(cli_args.config.as_deref()).unwrap_or_default();

    if let Some(host) = &cli_args.host {
        config.server.address = format!(
            "{}:{}",
            host,
            current_port(&config.server.address, cli_args.port)
        );
    }
    if let Some(port) = cli_args.port {
        config.server.address = format!("{}:{}", current_host(&config.server.address), port);
    }
    if let Some(cert_dir) = &cli_args.cert_dir {
        config.server.cert_dir = cert_dir.clone();
    }
    if !cli_args.san.is_empty() {
        config.server.san = cli_args.san.clone();
    }
    if let Some(hash) = &cli_args.password_hash {
        config.server.password_hash = hash.clone();
    }

    config.validate()?;
    Ok(config)
}

fn current_host(address: &str) -> &str {
    address
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or("0.0.0.0")
}

fn current_port(address: &str, cli_port: Option<u16>) -> u16 {
    cli_port
        .or_else(|| address.rsplit_once(':').and_then(|(_, p)| p.parse().ok()))
        .unwrap_or(4433)
}

/// Helper: SHA-256 hex of a UTF-8 string (used by --hash-password).
pub fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Load `config.toml` from the given path, or from next to the executable.
fn load_file_config(path: Option<&str>) -> Option<AppConfig> {
    let path = match path {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            let exe = std::env::current_exe().ok()?;
            let dir = exe.parent()?;
            let candidate = dir.join("config.toml");
            if !candidate.exists() {
                return None;
            }
            candidate
        }
    };
    let text = std::fs::read_to_string(&path).ok()?;
    toml::from_str(&text).ok()
}
