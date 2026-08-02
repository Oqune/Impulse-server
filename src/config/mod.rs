//! Server configuration and CLI parsing.
//!
//! Configuration is resolved from (in increasing priority):
//!   1. built-in defaults,
//!   2. an optional TOML config file (`--config <path>`, or `config.toml`
//!      discovered in the current directory, then next to the executable),
//!   3. command-line flags (which always win when provided).
//!
//! A config file that is explicitly requested or discovered but cannot be read
//! or parsed is a fatal error — the server never silently falls back to
//! defaults, so a misconfiguration surfaces immediately at startup.

pub mod cli;
pub mod file;

pub use cli::{CliArgs, SetupCommand, resolve_command};
pub use file::{config_file_loaded, load_file_config, resolve_config_path};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    /// IPv4 bind address, e.g. `0.0.0.0:4433`.
    #[serde(default = "default_address_v4")]
    pub address: String,
    /// IPv6 bind address, e.g. `[::]:4433`. Empty string = disabled.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address6: String,
    /// Directory where the self-signed certificate + key are persisted.
    #[serde(default = "default_cert_dir")]
    pub cert_dir: String,
    /// Extra Subject Alternative Names for the certificate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub san: Vec<String>,
    /// Password hash for authentication (Argon2id encoded). Required at
    /// startup; may be supplied via config, `--password-hash`, or generated
    /// with `--hash-password`.
    #[serde(default)]
    pub password_hash: String,
}

fn default_address_v4() -> String {
    "0.0.0.0:4433".to_string()
}

fn default_cert_dir() -> String {
    "cert_data".to_string()
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            address: default_address_v4(),
            address6: String::new(),
            cert_dir: default_cert_dir(),
            san: Vec::new(),
            password_hash: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerSettings,
}

impl AppConfig {
    /// Validate that the resolved configuration is usable.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.server.password_hash.trim().is_empty() {
            anyhow::bail!(
                "no password hash configured: run 'impulse-server --init' (interactive), \
                 or pass --password-hash <hash>, or set `server.password_hash` in config.toml"
            );
        }
        let h = self.server.password_hash.trim();
        if !h.starts_with("$argon2") {
            // Use chars().take() to avoid panicking on multi-byte UTF-8 at byte boundary.
            let preview: String = h.chars().take(32).collect();
            anyhow::bail!(
                "password_hash must be an Argon2id encoded string (starts with $argon2), \
                 got: {}",
                preview
            );
        }

        // Validate primary bind address.
        if self.server.address.parse::<std::net::SocketAddr>().is_err() {
            anyhow::bail!(
                "invalid bind address '{}': expected format like '0.0.0.0:4433'",
                self.server.address
            );
        }

        // Validate optional IPv6 bind address.
        if !self.server.address6.is_empty() {
            if self.server.address6.parse::<std::net::SocketAddr>().is_err()
                && self.server.address6.parse::<std::net::SocketAddrV6>().is_err()
            {
                anyhow::bail!(
                    "invalid IPv6 bind address '{}': expected format like '[::]:4433'",
                    self.server.address6
                );
            }
        }

        Ok(())
    }
}

/// Resolve the effective configuration from a TOML file (if found) and CLI flags.
pub fn load_config(cli_args: &CliArgs) -> anyhow::Result<AppConfig> {
    let mut config = load_file_config(cli_args.config.as_deref())?.unwrap_or_default();

    // CLI flags override config file values. `--host`/`--port` only rewrite the
    // corresponding part of `server.address` when explicitly given, so a value
    // from the config file is preserved otherwise.
    let file_address = config.server.address.clone();
    let file_port = current_port(&file_address);
    match (&cli_args.host, cli_args.port) {
        (Some(host), Some(port)) => config.server.address = format!("{}:{}", bracket_host(host), port),
        (Some(host), None) => config.server.address = format!("{}:{}", bracket_host(host), file_port),
        (None, Some(port)) => {
            let host = current_host(&file_address);
            config.server.address = format!("{}:{}", host, port);
        }
        (None, None) => {}
    }

    if let Some(ref host6) = cli_args.host6 {
        let port = cli_args.port.unwrap_or(file_port);
        config.server.address6 = format!("{}:{}", bracket_host(host6), port);
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

    // NOTE: Do NOT lowercase the password hash — Base64 is case-sensitive and
    // lowercasing would corrupt the Argon2 salt/hash bytes.

    config.validate()?;
    Ok(config)
}

/// Wrap a host in square brackets when it is an IPv6 literal, e.g. `::` → `[::]`.
fn bracket_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Extract host from address string.
///   IPv4: "0.0.0.0:4433" → "0.0.0.0"
///   IPv6: "[::]:4433" → "[::]"
pub fn current_host(address: &str) -> &str {
    if let Some(bracket_end) = address.rfind(']') {
        return &address[..=bracket_end];
    }
    address
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or("0.0.0.0")
}

/// Extract port from address string.
pub fn current_port(address: &str) -> u16 {
    let after = if let Some(bracket_end) = address.rfind(']') {
        address.get(bracket_end + 1..)
    } else {
        address.rsplit_once(':').map(|(_, p)| p)
    };
    after
        .and_then(|p| p.trim_start_matches(':').parse().ok())
        .unwrap_or(4433)
}
