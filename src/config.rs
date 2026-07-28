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
    #[arg(
        long,
        default_value = "0.0.0.0",
        help = "IPv4 bind address (default: 0.0.0.0)"
    )]
    pub host: String,

    #[arg(
        long,
        help = "IPv6 bind address (e.g. [::]). Enables dual-stack when set."
    )]
    pub host6: Option<String>,

    #[arg(
        short,
        long,
        default_value_t = 4433,
        help = "WebTransport (QUIC) listen port"
    )]
    pub port: u16,

    #[arg(
        long,
        help = "Directory to store the generated certificate/key"
    )]
    pub cert_dir: Option<String>,

    #[arg(
        long,
        num_args = 0..,
        help = "Extra SAN (DNS name or IP) for the generated self-signed certificate"
    )]
    pub san: Vec<String>,

    #[arg(
        long,
        help = "Password hash for authentication (Argon2id encoded string)"
    )]
    pub password_hash: Option<String>,

    #[arg(
        long,
        help = "Compute Argon2id hash of a password (prints to stdout and exits)"
    )]
    pub hash_password: Option<String>,

    #[arg(long, help = "Path to a TOML config file")]
    pub config: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    /// IPv4 bind address, e.g. `0.0.0.0:4433`.
    #[serde(default = "default_address_v4")]
    pub address: String,
    /// IPv6 bind address, e.g. `[::]:4433`. Empty string = disabled.
    #[serde(default)]
    pub address6: String,
    /// Directory where the self-signed certificate + key are persisted.
    pub cert_dir: String,
    /// Extra Subject Alternative Names for the certificate.
    #[serde(default)]
    pub san: Vec<String>,
    /// Password hash for authentication (Argon2id encoded). Required.
    pub password_hash: String,
}

fn default_address_v4() -> String {
    "0.0.0.0:4433".to_string()
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            address: default_address_v4(),
            address6: String::new(),
            cert_dir: "cert_data".to_string(),
            san: Vec::new(),
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
    /// Validate that the resolved configuration is usable.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.server.password_hash.trim().is_empty() {
            anyhow::bail!(
                "no password hash configured: pass --hash-password <password> or set \
                 `server.password_hash` in config.toml"
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
    if let Some(pw) = &cli_args.hash_password {
        let hash = argon2_hash(pw);
        println!("{hash}");
        std::process::exit(0);
    }

    let mut config = load_file_config(cli_args.config.as_deref()).unwrap_or_default();

    // CLI flags override config file values.
    config.server.address = format!("{}:{}", cli_args.host, cli_args.port);

    if let Some(ref host6) = cli_args.host6 {
        let host6_bracketed = if host6.contains(':') && !host6.starts_with('[') {
            format!("[{}]", host6)
        } else {
            host6.clone()
        };
        config.server.address6 = format!("{}:{}", host6_bracketed, cli_args.port);
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

/// SHA-256 hex of a string (used in tests).
pub fn sha256_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Argon2id hash of a string (used by --hash-password).
pub fn argon2_hash(input: &str) -> String {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use rand::rngs::OsRng;
    let salt = SaltString::generate(&mut OsRng);
    // Use Argon2id explicitly to match argon2_verify which uses Argon2::new(Argon2id, ...).
    // Argon2::default() may use Argon2i which would cause silent verification failures.
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    );
    argon2
        .hash_password(input.as_bytes(), &salt)
        .expect("Argon2 hash should not fail")
        .to_string()
}

/// Verify a password against an Argon2id encoded hash.
pub fn argon2_verify(password: &str, stored_hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let parsed = match PasswordHash::new(stored_hash) {
        Ok(p) => p,
        Err(_) => return false,
    };
    // Use params from the stored hash, not Argon2::default().
    let params = match argon2::Params::try_from(&parsed) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );
    argon2.verify_password(password.as_bytes(), &parsed)
        .is_ok()
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
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Warning: could not read config file {}: {}", path.display(), e);
            return None;
        }
    };
    match toml::from_str(&text) {
        Ok(config) => Some(config),
        Err(e) => {
            eprintln!("Warning: could not parse config file {}: {}", path.display(), e);
            None
        }
    }
}
