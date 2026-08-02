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

use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug, Clone)]
#[command(name = "impulse-server")]
#[command(about = "Secure ephemeral messenger server over WebTransport (QUIC)")]
pub struct CliArgs {
    #[arg(
        long,
        help = "IPv4 bind address (overrides `server.address` in the config file)"
    )]
    pub host: Option<String>,

    #[arg(
        long,
        help = "IPv6 bind address (e.g. [::]). Enables dual-stack when set."
    )]
    pub host6: Option<String>,

    #[arg(
        short,
        long,
        help = "WebTransport (QUIC) listen port (overrides the port in the config file)"
    )]
    pub port: Option<u16>,

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

    #[arg(
        long,
        help = "Interactively create a config.toml (prompts for password, address, SANs) and exit"
    )]
    pub init: bool,

    #[arg(
        long,
        help = "Overwrite an existing config.toml when used with --init"
    )]
    pub force: bool,

    #[arg(long, help = "Print the MIT license text and exit")]
    pub license: bool,

    #[arg(long, help = "Path to a TOML config file")]
    pub config: Option<String>,
}

/// One-shot commands that exit before the server starts.
#[derive(Debug, PartialEq, Eq)]
pub enum SetupCommand {
    /// Normal run: start the relay.
    Run,
    /// `--hash-password <pw>`: print an Argon2id hash and exit.
    HashPassword(String),
    /// `--license`: print the MIT license text and exit.
    PrintLicense,
    /// `--init`: run the interactive setup wizard and exit.
    Init,
}

/// Resolve the one-shot command from CLI flags, rejecting combinations.
pub fn resolve_command(cli: &CliArgs) -> anyhow::Result<SetupCommand> {
    let count =
        usize::from(cli.license) + usize::from(cli.init) + usize::from(cli.hash_password.is_some());
    if count > 1 {
        anyhow::bail!("--license, --init, and --hash-password are mutually exclusive");
    }
    if cli.license {
        return Ok(SetupCommand::PrintLicense);
    }
    if cli.init {
        return Ok(SetupCommand::Init);
    }
    if let Some(pw) = &cli.hash_password {
        return Ok(SetupCommand::HashPassword(pw.clone()));
    }
    Ok(SetupCommand::Run)
}

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

/// Resolve the config file path to try: explicit `--config`, or auto-discovery
/// in the current directory, then next to the executable.
/// `Ok(None)` means "no config file found" (only possible without `--config`).
fn resolve_config_path(path: Option<&str>) -> anyhow::Result<Option<std::path::PathBuf>> {
    match path {
        Some(p) => Ok(Some(std::path::PathBuf::from(p))),
        None => {
            let cwd = std::env::current_dir().ok().map(|d| d.join("config.toml"));
            if let Some(c) = cwd.as_ref() && c.exists() {
                Ok(Some(c.clone()))
            } else if let Some(exe_dir) = std::env::current_exe().ok()
                .and_then(|e| e.parent().map(|p| p.to_path_buf()))
            {
                let candidate = exe_dir.join("config.toml");
                if candidate.exists() {
                    Ok(Some(candidate))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }
    }
}

/// Whether a config file was explicitly requested or auto-discovered.
/// An explicit `--config` counts as loaded even if missing — `load_config`
/// reports the missing-file error. Used to decide if the first-run wizard runs.
pub fn config_file_loaded(cli_args: &CliArgs) -> bool {
    if cli_args.config.is_some() {
        return true;
    }
    resolve_config_path(None).map(|p| p.is_some()).unwrap_or(false)
}

/// Load `config.toml` from `--config <path>`, or auto-discover it in the
/// current directory and next to the executable.
///
/// An explicit path that cannot be read, or any discovered file that cannot be
/// parsed, is a fatal error (the server never silently falls back to defaults).
/// `Ok(None)` means "no config file found" and is only returned when no
/// `--config` was given and neither candidate exists.
fn load_file_config(path: Option<&str>) -> anyhow::Result<Option<AppConfig>> {
    let path = match resolve_config_path(path)? {
        Some(p) => p,
        None => return Ok(None),
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            anyhow::bail!("could not read config file {}: {}", path.display(), e);
        }
    };
    match toml::from_str(&text) {
        Ok(config) => {
            eprintln!("Using config file: {}", path.display());
            Ok(Some(config))
        }
        Err(e) => {
            anyhow::bail!("could not parse config file {}: {}", path.display(), e);
        }
    }
}
