//! Command-line interface definitions (clap) and one-shot command resolution.

use clap::Parser;

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
        help = "Interactively create a config.toml (prompts for password, address, certificate directory, SANs) and exit"
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
    if cli.force && !cli.init {
        anyhow::bail!("--force requires --init");
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
