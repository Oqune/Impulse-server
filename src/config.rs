use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug, Clone)]
#[command(name = "impulse-server")]
#[command(about = "WebSocket server")]
pub struct CliArgs {
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    #[arg(short, long, default_value = "8087")]
    pub port: u16,

    #[arg(short = 'P', long)]
    pub password: Option<String>,

    #[arg(long, help = "Disable colored output")]
    pub no_color: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub address: String,
    pub password: String,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:8087".to_string(),
            password: "your_secure_password_here".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub server: ServerSettings,
}

pub fn load_config(cli_args: &CliArgs) -> AppConfig {
    let mut config = AppConfig::default();

    config.server.address = format!("{}:{}", cli_args.host, cli_args.port);

    if let Some(ref pwd) = cli_args.password {
        config.server.password = pwd.clone();
    }

    config
}
