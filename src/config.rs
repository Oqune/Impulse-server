use clap::Parser;
use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Parser, Debug, Clone)]
#[command(name = "impulse-server")]
#[command(about = "WebSocket server with external configuration support")]
pub struct CliArgs {

    #[arg(short, long, env = "SERVER_ADDRESS")]
    pub address: Option<String>,

    #[arg(short, long, env = "SERVER_PASSWORD")]
    pub password: Option<String>,

    #[arg(short, long, default_value = "config.json")]
    pub config: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub server: ServerSettings,
    #[serde(default)]
    pub api: ApiSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub address: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSettings {
    pub enabled: bool,
    pub address: String,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:8080".to_string(),
            password: "your_secure_password_here".to_string(),
        }
    }
}

impl Default for ApiSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            address: "0.0.0.0:8081".to_string(),
        }
    }
}

pub fn load_config(cli_args: &CliArgs) -> Result<AppConfig, ConfigError> {
    let _ = dotenvy::dotenv();

    let config_builder = Config::builder()
        .set_default("server.address", "0.0.0.0:8080")?
        .set_default("server.password", "your_secure_password_here")?
        .set_default("api.enabled", true)?
        .set_default("api.address", "0.0.0.0:8081")?
        .add_source(File::with_name(&cli_args.config).required(false))
        .add_source(
            Environment::with_prefix("IMPULSE")
                .prefix_separator("_")
                .separator("__")
                .try_parsing(true),
        );

    let config = config_builder.build()?;

    let mut app_config: AppConfig = config.try_deserialize()?;

    if let Some(ref addr) = cli_args.address {
        app_config.server.address = addr.clone();
    }
    if let Some(ref pwd) = cli_args.password {
        app_config.server.password = pwd.clone();
    }

    Ok(app_config)
}

#[derive(Clone)]
pub struct SharedConfig {
    inner: Arc<RwLock<AppConfig>>,
}

impl SharedConfig {
    pub fn new(config: AppConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(config)),
        }
    }

    pub async fn get(&self) -> AppConfig {
        self.inner.read().await.clone()
    }

    pub async fn update_server_settings(&self, settings: ServerSettings) {
        let mut config = self.inner.write().await;
        config.server = settings;
    }

    pub async fn update_api_settings(&self, settings: ApiSettings) {
        let mut config = self.inner.write().await;
        config.api = settings;
    }

    pub async fn update_password(&self, new_password: String) {
        let mut config = self.inner.write().await;
        config.server.password = new_password;
    }

    pub async fn update_address(&self, new_address: String) {
        let mut config = self.inner.write().await;
        config.server.address = new_address;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.server.address, "0.0.0.0:8080");
        assert_eq!(config.server.password, "your_secure_password_here");
        assert!(config.api.enabled);
        assert_eq!(config.api.address, "0.0.0.0:8081");
    }
}
