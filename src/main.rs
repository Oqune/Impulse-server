use clap::Parser;
use impulse_server::config::{load_config, CliArgs, SharedConfig};
use impulse_server::console::{log, LogLevel};
use impulse_server::WsServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI arguments (also reads env vars via clap's env attribute)
    let cli = CliArgs::parse();

    // Load configuration from all sources
    let app_config = match load_config(&cli) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    // Print modern styled configuration banner
    impulse_server::console::print_banner(
        "0.1.0",
        &app_config.server.address,
        Some(&app_config.api.address),
        app_config.api.enabled,
    );

    // Create shared configuration for runtime updates
    let shared_config = SharedConfig::new(app_config.clone());

    // Start configuration API if enabled
    if app_config.api.enabled {
        let api_config = shared_config.clone();
        let api_address = app_config.api.address.clone();
        tokio::spawn(async move {
            log(
                LogLevel::Info,
                "CONFIG",
                &format!("Configuration API started on {}", api_address),
            );
            if let Err(e) = impulse_server::config_api::start_config_api(api_config, &api_address).await {
                log(LogLevel::Error, "CONFIG", &format!("Configuration API error: {}", e));
            }
        });
    }

    // Create server with configuration from shared config
    let current_config = shared_config.get().await;
    let server_config = impulse_server::ServerConfig {
        address: current_config.server.address.clone(),
        password: current_config.server.password.clone(),
    };
    let mut server = WsServer::with_config(server_config);

    log(
        LogLevel::Info,
        "SERVER",
        &format!("Starting WebSocket server on {}", server.address()),
    );
    println!();

    // Start the server (this will block until shutdown is called)
    server.start().await?;

    Ok(())
}
