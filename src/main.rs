use clap::Parser;
use impulse_server::config::{load_config, CliArgs};
use impulse_server::console::{log, LogLevel, set_colors_enabled};
use impulse_server::WsServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = CliArgs::parse();
    set_colors_enabled(!cli.no_color);
    let app_config = load_config(&cli);

    impulse_server::console::print_banner(env!("CARGO_PKG_VERSION"), &app_config.server.address);

    let server_config = impulse_server::ServerConfig {
        address: app_config.server.address.clone(),
        password: app_config.server.password.clone(),
    };
    let mut server = WsServer::with_config(server_config);

    log(LogLevel::Info, "SERVER", &format!("Starting on {}", server.address()));
    println!();

    server.start().await?;
    Ok(())
}
