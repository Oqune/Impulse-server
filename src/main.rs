use clap::Parser;
use impulse_server::WsServer;
use impulse_server::config::{CliArgs, load_config};
use impulse_server::console::{LogLevel, log, set_colors_enabled};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = CliArgs::parse();
    set_colors_enabled(!cli.no_color);
    let app_config = load_config(&cli);

    impulse_server::console::print_banner(env!("CARGO_PKG_VERSION"), &app_config.server.address);

    let mut server = WsServer::with_config(app_config.server.clone());

    log(
        LogLevel::Info,
        "SERVER",
        &format!("Starting secure (WSS) on {}", server.address()),
    );
    println!();

    tokio::select! {
        result = server.start() => {
            if let Err(e) = result {
                log(LogLevel::Error, "SERVER", &format!("Server error: {}", e));
            }
        }
        _ = shutdown_signal() => {
            log(LogLevel::Info, "SERVER", "Shutdown signal received, stopping");
            server.shutdown();
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            log(
                LogLevel::Error,
                "SERVER",
                &format!("Failed to listen for Ctrl+C: {}", e),
            );
        }
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
