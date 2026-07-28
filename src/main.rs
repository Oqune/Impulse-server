use std::sync::Arc;

use clap::Parser;
use impulse_server::config::{AppConfig, CliArgs, load_config};
use impulse_server::run;
use tokio::sync::Notify;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = CliArgs::parse();
    let app_config: AppConfig = load_config(&cli)?;

    let shutdown = Arc::new(Notify::new());

    // Trigger graceful shutdown on Ctrl+C / SIGTERM.
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("Received Ctrl+C, shutting down");
            shutdown.notify_one();
        });
    }

    if let Err(e) = run(app_config, shutdown).await {
        // The TUI thread may have put the terminal into raw mode / alternate
        // screen. Clean up before printing the error so the user sees output.
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen
        );
        eprintln!("Fatal error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
