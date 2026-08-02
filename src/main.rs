use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use impulse_server::cli::{LICENSE_TEXT, run_first_run_wizard, run_init_wizard};
use impulse_server::config::cli::{CliArgs, resolve_command, SetupCommand};
use impulse_server::config::{config_file_loaded, load_config};
use impulse_server::crypto::argon2_hash;
use impulse_server::run;
use tokio::sync::Notify;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = CliArgs::parse();

    // One-shot commands that exit before the server starts.
    match resolve_command(&cli)? {
        SetupCommand::HashPassword(pw) => {
            println!("{}", argon2_hash(&pw)?);
            return Ok(());
        }
        SetupCommand::PrintLicense => {
            print!("{}", LICENSE_TEXT);
            return Ok(());
        }
        SetupCommand::Init => {
            run_init_wizard(cli.force)?;
            return Ok(());
        }
        SetupCommand::Run => {}
    }

    // First-run onboarding: no config file and no hash, interactive terminal.
    if !config_file_loaded(&cli)
        && cli.password_hash.is_none()
        && std::io::stdin().is_terminal()
    {
        run_first_run_wizard()?;
    }

    let app_config = load_config(&cli)?;

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
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::event::DisableMouseCapture
        );
        eprintln!("Fatal error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
