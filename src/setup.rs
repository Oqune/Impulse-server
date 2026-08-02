//! First-run wizard and `--init` interactive setup, plus config-file writing.

use std::io::{self, Write};
use std::path::Path;

use crate::config::AppConfig;

/// MIT license text embedded from the repo-root LICENSE file.
pub const LICENSE_TEXT: &str = include_str!("../LICENSE");

/// Write a minimal config file as TOML.
///
/// * Refuses to overwrite an existing file unless `overwrite` is set.
/// * Written with mode `0600` on Unix (the password hash is sensitive).
/// * `address`, `cert_dir`, `password_hash` are always emitted; `address6`
///   and `san` are omitted when empty (see `skip_serializing_if` in config.rs).
pub fn write_config_file(path: &Path, cfg: &AppConfig, overwrite: bool) -> anyhow::Result<()> {
    if path.exists() && !overwrite {
        anyhow::bail!("{} already exists (refusing to overwrite)", path.display());
    }
    let text = toml::to_string_pretty(cfg)?;
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(text.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, text)?;
    }
    Ok(())
}

/// Error hint for a failed password attempt; `None` on the last attempt so the
/// user is not told to "try again" right before the wizard bails.
fn attempt_error_message(attempt: usize, mismatch: bool) -> Option<&'static str> {
    if attempt == 2 {
        return None;
    }
    Some(if mismatch {
        "Passwords do not match, try again."
    } else {
        "Password must not be empty, try again."
    })
}

/// Prompt for a password twice (hidden input, rpassword). Up to 3 attempts,
/// then an error. Rejects empty passwords and mismatches.
pub fn prompt_password(prompt: &str) -> anyhow::Result<String> {
    for attempt in 0..3 {
        print!("{prompt}");
        io::stdout().flush()?;
        let first = rpassword::read_password()?;
        print!("Repeat password: ");
        io::stdout().flush()?;
        let second = rpassword::read_password()?;
        if first == second && !first.is_empty() {
            return Ok(first);
        }
        if let Some(msg) = attempt_error_message(attempt, first != second) {
            eprintln!("{msg}");
        }
    }
    anyhow::bail!("too many failed password attempts")
}

/// Prompt for a line; empty input returns `default`.
fn prompt_line(prompt: &str, default: &str) -> anyhow::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

/// First-run wizard (startup path A): prompt for a password, write a minimal
/// `config.toml` to the current directory. The caller then loads it normally.
pub fn run_first_run_wizard() -> anyhow::Result<()> {
    let password = prompt_password("Enter client password: ")?;
    let cfg = crate::config::AppConfig {
        server: crate::config::ServerSettings {
            password_hash: crate::config::argon2_hash(&password),
            ..Default::default()
        },
    };
    cfg.validate()?;
    write_config_file(Path::new("config.toml"), &cfg, false)?;
    println!("Config written to config.toml.");
    Ok(())
}

/// `--init` wizard (path B): interactive setup that writes config.toml and exits.
pub fn run_init_wizard(force: bool) -> anyhow::Result<()> {
    let password = prompt_password("Enter client password: ")?;
    let mut settings = crate::config::ServerSettings {
        password_hash: crate::config::argon2_hash(&password),
        ..Default::default()
    };

    settings.address = prompt_line(
        &format!("Bind address [{}]: ", settings.address),
        &settings.address,
    )?;
    settings.cert_dir = prompt_line(
        &format!("Certificate directory [{}]: ", settings.cert_dir),
        &settings.cert_dir,
    )?;
    let san_line = prompt_line("Extra SANs (comma-separated, empty = none): ", "")?;
    settings.san = san_line
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let cfg = crate::config::AppConfig { server: settings };
    cfg.validate()?;
    write_config_file(Path::new("config.toml"), &cfg, force)?;
    println!("Config written to config.toml. Run impulse-server to start.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::attempt_error_message;

    #[test]
    fn last_attempt_gets_no_try_again_message() {
        assert!(attempt_error_message(2, true).is_none(), "final attempt must not say 'try again'");
        assert!(attempt_error_message(2, false).is_none(), "final attempt must not say 'try again'");
        assert!(attempt_error_message(0, true).is_some());
        assert!(attempt_error_message(1, false).is_some());
    }
}
