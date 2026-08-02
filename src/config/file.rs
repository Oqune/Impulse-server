//! Config-file discovery, loading, and parsing.

use crate::config::AppConfig;
use super::cli::CliArgs;

/// Resolve the config file path to try: explicit `--config`, or auto-discovery
/// in the current directory, then next to the executable.
/// `Ok(None)` means "no config file found" (only possible without `--config`).
pub fn resolve_config_path(path: Option<&str>) -> anyhow::Result<Option<std::path::PathBuf>> {
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
pub fn load_file_config(path: Option<&str>) -> anyhow::Result<Option<AppConfig>> {
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
