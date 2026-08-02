//! Config-file writer (refuses overwrite, 0600 on Unix).

use std::path::Path;

use crate::config::AppConfig;

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
