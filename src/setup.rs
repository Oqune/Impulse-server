//! First-run wizard and `--init` interactive setup, plus config-file writing.

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
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut f = opts.open(path)?;
        f.write_all(text.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, text)?;
    }
    Ok(())
}
