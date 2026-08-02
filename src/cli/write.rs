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

#[cfg(test)]
mod tests {
    use super::write_config_file;
    use crate::config::{AppConfig, ServerSettings};

    const TEST_HASH: &str = "$argon2id$v=19$m=47104,t=3,p=1$ZU3OGIF2VhIrUVb19y2izg$7njBEf6KUZtU/sC4HSVFti9DFEC3Mkwqd+uQsUqBAUc";

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("impulse-setup-test-{name}-{}.toml", std::process::id()))
    }

    #[test]
    fn write_config_roundtrips_and_omits_empty_optional_fields() {
        let path = temp_path("roundtrip");
        let cfg = AppConfig {
            server: ServerSettings {
                password_hash: TEST_HASH.to_string(),
                ..Default::default()
            },
        };
        write_config_file(&path, &cfg, false).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("password_hash"), "text: {text}");
        assert!(!text.contains("address6"), "address6 should be omitted: {text}");
        assert!(!text.contains("san"), "san should be omitted: {text}");
        let parsed: AppConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed.server.password_hash, TEST_HASH);
        assert_eq!(parsed.server.address, "0.0.0.0:4433");
        assert_eq!(parsed.server.cert_dir, "cert_data");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_config_refuses_overwrite_without_flag() {
        let path = temp_path("overwrite");
        let cfg = AppConfig::default();
        write_config_file(&path, &cfg, false).unwrap();
        let err = write_config_file(&path, &cfg, false).unwrap_err();
        assert!(err.to_string().contains("already exists"), "err: {err}");
        write_config_file(&path, &cfg, true).unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn write_config_sets_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("mode");
        let cfg = AppConfig::default();
        write_config_file(&path, &cfg, false).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {mode:o}");
        let _ = std::fs::remove_file(&path);
    }
}
