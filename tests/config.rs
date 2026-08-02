//! CLI/config integration tests (moved from `src/tests.rs`, Task 6).
//!
//! Exercises clap arg parsing, one-shot command resolution, and config-file
//! loading/validation against temp files on disk.

use clap::{CommandFactory, Parser};

use impulse_server::config::cli::{CliArgs, SetupCommand, resolve_command};
use impulse_server::config::{config_file_loaded, load_config};

const TEST_HASH: &str =
    "$argon2id$v=19$m=47104,t=3,p=1$ZU3OGIF2VhIrUVb19y2izg$7njBEf6KUZtU/sC4HSVFti9DFEC3Mkwqd+uQsUqBAUc";

fn cli_with_config(path: Option<&str>) -> CliArgs {
    let mut c = CliArgs::parse_from(["impulse-server"]);
    c.config = path.map(str::to_string);
    c
}

fn temp_config(name: &str, content: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "impulse-config-test-{name}-{}.toml",
        std::process::id()
    ));
    std::fs::write(&p, content).unwrap();
    p
}

#[test]
fn commands_are_mutually_exclusive() {
    let mut c = CliArgs::parse_from(["impulse-server"]);
    c.license = true;
    c.init = true;
    assert!(resolve_command(&c).is_err(), "license+init must be rejected");

    let mut c2 = CliArgs::parse_from(["impulse-server"]);
    c2.init = true;
    c2.hash_password = Some("pw".to_string());
    assert!(
        resolve_command(&c2).is_err(),
        "init+hash-password must be rejected"
    );

    let mut c3 = CliArgs::parse_from(["impulse-server"]);
    c3.license = true;
    c3.hash_password = Some("pw".to_string());
    assert!(
        resolve_command(&c3).is_err(),
        "license+hash-password must be rejected"
    );
}

#[test]
fn commands_resolve_to_expected_variant() {
    let c = CliArgs::parse_from(["impulse-server", "--init"]);
    assert!(matches!(resolve_command(&c).unwrap(), SetupCommand::Init));

    let c = CliArgs::parse_from(["impulse-server", "--license"]);
    assert!(matches!(resolve_command(&c).unwrap(), SetupCommand::PrintLicense));

    let c = CliArgs::parse_from(["impulse-server", "--hash-password", "abc"]);
    assert!(matches!(
        resolve_command(&c).unwrap(),
        SetupCommand::HashPassword(p) if p == "abc"
    ));

    let c = CliArgs::parse_from(["impulse-server"]);
    assert!(matches!(resolve_command(&c).unwrap(), SetupCommand::Run));

    let c = CliArgs::parse_from(["impulse-server", "--init", "--force"]);
    assert!(matches!(resolve_command(&c).unwrap(), SetupCommand::Init));
}

#[test]
fn force_without_init_is_rejected() {
    let c = CliArgs::parse_from(["impulse-server", "--force"]);
    assert!(
        resolve_command(&c).is_err(),
        "--force without --init must be rejected"
    );
}

#[test]
fn init_help_mentions_certificate_directory() {
    let help = CliArgs::command().render_long_help().to_string();
    assert!(
        help.contains("certificate directory"),
        "--init help should mention the certificate-directory prompt"
    );
}

#[test]
fn config_address_is_used_when_no_flags() {
    let path = temp_config(
        "address",
        &format!(
            "[server]\naddress = \"127.0.0.1:9999\"\ncert_dir = \"certs\"\npassword_hash = \"{TEST_HASH}\"\n"
        ),
    );
    let cfg = load_config(&cli_with_config(Some(path.to_str().unwrap()))).unwrap();
    assert_eq!(cfg.server.address, "127.0.0.1:9999");
    assert_eq!(cfg.server.cert_dir, "certs");
}

#[test]
fn missing_explicit_config_is_hard_error() {
    let cli = cli_with_config(Some("definitely-missing-config.toml"));
    let err = load_config(&cli).unwrap_err();
    assert!(
        err.to_string().contains("definitely-missing-config.toml"),
        "error should reference the config path, got: {err}"
    );
}

#[test]
fn malformed_config_is_hard_error() {
    let path = temp_config("bad", "[server\nthis is not toml");
    let err = load_config(&cli_with_config(Some(path.to_str().unwrap()))).unwrap_err();
    assert!(
        err.to_string().contains("parse"),
        "error should mention the parse failure, got: {err}"
    );
}

#[test]
fn cert_dir_defaults_when_missing_in_config() {
    let path = temp_config(
        "nocert",
        &format!("[server]\npassword_hash = \"{TEST_HASH}\"\n"),
    );
    let cfg = load_config(&cli_with_config(Some(path.to_str().unwrap()))).unwrap();
    assert_eq!(cfg.server.cert_dir, "cert_data");
}

#[test]
fn password_hash_flag_fills_missing_config_hash() {
    let path = temp_config(
        "nohash",
        "[server]\naddress = \"0.0.0.0:7777\"\ncert_dir = \"certs\"\n",
    );
    let mut cli = cli_with_config(Some(path.to_str().unwrap()));
    cli.password_hash = Some(TEST_HASH.to_string());
    let cfg = load_config(&cli).unwrap();
    assert_eq!(cfg.server.address, "0.0.0.0:7777");
    assert_eq!(cfg.server.password_hash, TEST_HASH);
}

#[test]
fn unknown_config_field_is_rejected() {
    let path = temp_config(
        "typo",
        &format!("[server]\npassword_hash = \"{TEST_HASH}\"\npor = 4433\n"),
    );
    let err = load_config(&cli_with_config(Some(path.to_str().unwrap()))).unwrap_err();
    assert!(
        err.to_string().contains("por") || err.to_string().contains("unknown field"),
        "error should flag the unknown field, got: {err}"
    );
}

#[test]
fn config_file_loaded_reports_discovery() {
    let dir = std::env::temp_dir().join(format!("impulse-discovery-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("config.toml");
    std::fs::write(
        &cfg_path,
        &format!("[server]\npassword_hash = \"{TEST_HASH}\"\n"),
    )
    .unwrap();

    // Explicit --config always counts as "loaded" (missing file errors in load_config).
    let c = cli_with_config(Some(cfg_path.to_str().unwrap()));
    assert!(config_file_loaded(&c));

    // No explicit config: discovery depends on whether cwd holds a stray
    // config.toml; the exe dir (target/debug/deps) never does.
    let c = cli_with_config(None);
    if std::path::Path::new("config.toml").exists() {
        assert!(config_file_loaded(&c), "expected discovery to find cwd config.toml");
    } else {
        assert!(!config_file_loaded(&c), "expected no config to be discovered");
    }

    let _ = std::fs::remove_file(&cfg_path);
    let _ = std::fs::remove_dir_all(&dir);
}
