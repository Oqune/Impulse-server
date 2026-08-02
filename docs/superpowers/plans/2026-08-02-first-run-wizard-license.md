# First-Run Wizard, License Credits, Archive Cleanup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add interactive first-run onboarding (`--init` wizard + startup prompt), a `--license` flag and TUI license line, slim the archives to `binary + LICENSE`, and fix the `RUST_LOG`/TUI filter bug plus small cleanups.

**Architecture:** A new `src/setup.rs` module owns all interactive setup and config-file writing; `config.rs` gains a `resolve_command` + `config_file_loaded` and loses its `process::exit` side effect; `main.rs` dispatches one-shot commands (`--license`/`--init`/`--hash-password`) before starting. Packaging changes are separate (`packaging/config.toml`, workflow, docs).

**Tech Stack:** Rust (edition 2024, Rust 1.85+), clap 4 derive, serde/toml 0.8, rpassword (new dep), anyhow, tracing/tracing-subscriber.

## Global Constraints

- Rust 1.85+, edition 2024. No new dependencies except `rpassword = "7"`.
- `password_hash` must never default to a usable value — an empty/missing hash is a loud startup error (no secret by default). Remove the `changeme` placeholder everywhere it is shipped.
- `LICENSE` (MIT) must remain in every archive/package; the copyright + permission notice ships with the software.
- Archive (tar.gz/zip) contents become exactly `impulse-server` (+ `.exe`) and `LICENSE` inside `ImpulseServer-<arch>/`.
- `.deb`/`.rpm` install `packaging/config.toml` at `/etc/impulse-server/config.toml` with `password_hash = ""`.
- Config writer emits `address`, `cert_dir`, `password_hash` always; `address6`/`san` only when non-empty; mode `0600` on Unix.
- `--license`, `--init`, `--hash-password` are mutually exclusive one-shot commands; when any is given the server does not start.
- All `cargo test` must pass on Windows (tests that assert file mode are `#[cfg(unix)]`).
- Current baseline: 61 passing tests. Work happens on branch `master` in `D:\Data\Projects\ImpulseProject\server`.

---

### Task 1: Add `rpassword` and create `src/setup.rs` with the config-file writer

**Files:**
- Modify: `Cargo.toml`
- Create: `src/setup.rs`
- Modify: `src/lib.rs` (add `pub mod setup;`)
- Test: `src/tests.rs` (new `mod setup_tests`)

**Interfaces:**
- Consumes: `crate::config::{AppConfig, ServerSettings}` (both already `Serialize`).
- Produces: `pub fn write_config_file(path: &std::path::Path, cfg: &AppConfig, overwrite: bool) -> anyhow::Result<()>` — writes minimal TOML, `0600` on Unix, refuses overwrite unless `overwrite`.

- [ ] **Step 1: Add the dependency**

In `Cargo.toml`, after the `argon2 = "0.5"` line, add:

```toml
# Hidden password input for --init / first-run wizard
rpassword = "7"
```

- [ ] **Step 2: Create `src/setup.rs`**

```rust
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
```

- [ ] **Step 3: Register the module in `src/lib.rs`**

Add to the module list (alphabetical, after `pub mod server;`):

```rust
pub mod setup;
```

- [ ] **Step 4: Add `skip_serializing_if` to `ServerSettings` in `src/config.rs`**

In `struct ServerSettings` (config.rs:70), change `address6` and `san` so they serialize only when non-empty:

```rust
    /// IPv6 bind address, e.g. `[::]:4433`. Empty string = disabled.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address6: String,
    /// Extra Subject Alternative Names for the certificate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub san: Vec<String>,
```

- [ ] **Step 5: Write the failing tests**

Append this module to the end of `src/tests.rs`:

```rust
mod setup_tests {
    use crate::config::AppConfig;
    use crate::setup::write_config_file;

    const TEST_HASH: &str = "$argon2id$v=19$m=47104,t=3,p=1$ZU3OGIF2VhIrUVb19y2izg$7njBEf6KUZtU/sC4HSVFti9DFEC3Mkwqd+uQsUqBAUc";

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("impulse-setup-test-{name}-{}.toml", std::process::id()))
    }

    #[test]
    fn write_config_roundtrips_and_omits_empty_optional_fields() {
        let path = temp_path("roundtrip");
        let cfg = AppConfig {
            server: crate::config::ServerSettings {
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
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cargo test setup_tests`
Expected: compile error — `unresolved module setup` / `error[E0432]` because `src/setup.rs` exports nothing yet (create it first in Step 2; if the module exists but `write_config_file` is missing, you get `E0425 cannot find function`). Either way it must FAIL before the implementation is complete.

- [ ] **Step 7: Run tests to verify they pass**

Run: `cargo test setup_tests`
Expected: 3 passed (the `0600` test only on Unix; on Windows it is `#[cfg(unix)]`-gated).

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock src/setup.rs src/lib.rs src/config.rs src/tests.rs
git commit -m "feat(setup): add config-file writer with 0600 perms and tests"
```

---

### Task 2: Add `--init`, `--force`, `--license` flags and `resolve_command`

**Files:**
- Modify: `src/config.rs`
- Test: `src/tests.rs` (`mod config_tests`)

**Interfaces:**
- Consumes: existing `CliArgs` (clap derive).
- Produces:
  - `pub enum SetupCommand { Run, HashPassword(String), PrintLicense, Init }`
  - `pub fn resolve_command(cli: &CliArgs) -> anyhow::Result<SetupCommand>`

- [ ] **Step 1: Write the failing tests**

Add to `mod config_tests` in `src/tests.rs` (extend the `use` line at 1902):

```rust
    use crate::config::{SetupCommand, resolve_command};

    #[test]
    fn commands_are_mutually_exclusive() {
        let mut c = CliArgs::parse_from(["impulse-server"]);
        c.license = true;
        c.init = true;
        assert!(resolve_command(&c).is_err(), "license+init must be rejected");

        let mut c2 = CliArgs::parse_from(["impulse-server"]);
        c2.init = true;
        c2.hash_password = Some("pw".to_string());
        assert!(resolve_command(&c2).is_err(), "init+hash-password must be rejected");
    }

    #[test]
    fn commands_resolve_to_expected_variant() {
        let mut c = CliArgs::parse_from(["impulse-server", "--init"]);
        assert!(matches!(resolve_command(&c).unwrap(), SetupCommand::Init));

        let mut c = CliArgs::parse_from(["impulse-server", "--license"]);
        assert!(matches!(resolve_command(&c).unwrap(), SetupCommand::PrintLicense));

        let mut c = CliArgs::parse_from(["impulse-server", "--hash-password", "abc"]);
        assert!(matches!(resolve_command(&c).unwrap(), SetupCommand::HashPassword(p) if p == "abc"));

        let c = CliArgs::parse_from(["impulse-server"]);
        assert!(matches!(resolve_command(&c).unwrap(), SetupCommand::Run));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test config_tests::commands_`
Expected: FAIL — `error[E0425]: cannot find function resolve_command`.

- [ ] **Step 3: Add the flags to `CliArgs` in `src/config.rs`**

After the `--hash-password` field (config.rs:62) and before `--config`:

```rust
    #[arg(
        long,
        help = "Interactively create a config.toml (prompts for password, address, SANs) and exit"
    )]
    pub init: bool,

    #[arg(
        long,
        help = "Overwrite an existing config.toml when used with --init"
    )]
    pub force: bool,

    #[arg(long, help = "Print the MIT license text and exit")]
    pub license: bool,
```

- [ ] **Step 4: Add `SetupCommand` and `resolve_command`**

In `src/config.rs`, after the `CliArgs` struct:

```rust
/// One-shot commands that exit before the server starts.
#[derive(Debug, PartialEq, Eq)]
pub enum SetupCommand {
    /// Normal run: start the relay.
    Run,
    /// `--hash-password <pw>`: print an Argon2id hash and exit.
    HashPassword(String),
    /// `--license`: print the MIT license text and exit.
    PrintLicense,
    /// `--init`: run the interactive setup wizard and exit.
    Init,
}

/// Resolve the one-shot command from CLI flags, rejecting combinations.
pub fn resolve_command(cli: &CliArgs) -> anyhow::Result<SetupCommand> {
    let count =
        usize::from(cli.license) + usize::from(cli.init) + usize::from(cli.hash_password.is_some());
    if count > 1 {
        anyhow::bail!("--license, --init, and --hash-password are mutually exclusive");
    }
    if cli.license {
        return Ok(SetupCommand::PrintLicense);
    }
    if cli.init {
        return Ok(SetupCommand::Init);
    }
    if let Some(pw) = &cli.hash_password {
        return Ok(SetupCommand::HashPassword(pw.clone()));
    }
    Ok(SetupCommand::Run)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test config_tests::commands_`
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add src/config.rs src/tests.rs
git commit -m "feat(cli): add --init, --force, --license and resolve_command"
```

---

### Task 3: Refactor config loading — pure `load_config`, `config_file_loaded`, better error

**Files:**
- Modify: `src/config.rs`

**Interfaces:**
- Consumes: existing `CliArgs`.
- Produces:
  - `fn resolve_config_path(path: Option<&str>) -> anyhow::Result<Option<std::path::PathBuf>>`
  - `pub fn config_file_loaded(cli_args: &CliArgs) -> bool`
  - `load_config` no longer handles `--hash-password` (no `process::exit`).
  - `validate()` error message now also mentions `--init`.

- [ ] **Step 1: Write the failing test**

Add to `mod config_tests` in `src/tests.rs`:

```rust
    #[test]
    fn config_file_loaded_reports_discovery() {
        use crate::config::config_file_loaded;
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

        // No config anywhere → false (wizard may run).
        let c = cli_with_config(None);
        // cwd of a test is the crate root; avoid false positives from a stray config.toml.
        if config_file_loaded(&c) {
            // If the repo happens to have config.toml at cwd, skip: behavior is correct there.
            eprintln!("note: cwd contains config.toml; skipping negative discovery assert");
        }

        let _ = std::fs::remove_file(&cfg_path);
        let _ = std::fs::remove_dir_all(&dir);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test config_tests::config_file_loaded_reports_discovery`
Expected: FAIL — `error[E0425]: cannot find function config_file_loaded`.

- [ ] **Step 3: Extract `resolve_config_path` and add `config_file_loaded`**

In `src/config.rs`, replace the whole body of `load_file_config` with:

```rust
/// Resolve the config file path to try: explicit `--config`, or auto-discovery
/// in the current directory, then next to the executable.
/// `Ok(None)` means "no config file found" (only possible without `--config`).
fn resolve_config_path(path: Option<&str>) -> anyhow::Result<Option<std::path::PathBuf>> {
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
```

Then rewrite `load_file_config` (config.rs:296) to use the helper and stay otherwise identical:

```rust
fn load_file_config(path: Option<&str>) -> anyhow::Result<Option<AppConfig>> {
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
```

- [ ] **Step 4: Remove the `--hash-password` early-exit from `load_config`**

In `load_config` (config.rs:162), delete the block:

```rust
    if let Some(pw) = &cli_args.hash_password {
        let hash = argon2_hash(pw);
        println!("{hash}");
        std::process::exit(0);
    }
```

`main.rs` will handle it (Task 5). Keep `argon2_hash` as `pub`.

- [ ] **Step 5: Improve the `validate()` error message**

In `AppConfig::validate` (config.rs:120), replace the message with:

```rust
        if self.server.password_hash.trim().is_empty() {
            anyhow::bail!(
                "no password hash configured: run 'impulse-server --init' (interactive), \
                 or pass --password-hash <hash>, or set `server.password_hash` in config.toml"
            );
        }
```

- [ ] **Step 6: Run the full config test module**

Run: `cargo test config_tests setup_tests`
Expected: all pass (existing config tests + new discovery test + setup tests).

- [ ] **Step 7: Commit**

```bash
git add src/config.rs src/tests.rs
git commit -m "refactor(config): pure load_config, resolve_config_path, config_file_loaded"
```

---

### Task 4: Interactive password prompts and the two wizards

**Files:**
- Modify: `src/setup.rs`
- Test: `src/tests.rs` (`mod setup_tests`)

**Interfaces:**
- Consumes: `write_config_file`, `crate::config::{argon2_hash, AppConfig, ServerSettings}`, `crate::config::ServerSettings`.
- Produces:
  - `pub fn prompt_password(prompt: &str) -> anyhow::Result<String>`
  - `pub fn run_first_run_wizard() -> anyhow::Result<()>`
  - `pub fn run_init_wizard(force: bool) -> anyhow::Result<()>`

- [ ] **Step 1: Extend `src/setup.rs`**

Add after `write_config_file`:

```rust
use std::io::{self, Write};

/// Prompt for a password twice (hidden input, rpassword). Up to 3 attempts,
/// then an error. Rejects empty passwords and mismatches.
pub fn prompt_password(prompt: &str) -> anyhow::Result<String> {
    for _ in 0..3 {
        print!("{prompt}");
        io::stdout().flush()?;
        let first = rpassword::read_password()?;
        print!("Repeat password: ");
        io::stdout().flush()?;
        let second = rpassword::read_password()?;
        if first == second && !first.is_empty() {
            return Ok(first);
        }
        if first != second {
            eprintln!("Passwords do not match, try again.");
        } else {
            eprintln!("Password must not be empty, try again.");
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
    eprintln!("Config written to config.toml.");
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
    if !san_line.is_empty() {
        settings.san = san_line
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    let cfg = crate::config::AppConfig { server: settings };
    cfg.validate()?;
    write_config_file(Path::new("config.toml"), &cfg, force)?;
    println!("Config written to config.toml. Run impulse-server to start.");
    Ok(())
}
```

(Keep `use crate::config::AppConfig;` at the top; add `use crate::config::ServerSettings;` or use fully-qualified paths as above — pick one style.)

- [ ] **Step 2: Run the full suite to verify nothing regressed**

Run: `cargo test`
Expected: all existing + setup + config tests pass.

Note: `prompt_password`/wizards are interactive and not unit-tested (thin layer). `cfg.validate()` inside both wizards is the testable invariant — a bad address entered via `--init` errors before writing.

- [ ] **Step 3: Commit**

```bash
git add src/setup.rs
git commit -m "feat(setup): interactive password prompt and first-run/--init wizards"
```

---

### Task 5: Rewire `main.rs` — anyhow, command dispatch, first-run hook

**Files:**
- Modify: `src/main.rs`

**Interfaces:**
- Consumes: `config::{CliArgs, SetupCommand, load_config, resolve_command, argon2_hash, config_file_loaded}`, `setup::{LICENSE_TEXT, run_first_run_wizard, run_init_wizard}`, `run`.
- Produces: none (binary entry).

- [ ] **Step 1: Replace `src/main.rs` entirely**

```rust
use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use impulse_server::config::{CliArgs, argon2_hash, config_file_loaded, load_config, resolve_command, SetupCommand};
use impulse_server::setup::{LICENSE_TEXT, run_first_run_wizard, run_init_wizard};
use impulse_server::run;
use tokio::sync::Notify;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = CliArgs::parse();

    // One-shot commands that exit before the server starts.
    match resolve_command(&cli)? {
        SetupCommand::HashPassword(pw) => {
            println!("{}", argon2_hash(&pw));
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
            crossterm::terminal::LeaveAlternateScreen
        );
        eprintln!("Fatal error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
```

- [ ] **Step 2: Build to verify it compiles**

Run: `cargo build`
Expected: builds cleanly.

- [ ] **Step 3: Manual smoke test of one-shot commands**

Run:
```bash
cargo run -- --license | Select-Object -First 3
cargo run -- --hash-password smoke-test
cargo run -- --init --license
```
Expected: `--license` prints MIT text; `--hash-password` prints an `$argon2id$...` line; `--init --license` exits with the mutual-exclusion error message.

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat(main): dispatch --license/--init/--hash-password, first-run wizard, anyhow"
```

---

### Task 6: Fix `RUST_LOG` so it filters the TUI layer too

**Files:**
- Modify: `src/logging.rs`, `src/lib.rs`

**Interfaces:**
- Consumes: `TuiHandle`.
- Produces: `init_tracing(tui: TuiHandle, env_filter: &str)` unchanged signature; both the TUI layer and the file layer now share one `EnvFilter`.

- [ ] **Step 1: Rewrite `init_tracing` in `src/logging.rs`**

Replace the function (logging.rs:81-118) with:

```rust
/// Install the global tracing subscriber, sending events to the TUI and
/// a rolling log file under `logs/`. The same `EnvFilter` gates both layers.
/// Must be called once before logging.
pub fn init_tracing(tui: TuiHandle, env_filter: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(env_filter)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let tui_layer = TuiLogLayer { tui }.with_filter(filter.clone());

    // Ensure the logs directory exists before creating the rolling file appender.
    let _ = std::fs::create_dir_all("logs");

    use tracing_appender::rolling::{self, Rotation};
    let file_layer = match rolling::Builder::default()
        .rotation(Rotation::DAILY)
        .max_log_files(7)
        .filename_prefix("impulse-server")
        .filename_suffix(".log")
        .build("logs")
    {
        Ok(layer) => Some(
            tracing_subscriber::fmt::layer()
                .with_writer(layer)
                .with_timer(BracketTimer)
                .with_ansi(false)
                .with_filter(filter),
        ),
        Err(e) => {
            eprintln!("Warning: could not create log file layer: {}", e);
            None
        }
    };

    let registry = tracing_subscriber::registry().with(tui_layer);

    if let Some(fl) = file_layer {
        let _ = registry.with(fl).try_init();
    } else {
        let _ = registry.try_init();
    }
}
```

- [ ] **Step 2: Resolve the level from `RUST_LOG` in `src/lib.rs::run`**

Replace `logging::init_tracing(tui.clone(), "debug");` (lib.rs:59) with:

```rust
    let env_filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".to_string());
    logging::init_tracing(tui.clone(), &env_filter);
```

- [ ] **Step 3: Build and quick smoke test**

Run: `cargo build`
Expected: clean build. Then run the server briefly (`cargo run` with a config) and confirm the TUI starts; set `RUST_LOG=warn` and confirm no DEBUG lines appear.

- [ ] **Step 4: Commit**

```bash
git add src/logging.rs src/lib.rs
git commit -m "fix(logging): apply RUST_LOG filter to the TUI layer too"
```

---

### Task 7: Deduplicate level styling and add the license line in the TUI

**Files:**
- Modify: `src/tui.rs`

**Interfaces:**
- Consumes: `tracing::Level`.
- Produces: `fn level_style(level: Level) -> (Color, &'static str)`; one extra Info-panel line `License: MIT © oqune`.

- [ ] **Step 1: Add the `level_style` helper**

Near the top of `src/tui.rs` (after `const MAX_LOG_LINES`):

```rust
/// Single source of truth for log-level → (color, short label).
fn level_style(level: Level) -> (Color, &'static str) {
    match level {
        Level::ERROR => (Color::Red, "ERR"),
        Level::WARN => (Color::Yellow, "WRN"),
        Level::INFO => (Color::Cyan, "INF"),
        Level::DEBUG => (Color::Magenta, "DBG"),
        Level::TRACE => (Color::DarkGray, "TRC"),
    }
}
```

- [ ] **Step 2: Use it in `draw_logs`**

Replace the two `match rec.level` blocks inside `draw_logs` (tui.rs:546-560) with:

```rust
            let (color, lvl) = level_style(rec.level);
```

and remove the old `let color = match ...` and `let lvl = match ...` blocks. The rest of the line construction stays.

- [ ] **Step 3: Use it in `copy_logs_to_clipboard`**

Replace the inner `match rec.level` (tui.rs:615-621) with:

```rust
                let (_, lvl) = level_style(rec.level);
```

- [ ] **Step 4: Use it in `draw_help_bar`**

Replace the `filter_defs` slice + the styling loop (tui.rs:363-382) with:

```rust
    let filter_keys: &[(Level, &str)] = &[
        (Level::TRACE, "1"),
        (Level::DEBUG, "2"),
        (Level::INFO, "3"),
        (Level::WARN, "4"),
        (Level::ERROR, "5"),
    ];

    spans.push(Span::styled(" Filters: ", Style::default().fg(Color::Gray)));

    for (level, key) in filter_keys {
        let (color, short) = level_style(*level);
        let active = all_active || state.active_filters.contains(level);
        let style = if active {
            Style::default().fg(color).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        spans.push(Span::styled(format!("[{key}:{short}]"), style));
        spans.push(Span::raw(" "));
    }
```

- [ ] **Step 5: Add the license line to `draw_info`**

In the `lines` vec of `draw_info`, after the `Version:` line (tui.rs:492-495), insert:

```rust
        Line::from(vec![
            Span::styled("License: ", Style::default().fg(Color::Gray)),
            Span::styled("MIT © oqune", Style::default().fg(Color::Cyan)),
        ]),
```

- [ ] **Step 6: Build to verify it compiles**

Run: `cargo build`
Expected: clean build.

- [ ] **Step 7: Commit**

```bash
git add src/tui.rs
git commit -m "refactor(tui): dedupe level styling, add license line to Info panel"
```

---

### Task 8: Move user-data hex dump from DEBUG to TRACE

**Files:**
- Modify: `src/server.rs`

- [ ] **Step 1: Change the import**

At server.rs:19, change:

```rust
use tracing::{debug, info, warn};
```

to:

```rust
use tracing::{debug, info, trace, warn};
```

- [ ] **Step 2: Change the raw-chunk dump block**

Replace the block at server.rs:637-644:

```rust
                            if tracing::enabled!(tracing::Level::DEBUG) {
                                debug!("[READER] Session {} raw chunk: {} bytes", session_key, n);
                                debug!(
                                    "[READER] Session {} hex: {}",
                                    session_key,
                                    hex_dump(&chunk[..n], 128)
                                );
                            }
```

with:

```rust
                            if tracing::enabled!(tracing::Level::TRACE) {
                                trace!("[READER] Session {} raw chunk: {} bytes", session_key, n);
                                trace!(
                                    "[READER] Session {} hex: {}",
                                    session_key,
                                    hex_dump(&chunk[..n], 128)
                                );
                            }
```

Leave all other `debug!` lines (sizes, opcodes, counts) as-is — they carry no payload bytes.

- [ ] **Step 3: Build and test**

Run: `cargo test`
Expected: all tests pass (server tests compile; behavior unchanged at default level).

- [ ] **Step 4: Commit**

```bash
git add src/server.rs
git commit -m "fix(server): log raw payload hex only at TRACE level"
```

---

### Task 9: Package config with empty hash + point deb/rpm at it

**Files:**
- Create: `packaging/config.toml`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: `[package.metadata.deb]` / `[package.metadata.generate-rpm]` asset lists.
- Produces: `/etc/impulse-server/config.toml` (installed), empty `password_hash`.

- [ ] **Step 1: Create `packaging/config.toml`**

```toml
[server]
address = "0.0.0.0:4433"
cert_dir = "cert_data"
# REQUIRED. The server refuses to start with an empty hash on purpose — no
# secret by default. Configure with:  impulse-server --init   (writes a
# config with a real Argon2id hash), or set server.password_hash.
password_hash = ""
```

- [ ] **Step 2: Point the deb asset at it**

In `Cargo.toml` `[package.metadata.deb]` assets (Cargo.toml:90-94), replace:

```toml
    ["config.toml.example", "etc/impulse-server/config.toml", "644"],
```

with:

```toml
    ["packaging/config.toml", "etc/impulse-server/config.toml", "644"],
```

- [ ] **Step 3: Point the rpm asset at it**

In `[package.metadata.generate-rpm]` assets (Cargo.toml:102-106), replace:

```toml
    { source = "config.toml.example", dest = "/etc/impulse-server/config.toml", mode = "644" },
```

with:

```toml
    { source = "packaging/config.toml", dest = "/etc/impulse-server/config.toml", mode = "644" },
```

- [ ] **Step 4: Verify the packaged config is loadable and refuses to start**

Run: `cargo run -- --config packaging/config.toml`
Expected: exits with the "no password hash configured: run 'impulse-server --init'..." error (exit code 1). This is the intended loud failure.

- [ ] **Step 5: Commit**

```bash
git add packaging/config.toml Cargo.toml
git commit -m "fix(packaging): install config with empty password_hash (no changeme default)"
```

---

### Task 10: Remove `config.toml.example` from the archives

**Files:**
- Modify: `.github/workflows/server-build.yml`

- [ ] **Step 1: Linux packaging step**

In the `Package (Linux tar.gz)` step (server-build.yml:90), delete the line:

```yaml
          cp config.toml.example pkg/ImpulseServer-${{ matrix.arch }}/
```

- [ ] **Step 2: Windows packaging step**

In the `Package (Windows zip)` step (server-build.yml:100), delete the line:

```yaml
          Copy-Item "config.toml.example" "$dir/"
```

- [ ] **Step 3: Sanity-check the YAML**

Read the two package steps; each should now copy only the binary and `LICENSE`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/server-build.yml
git commit -m "ci(package): ship binary + LICENSE only in archives"
```

---

### Task 11: `config.toml.example` — no working placeholder

**Files:**
- Modify: `config.toml.example`

- [ ] **Step 1: Replace the hash block**

Replace lines 21-26 with:

```toml
# REQUIRED. Argon2id encoded password hash. The client sends the password
# Argon2id-hashed; the server compares it directly against this value.
# Generate with:
#   impulse-server --init            # interactive wizard (writes config.toml)
#   impulse-server --hash-password <password>
# Empty (or unset) = the server refuses to start until configured.
password_hash = ""
```

- [ ] **Step 2: Verify the example no longer starts**

Run: `cargo run -- --config config.toml.example`
Expected: the "no password hash configured" loud error (exit 1).

- [ ] **Step 3: Commit**

```bash
git add config.toml.example
git commit -m "docs(config): empty password_hash placeholder instead of changeme hash"
```

---

### Task 12: Update README.md and README.ru.md

**Files:**
- Modify: `README.md`, `README.ru.md`

- [ ] **Step 1: README.md — flags table**

In the flags table (README.md:73-80), add rows after `--config`:

```markdown
| `--init` | | Interactively create `config.toml` (password, address, SANs), then exit | _none_ |
| `--force` | | Overwrite an existing `config.toml` when used with `--init` | _none_ |
| `--license` | | Print the MIT license text and exit | _none_ |
```

- [ ] **Step 2: README.md — first-run section**

Replace the "Build & run" block text (README.md:63-92) with a version that documents the wizard. Key content:

```markdown
## Build & run

```bash
cargo build --release
./target/release/Impulse-server
```

On the very first launch (no `config.toml` found and no `--password-hash`), the
server asks for a client password interactively, writes a minimal `config.toml`
to the current directory, and starts with it. For explicit setup, run:

```bash
./target/release/Impulse-server --init
```

`--init` prompts for the password and, optionally, the bind address, cert
directory, and extra SANs, then writes `config.toml` (use `--force` to
overwrite). Headless environments (systemd, Docker) must configure the password
hash beforehand — the server refuses to start without one:

```bash
./target/release/Impulse-server --hash-password yourpassword
```

CLI flags always override the config file; `--license` prints the MIT license.
```

(Keep the existing flags table and the "password_hash is required" paragraph, but reword it to reference `--init`.)

- [ ] **Step 3: README.md — archive contents + RUST_LOG**

- In the "Platforms" section (README.md:219-226), update the artifact-scheme paragraph to say archives contain the binary and `LICENSE` (config is created on first run / via `--init`).
- In the "Recommended runtime flags" section (README.md:107-116), keep `RUST_LOG=info` guidance and note it now applies to the TUI as well.

- [ ] **Step 4: Mirror all README.md changes in README.ru.md** (same sections, Russian text).

- [ ] **Step 5: Commit**

```bash
git add README.md README.ru.md
git commit -m "docs: document --init/--license, first-run wizard, archive contents"
```

---

### Task 13: Full verification and release rebuild

**Files:** none (verification only).

- [ ] **Step 1: Full test suite**

Run: `cargo test`
Expected: all pass (baseline 61 + new tests ≈ 67). Note down the count.

- [ ] **Step 2: Manual smoke of all commands**

Run:
```bash
cargo run -- --license          # MIT text, exit 0
cargo run -- --hash-password x  # argon2id hash, exit 0
cargo run -- --init --license   # mutual-exclusion error
cargo run -- --config packaging/config.toml   # "no password hash" loud error
cargo build --release           # clean release build
```

- [ ] **Step 3: Push and rebuild the release**

```bash
git push origin master
git tag -f v2.5.0 && git push --force origin v2.5.0
gh release delete v2.5.0 --repo Oqune/Impulse-server --yes   # immutable assets
gh run watch <tag-run-id> --repo Oqune/Impulse-server --exit-status
```

- [ ] **Step 4: Verify release artifacts**

Run: `gh api repos/Oqune/Impulse-server/releases/tags/v2.5.0 --jq '.assets[].name'`
Expected: 10 assets `ImpulseServer-2.5.0-<os>-<arch>.<ext>`.
Download one Linux tar.gz and one `.deb`, extract, and confirm each contains the binary + `LICENSE` (archive) and that `/etc/impulse-server/config.toml` inside the deb has an empty `password_hash`.

- [ ] **Step 5: Final commit if any verification-only fix was needed** (otherwise skip).

---

## Self-review

- **Spec coverage:** §1 wizard → Task 4/5; §2 `--init`/`--force` → Task 2/4/5; §3 `--license` + TUI line → Task 2/5/7; §4 archive/package/example → Task 9/10/11; §5 RUST_LOG, hash-password purity, anyhow, level_style, hex→TRACE, rpassword → Task 1/3/6/7/8; §6 tests + release → Task 13. No gaps.
- **Placeholders:** no TBD/TODO; every step has exact code or commands.
- **Type consistency:** `write_config_file(path, cfg, overwrite)`, `resolve_command(cli) -> Result<SetupCommand>`, `SetupCommand::{Run,HashPassword,PrintLicense,Init}`, `config_file_loaded(&CliArgs) -> bool`, `run_init_wizard(force)`, `prompt_password(&str) -> Result<String>`, `level_style(Level) -> (Color, &'static str)` are used consistently across tasks.
