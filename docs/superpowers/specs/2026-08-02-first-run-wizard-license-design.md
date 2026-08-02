# Design: First-run wizard, license credits, archive cleanup

Date: 2026-08-02
Status: Approved (sections 1–5)
Scope: single implementation plan

## Problem

1. First launch without a configured `password_hash` is a dead end: the server
   fails loudly, but the only remedy is a two-step copy-paste dance
   (`--hash-password <pw>` prints a hash, which must then be pasted into a
   config file or `--password-hash`). There is no config generation and no
   interactive onboarding.
2. The shipped `config.toml.example` contains a **real Argon2id hash of
   `changeme`**, and the `.deb`/`.rpm` packages install it verbatim at
   `/etc/impulse-server/config.toml`. A fresh systemd install therefore runs
   with password `changeme` until the admin notices.
3. The archive is `binary + LICENSE + config.toml.example`; the example file
   is reference material that adds noise. (LICENSE must stay — MIT requires the
   copyright + permission notice to ship with the software.)
4. Minor bugs / code smells discovered during review: `RUST_LOG` does not
   affect the TUI log layer (only the file layer); raw message chunks are hex-
   dumped at DEBUG into the visible log; `--hash-password` performs
   `process::exit` from inside the config loader; `main.rs` uses
   `Box<dyn Error>` while the rest uses `anyhow`.

## Goals

- One-command onboarding for interactive users: first run without config asks
  for a password, writes a minimal `config.toml`, and starts immediately.
- A dedicated `--init` wizard for explicit setup (including under systemd,
  where the first-run prompt cannot run because stdin is not a TTY).
- License "credits": keep `LICENSE` in archives, add `--license` flag and a
  license line in the TUI Info panel.
- No secret-by-default: remove the `changeme` placeholder from everything
  shipped; packaged config has an empty `password_hash` so first start fails
  loudly.
- Include the low-risk bug fixes and cleanups listed in section 5.

## Non-goals (potential follow-up plan)

- Splitting `src/server.rs` (1244 lines) into `auth.rs` / `session.rs` /
  `handshake.rs`.
- Moving hardcoded limits (`MAX_*`, message TTL, max payload) into config.
- Making the logs directory configurable (`logs` is hardcoded in 3 places).

---

## 1. Interactive first-run wizard (A)

Triggers when: no config file is found (neither `--config`, nor `config.toml`
in cwd, nor next to the exe), **and** no `--password-hash` flag given, **and**
stdin is a TTY.

Flow:

1. Prompt `Enter client password:` — hidden input via `rpassword`, then
   `Repeat password:` confirmation.
   - Mismatch → re-ask (up to 3 attempts, then abort with a clear error).
   - Empty password → reject with a message.
2. Generate Argon2id hash (reuse `config::argon2_hash`).
3. Write a minimal `config.toml` to the current directory:

   ```toml
   [server]
   address = "0.0.0.0:4433"
   cert_dir = "cert_data"
   password_hash = "$argon2id$..."
   ```

   - Written with mode `0600` on Unix.
   - Serialization: always emit `address`, `cert_dir`, `password_hash`;
     emit `address6` / `san` only when non-empty (e.g. set via `--init`).
4. The server continues and starts with the in-memory config (no restart).
   Log: `Config written to config.toml`.

Non-TTY (systemd / daemon, no config and no hash): loud error, e.g.
`no password hash configured: run 'impulse-server --init' (interactive), or
set server.password_hash in config.toml, or pass --password-hash <hash>`.
Never a silent default.

Edge: if writing the config file fails (read-only cwd), abort with the write
error; do not start.

## 2. `--init` command (B)

`impulse-server --init` is an interactive setup command; the server does NOT
start. Behavior:

1. Prompt password (hidden + confirm) as in section 1.
2. Optionally prompt for address / port / extra SANs; `Enter` accepts the
   defaults (`0.0.0.0:4433`, `cert_data`, none).
3. Write the same minimal `config.toml` (0600) to the current directory.
   Print `Config written to config.toml. Run impulse-server to start.`
   Exit 0.
   - For the systemd path: run `--init` from `/etc/impulse-server`
     (`cd /etc/impulse-server && impulse-server --init`), which matches the
     unit's `WorkingDirectory` so the file is auto-discovered on start.
4. If `config.toml` already exists: refuse (`already exists`) unless
   `--force` is given, in which case overwrite.

## 3. License and credits

- `LICENSE` stays in every archive (tar.gz / zip / deb / rpm as today).
- New flag `--license`: print the full MIT text to stdout, exit 0.
- TUI Info panel gains a line: `License: MIT © oqune`.
- `--init`, `--license`, `--hash-password` are mutually exclusive commands:
  if any one is present, the server does not start. Passing more than one is
  an error.

## 4. Archive and package contents

- **tar.gz / zip**: remove `config.toml.example`. Archive becomes
  `ImpulseServer-<arch>/` containing only the binary and `LICENSE`.
- **deb / rpm**: keep installing a config at `/etc/impulse-server/config.toml`
  and the systemd unit (already `WorkingDirectory=/etc/impulse-server`), but
  the packaged config now has `password_hash = ""` (no `changeme`). First
  `systemctl start` fails loudly; the admin runs `impulse-server --init`
  (which writes a new config) and restarts.
  - The packaged config is a new file, e.g. `packaging/config.toml`,
    referenced from `[package.metadata.deb]` / `[package.metadata.generate-rpm]`
    assets instead of `config.toml.example`.
- **Repo `config.toml.example`**: replace the `changeme` hash with
  `password_hash = ""` and a comment: generate with `--init` or
  `--hash-password`. It no longer ships in archives.

## 5. Bug fixes and cleanup (in scope)

- **RUST_LOG affects the TUI too**: apply `EnvFilter` to `TuiLogLayer` as well
  as the file layer. Level resolution: `RUST_LOG` env var, falling back to
  `debug` (same default as today, so no behavior regression). Document in
  README that `RUST_LOG=info` (or `warn`) trims TUI log output.
  Removes the hardcoded `"debug"` argument in `lib.rs::run`.
- **`--hash-password`**: move out of `config::load_config` (remove the
  `process::exit` side effect); handle it in `main` before config loading.
  `load_config` becomes pure.
- **`main.rs`**: switch error type to `anyhow::Result`.
- **`tui.rs`**: extract the level → (color, label) mapping into one helper
  (currently duplicated 3×); add the license line to `draw_info`.
- **Raw chunk hex-dump**: lower the DEBUG hex dumps of message payloads to
  TRACE so user data does not appear in default logs.
- New dependency: `rpassword` (hidden input). Nothing else.

## 6. Testing

- Unit tests for the minimal-config writer: writes to a temp dir, TOML
  round-trips, only non-default fields serialized, mode 0600 on Unix.
- CLI tests: `--init` / `--license` / `--hash-password` are mutually
  exclusive; `--license` exits 0 and prints text.
- Interactive prompt layer stays thin and untested.
- Full suite: `cargo test` (currently 61 passing).
- After implementation: rebuild the release (tag push) and verify archive
  contents (binary + LICENSE only) and package config (empty hash).

## Files touched

- Modify: `src/config.rs` (add `--init`, `--license`; pure `load_config`),
  `src/main.rs` (anyhow, command dispatch), `src/lib.rs` (log level),
  `src/logging.rs` (TUI filter), `src/tui.rs` (level helper, license line),
  `src/server.rs` (hex dump → TRACE), `Cargo.toml` (rpassword; deb/rpm asset
  source), `config.toml.example`, `.github/workflows/server-build.yml`
  (archive contents), `packaging/` (new `config.toml`),
  `README.md`, `README.ru.md`.
- Add: `src/setup.rs` (first-run prompt + config writer + `--init` wizard),
  `packaging/config.toml`, `docs/superpowers/specs/` (this doc).
- Tests in `src/tests.rs`.
