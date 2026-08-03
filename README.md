<div align="center">

[🇺🇸 **English**](README.md) | [🇷🇺 Русский](README.ru.md)

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.85%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebTransport](https://img.shields.io/badge/Transport-WebTransport%20%2F%20QUIC-green)](https://w3c.github.io/webtransport/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Oqune/Impulse-server/actions/workflows/server-build.yml/badge.svg)](https://github.com/Oqune/Impulse-server/actions/workflows/server-build.yml)
[![Release](https://img.shields.io/github/v/release/Oqune/Impulse-server?label=latest)](https://github.com/Oqune/Impulse-server/releases)

Secure, **ephemeral** messenger server over **WebTransport (QUIC)** with
**TOFU** trust-on-first-use and password authentication.

> **Client:** [Oqune/Impulse-client](https://github.com/Oqune/Impulse-client) —
> Android post-quantum E2EE chat client for this server.

</div>

## Overview

Impulse is a relay server for an end-to-end-encrypted messenger. The server
**never sees plaintext** — clients encrypt message payloads locally using
Per-Recipient KEM Wrapping (ML-KEM-768 + AES-256-GCM) and only hand the server
opaque bytes, a sequence id, a timestamp, and per-message public keys. The server
stores messages in RAM (TTL 72h), assigns monotonic ids, and broadcasts them to
all connected clients.

Key design points:

- **Transport:** WebTransport over QUIC only (`wtransport` 0.7). TLS 1.3 is
  mandatory; the old WSS transport was removed.
- **Binary protocol:** length-prefixed binary frames with opcodes `0x01`–`0x0C`
  (little-endian), not JSON.
- **Auth:** server sends `AuthChallenge` (0x0B) with a 16-byte nonce and
  Argon2id salt; client derives a key, computes HMAC-SHA-256, and responds
  with `Auth` (0x01). Server verifies in constant time against a stored
  Argon2id hash.
- **TLS / Certificates:** self-signed **ECDSA P-256** certificates, valid **14 days**,
  rotated automatically with a **2-day overlap** window. The PEM material is
  persisted under `cert_dir` (resolved relative to the executable, `0600` on
  Unix, restricted DACL on Windows).
- **TOFU:** the server renders a QR code containing `impulse-cert:<sha256>`
  (the SHA-256 fingerprint of the DER certificate). Clients scan it, pin
  `serverCertificateHashes`, and trust the server on first use. On rotation
  the new fingerprint is broadcast via `NewCertHash` (0x07).
- **Storage:** in-RAM ring buffer, messages expire after 72h (`TTL`), bounded by
  count (`10_000`) and per-payload size (`1 MB`).
- **Relay:** broadcast to all active sessions; late joiners catch up via
  `Sync { last_seen_id }`. A single `Sync` returns at most `2000` messages.
- **Admin:** a **TUI** with a responsive three-column layout:
  - **Left column** (Info + QR + Certificate): server bind address, transport
    (`WebTransport/QUIC TLS1.3 (h3)`), crate version, SAN count, live
    `sessions / MAX_SESSIONS`, stored message count, message TTL, max payload
    size, certificate SHA-256 fingerprint (short), cert expiry countdown, a
    ⚠ rotating indicator during key overlap, and a scannable QR code.
  - **Middle column** (Users on top, Sessions below): every user ever seen —
    `U{n}` alias, first 8 hex of the client public-key fingerprint, ● online /
    ○ offline, live total online time and messages sent — plus the live session
    table, each row tagged with its bound user alias.
  - **Right column** (Logs, widest): live server log stream with level filters
    `1`–`5` (ERR/WRN/INF/DBG/TRC), scroll (`↑↓`/`PgUp`/`PgDn`/`Home`/`End` or
    mouse wheel), search (`/`), `Space` to pause, and `Shift+C` to copy all logs
    to clipboard. `Tab` cycles the left column (full → QR-only → hidden); `f`
    focuses the QR code. Below ~125 columns the middle column folds into the
    right (Users + Sessions + Logs); below ~90 columns only the logs remain.
    The status bar shows live throughput, uptime, active filters and hints.
  `Ctrl+C` / `q` quits and shuts down gracefully.

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

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--host` | | Bind host (overrides `server.address` in the config file) | from config / `0.0.0.0` |
| `--port` | `-p` | WebTransport (QUIC) listen port (overrides the port in the config file) | from config / `4433` |
| `--cert-dir` | | Directory for the generated certificate/key | `cert_data` |
| `--san` | | Extra SAN (DNS name or IP) for the self-signed cert (repeatable) | _none_ |
| `--password-hash` | | Argon2id encoded hash of the client password (required) | _none_ |
| `--config` | | Path to a TOML config file; auto-discovered as `config.toml` in the working directory, then next to the executable | auto-discover |
| `--init` | | Interactively create `config.toml` (password, address, SANs), then exit | _none_ |
| `--force` | | Overwrite an existing `config.toml` when used with `--init` | _none_ |
| `--license` | | Print the MIT license text and exit | _none_ |

`password_hash` is **required** — there is no insecure default. Configure it
with `--init` (interactive), `--password-hash <hash>`, or `server.password_hash`
in `config.toml`.

## Production deployment

### Requirements

- **Rust 1.85+** (edition 2024) to build from source.
- A **UDP-reachable** port (QUIC runs over UDP). Open/forward the configured
  port in firewalls / security groups.
- On **Unix**, the private key file is written with `0600` permissions
  automatically; on Windows the ACL is restricted to the current user via `icacls`.
- **Root/administrator is NOT required** — bind to a high port (e.g. `4433`)
  instead of `443`. The QR/TOFU flow lets clients trust a self-signed cert,
  so no public CA is needed.

### Recommended runtime flags

For production, run with `RUST_LOG=info` or `RUST_LOG=warn` to avoid excessive
I/O from debug-level hex dumps (raw chunk data is logged at DEBUG level). The
`RUST_LOG` filter now applies to the TUI log stream as well:

```bash
RUST_LOG=info ./target/release/Impulse-server --config config.toml
```

The server writes rolling logs under `logs/` (daily rotation, 7-day retention).

### Systemd service (Linux)

Create `/etc/systemd/system/impulse-server.service`:

```ini
[Unit]
Description=Impulse Server
After=network.target

[Service]
Type=simple
User=impulse
WorkingDirectory=/opt/impulse-server
ExecStart=/opt/impulse-server/Impulse-server --config /opt/impulse-server/config.toml
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now impulse-server
```

### Docker

```dockerfile
FROM rust:1.85-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/Impulse-server /usr/local/bin/impulse-server
COPY config.toml /etc/impulse-server/config.toml
VOLUME /var/lib/impulse-server/cert_data /var/log/impulse-server
EXPOSE 4433/udp
ENV RUST_LOG=info
ENTRYPOINT ["impulse-server", "--config", "/etc/impulse-server/config.toml"]
```

```bash
docker build -t impulse-server .
docker run -d \
  --name impulse \
  --restart unless-stopped \
  -v cert_data:/var/lib/impulse-server/cert_data \
  -v impulse_logs:/var/log/impulse-server \
  -p 4433:4433/udp \
  impulse-server
```

### NixOS

```console
$ nix build github:Oqune/Impulse-server
$ ./result/bin/impulse-server --help
```

Or install into your profile:

```console
$ nix profile install github:Oqune/Impulse-server
```

### Firewall

QUIC uses UDP. Ensure the chosen port is allowed:

```bash
# ufw (Ubuntu/Debian)
sudo ufw allow 4433/udp

# firewalld (RHEL/CentOS/Fedora)
sudo firewall-cmd --add-port=4433/udp --permanent && sudo firewall-cmd --reload

# Windows PowerShell
New-NetFirewallRule -DisplayName "Impulse QUIC" -Direction Inbound -Protocol UDP -LocalPort 4433 -Action Allow
```

## Platforms

Impulse-server is written in portable Rust (edition 2024) and builds on the
targets below with a working Rust toolchain and UDP/QUIC networking. CI produces
release binaries and `.deb`/`.rpm` packages for Linux on x86-64 and ARM64, plus
release binaries for Linux ARMv7/RISC-V 64 and Windows on x86-64 and ARM64.

| Platform | Target triple | Status | Notes |
|----------|---------------|--------|-------|
| Linux (x86-64) | `x86_64-unknown-linux-gnu` | ✅ CI tested | Recommended for servers |
| Linux (ARM64) | `aarch64-unknown-linux-gnu` | ✅ CI tested (cross) | e.g. AWS Graviton, Raspberry Pi 4 (64-bit OS) |
| Linux (ARMv7) | `armv7-unknown-linux-gnueabihf` | ✅ CI tested (cross) | Raspberry Pi 2/3, 32-bit OS |
| Linux (RISC-V 64) | `riscv64gc-unknown-linux-gnu` | ✅ CI tested (cross) | e.g. VisionFive 2 |
| Windows (x86-64) | `x86_64-pc-windows-msvc` | ✅ CI tested | Console app; binds the UDP/QUIC port directly |
| Windows (ARM64) | `aarch64-pc-windows-msvc` | ✅ CI tested | Windows on ARM devices |
| FreeBSD / BSDs | `x86_64-unknown-freebsd` | ⚠️ Manual only | The `aws-lc-sys` crypto backend has no FreeBSD sysroot under cross-tools; a native FreeBSD toolchain is required |

Prebuilt binaries for every ✅ and ⚠️ row (except FreeBSD) are attached to each
GitHub Release; `.deb` and `.rpm` packages are built for Linux x86-64 and ARM64.
Release artifacts follow the unified naming scheme `ImpulseServer-<version>-<os>-<arch>.<ext>`
(e.g. `ImpulseServer-2.5.0-linux-amd64.tar.gz`, `ImpulseServer-2.5.0-windows-arm64.zip`,
`ImpulseServer-2.5.0-linux-arm64.deb`, `ImpulseServer-2.5.0-linux-arm64.rpm`).
The `.tar.gz`/`.zip` archives contain the binary and `LICENSE` only — the config
is created on first run or via `--init`.

### Requirements

- **Rust 1.85+** (edition 2024).
- A **UDP-reachable** port (QUIC runs over UDP). Open/forward the configured
  port in firewalls.
- On **Unix**, the private key file is written with `0600` permissions
  automatically; on Windows the DACL is restricted to the current user.
- **Root/administrator is NOT required** — bind to a high port (e.g. `4433`)
  instead of `443`. The QR/TOFU flow lets clients trust a self-signed cert,
  so no public CA is needed.

## Protocol (binary, little-endian)

All frames: `[opcode: u8][...fields]`. Length-prefixed blobs are `u32 len`
followed by `len` bytes.

| Opcode | Dir | Name | Fields |
|--------|-----|------|--------|
| `0x01` | C→S | Auth | `u32 LE pwd_len` + raw password bytes + 32 raw HMAC-SHA-256 bytes |
| `0x0B` | S→C | AuthChallenge | 16-byte nonce + `u32 LE salt_len` + B64 Argon2id salt |
| `0x02` | S→C | AuthResult | `u8` status (`0`=ok, `1`=fail) + optional `len`-prefixed message |
| `0x03` | C→S | Sync | `u64` last_seen_id |
| `0x04` | S→C | SyncResponse | `u32` count, then per message: `u64 id`, `u64 ts`, `len`-prefixed payload |
| `0x05` | C→S / S→C | Data | C→S: `len`-prefixed payload. S→C: `u64 id`, `u64 ts`, `len`-prefixed payload |
| `0x06` | both | Heartbeat | `u64` client_timestamp (echoed back) |
| `0x07` | S→C | NewCertHash | exactly 32 raw SHA-256 bytes + `u64` unix expiry |
| `0x08` | both | Disconnect | no payload (graceful close from either side) |
| `0x0B` | S→C | AuthChallenge | 16-byte nonce + `u32 LE salt_len` + B64 Argon2id salt |
| `0x0C` | C→S / S→C | KeyExchangeKemDsa | `len`-prefixed combined ML-KEM + ML-DSA-65 public keys (relayed atomically) |

Unknown/invalid opcodes from a client close the connection. Idle streams are
closed after 300s. Sessions are capped at 1024 with `AtomicU64` unique IDs;
aggregate buffer capacity is capped at 512 MB (`AtomicUsize`). Oversized
payloads (>1 MB) are dropped. A single `Sync` returns at most 2000 messages.
Key exchanges are cached per-session in a `DashMap` and replayed to newly
authenticated sessions. The wire parser validates declared packet length against
the same 1 MB payload limit before any allocation, preventing CPU-DoS via
inflated length prefixes (C1).

## Security

- Mandatory QUIC/TLS 1.3 transport (WebTransport).
- Short-lived ECDSA P-256 certificates (14d) with automatic rotation (2d overlap);
  PEM material persisted atomically. The new cert is applied to the **live** TLS
  resolver (no restart) and announced via `NewCertHash`.
- TOFU fingerprint pinning via QR code + `NewCertHash` control packet.
- Post-quantum hybrid TLS key exchange (X25519Kyber768) via `aws-lc-rs`.
- **Blind relay** — the server never decrypts message payloads. Clients encrypt
  locally using Per-Recipient KEM Wrapping (ML-KEM-768 + AES-256-GCM) and the
  server only sees opaque bytes.   `KeyExchangeKemDsa` (0x0C) opcodes relay combined ML-KEM and ML-DSA-65
  public keys atomically — the server stores nothing and inspects nothing.
- Ephemeral RAM-only storage, 72h TTL, bounded ring buffer and payload size.
- Passwords stored as Argon2id hashes; challenge-response auth with
  constant-time HMAC comparison.
- KeyExchange replay protection via per-session `DashMap` cache.
- Private key file restricted to `0600` on Unix; exclusive DACL on Windows.
- Per-IP rate limiting (10 connections / 10s window) and session caps to mitigate DoS.
- Idle sessions are closed after 300s to avoid leaking resources.
- No plaintext, passwords, or payloads are logged.

## Graceful shutdown

`Ctrl+C` / `SIGTERM` (or `q` in the TUI) triggers a graceful shutdown: the
endpoint stops accepting new sessions and active writers are drained. Logs are
written to `logs/` with daily rotation and 7-day retention.

## Project layout

```
src/
  cert/        — ECDSA P-256 cert generation, rotation, SHA-256 TOFU fingerprint, FS persist
  storage/     — ephemeral in-RAM message log (TTL 72h, sequence ids)
  protocol.rs  — binary wire frames; framing/limits live in protocol/
  relay/       — WebTransport endpoint, session handling, auth and broadcast relay
  ui/          — terminal UI: Server/Sessions panels, logs, TOFU QR and live stats
  logging/     — tracing → TUI / rolling file bridge
  config/      — CLI parsing and config.toml loading
  cli/         — first-run and --init wizards, config writer
  lib.rs       — wiring + run() entry point
  main.rs      — binary entry point
tests/         — integration tests (handshake, relay, config, storage)
```

## License

MIT — see [LICENSE](LICENSE).
