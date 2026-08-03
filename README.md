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
**never sees plaintext** — clients encrypt payloads locally (Per-Recipient KEM
Wrapping, ML-KEM-768 + AES-256-GCM) and hand the server only opaque bytes, a
sequence id, a timestamp, and per-message public keys. Messages live in RAM
(72h TTL), ids are monotonic, and broadcasts go to every connected client.

Key design points:

- **Transport:** WebTransport over QUIC only (`wtransport` 0.7), TLS 1.3 mandatory.
- **Protocol:** length-prefixed binary frames, opcodes `0x01`–`0x0C`, little-endian.
- **Auth:** `AuthChallenge` (0x0B) with a 16-byte nonce + Argon2id salt → client
  HMAC-SHA-256 response (`Auth`, 0x01) → constant-time verification.
- **TLS / Certificates:** self-signed **ECDSA P-256**, valid **14 days**, rotated
  automatically with a **2-day overlap**. PEM persisted with `0600` (Unix) /
  restricted DACL (Windows).
- **TOFU:** QR code with `impulse-cert:<sha256>`; clients pin
  `serverCertificateHashes`. Rotation is announced via `NewCertHash` (0x07).
- **Storage:** in-RAM ring buffer, 72h TTL, capped at `10_000` messages and `1 MB`
  per payload.
- **Relay:** broadcast + `Sync { last_seen_id }` catch-up (≤ 2000 msgs); key
  exchanges replayed to late joiners.
- **Admin:** responsive **three-column TUI** — Info/QR/Cert | Users + Sessions |
  Logs — with live user stats, log filters, search, and QR focus.

## Build & run

```bash
cargo build --release
./target/release/Impulse-server
```

On first launch (no `config.toml`, no `--password-hash`) the server asks for a
client password interactively, writes a minimal `config.toml`, and starts. For
explicit setup:

```bash
./target/release/Impulse-server --init
```

`--init` prompts for the password and optionally the bind address, cert
directory, and extra SANs, then writes `config.toml` (`--force` overwrites).
Headless environments (systemd, Docker) must configure the password hash first —
the server refuses to start without one:

```bash
./target/release/Impulse-server --hash-password yourpassword
```

CLI flags always override the config file; `--license` prints the MIT license.

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--host` | | Bind host (overrides `server.address`) | from config / `0.0.0.0` |
| `--port` | `-p` | WebTransport (QUIC) listen port | from config / `4433` |
| `--cert-dir` | | Directory for the generated certificate/key | `cert_data` |
| `--san` | | Extra SAN (DNS name or IP) for the self-signed cert (repeatable) | _none_ |
| `--password-hash` | | Argon2id encoded hash of the client password (required) | _none_ |
| `--config` | | Path to a TOML config file; auto-discovered as `config.toml` in the working directory, then next to the executable | auto-discover |
| `--init` | | Interactively create `config.toml` (password, address, SANs), then exit | _none_ |
| `--force` | | Overwrite an existing `config.toml` when used with `--init` | _none_ |
| `--license` | | Print the MIT license text and exit | _none_ |

`password_hash` is **required** — there is no insecure default. Configure it
with `--init`, `--password-hash <hash>`, or `server.password_hash` in `config.toml`.

## Production deployment

### Requirements

- **Rust 1.85+** (edition 2024) to build from source.
- A **UDP-reachable** port (QUIC runs over UDP). Open/forward it in firewalls /
  security groups.
- **Root/administrator is NOT required** — bind a high port (e.g. `4433`) instead
  of `443`. The QR/TOFU flow lets clients trust a self-signed cert, so no public
  CA is needed.

Run with `RUST_LOG=info` (or `warn`) to avoid debug-level hex dump I/O; the
filter applies to the TUI log stream too. Rolling logs land in `logs/` (daily
rotation, 7-day retention).

```bash
RUST_LOG=info ./target/release/Impulse-server --config config.toml
```

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

## Platforms & downloads

Impulse-server is portable Rust (edition 2024). CI builds release binaries and
`.deb`/`.rpm` packages for the targets below on every tagged release.

| Platform | Target triple | Status | Notes |
|----------|---------------|--------|-------|
| Linux (x86-64) | `x86_64-unknown-linux-gnu` | ✅ CI tested | Recommended for servers |
| Linux (ARM64) | `aarch64-unknown-linux-gnu` | ✅ CI tested (cross) | AWS Graviton, Raspberry Pi 4 (64-bit OS) |
| Linux (ARMv7) | `armv7-unknown-linux-gnueabihf` | ✅ CI tested (cross) | Raspberry Pi 2/3, 32-bit OS |
| Linux (RISC-V 64) | `riscv64gc-unknown-linux-gnu` | ✅ CI tested (cross) | VisionFive 2 |
| Windows (x86-64) | `x86_64-pc-windows-msvc` | ✅ CI tested | Console app, binds UDP/QUIC directly |
| Windows (ARM64) | `aarch64-pc-windows-msvc` | ✅ CI tested | Windows on ARM |
| FreeBSD / BSDs | `x86_64-unknown-freebsd` | ⚠️ Manual only | `aws-lc-sys` has no FreeBSD cross sysroot; native toolchain required |

Prebuilt binaries for every ✅/⚠️ row (except FreeBSD) are attached to each
GitHub Release; `.deb`/`.rpm` packages are built for Linux x86-64 and ARM64.
Artifacts follow `ImpulseServer-<version>-<os>-<arch>.<ext>`, e.g.
`ImpulseServer-2.7.2-linux-amd64.tar.gz` or
`ImpulseServer-2.7.2-windows-arm64.zip`. The archives contain the binary and
`LICENSE` only — config is created on first run or via `--init`.

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
| `0x0C` | C→S / S→C | KeyExchangeKemDsa | combined ML-KEM + ML-DSA-65 public keys (relayed atomically) |

Unknown/invalid client opcodes close the connection. Idle streams close after
300 s. Sessions are capped at 1024 (unique `AtomicU64` ids); the aggregate buffer
is capped at 512 MB; payloads over 1 MB are dropped; a single `Sync` returns at
most 2000 messages. The parser validates declared packet length against the 1 MB
limit before allocating, preventing CPU-DoS via inflated length prefixes.

## Security

- Mandatory QUIC/TLS 1.3 transport (WebTransport).
- Short-lived ECDSA P-256 certs (14 d) with automatic rotation (2 d overlap),
  applied to the **live** TLS resolver without restart, announced via `NewCertHash`.
- TOFU fingerprint pinning via QR code + `NewCertHash`.
- Post-quantum hybrid TLS key exchange (X25519Kyber768) via `aws-lc-rs`.
- **Blind relay** — the server never decrypts payloads; it only sees opaque bytes.
- Ephemeral RAM-only storage, 72h TTL, bounded ring buffer and payload size.
- Passwords stored as Argon2id hashes; constant-time HMAC comparison.
- Per-IP rate limiting (10 connections / 10 s) and session caps against DoS.
- Idle sessions closed after 300 s.
- Private key file `0600` on Unix; exclusive DACL on Windows.
- No plaintext, passwords, or payloads are logged.

## Graceful shutdown

`Ctrl+C` / `SIGTERM` (or `q` in the TUI) stops accepting new sessions and drains
active writers. Logs roll daily in `logs/` with 7-day retention.

## Project layout

```
src/
  cert/        — ECDSA P-256 cert generation, rotation, TOFU fingerprint, FS persist
  storage/     — ephemeral in-RAM message log (TTL 72h, sequence ids)
  protocol.rs  — binary wire frames; framing/limits live in protocol/
  relay/       — WebTransport endpoint, session handling, auth and broadcast relay
  ui/          — terminal UI: Server/Users/Sessions panels, logs, TOFU QR and live stats
  logging/     — tracing → TUI / rolling file bridge
  config/      — CLI parsing and config.toml loading
  cli/         — first-run and --init wizards, config writer
  lib.rs       — wiring + run() entry point
  main.rs      — binary entry point
tests/         — integration tests (handshake, relay, config, storage)
```

## License

MIT — see [LICENSE](LICENSE).
