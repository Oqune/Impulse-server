<div align="center">

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebSocket](https://img.shields.io/badge/WebSocket-tungstenite-green)](https://github.com/snapview/tokio-tungstenite)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

WebSocket chat server with bcrypt authentication.

</div>

---

## Quick Start

```bash
# Build release
cargo build --release

# Run with defaults (0.0.0.0:8087)
./target/release/impulse-server

# Custom host/port
./target/release/impulse-server --host 0.0.0.0 --port 9090

# Custom password
./target/release/impulse-server -P my_secret_password

# Disable colors (for cmd.exe or non-TTY)
./target/release/impulse-server --no-color
```

### Platform Notes

| Platform | Binary | Run Command |
|----------|--------|-------------|
| **Windows** | `impulse-server.exe` | `.\target\release\impulse-server.exe` |
| **Linux** | `impulse-server` | `./target/release/impulse-server` |
| **macOS** | `impulse-server` | `./target/release/impulse-server` |

---

## Language

[English](README.md) | [Русский](README.ru.md)

---

## CLI Reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--host` | | Listen address | `0.0.0.0` |
| `--port` | `-p` | Port | `8087` |
| `--password` | `-P` | Server password | `your_secure_password_here` |
| `--no-color` | | Disable ANSI colors | `false` |
| `--help` | `-h` | Show help | |

---

## Protocol

All messages are JSON objects with three fields: `version` (u8), `timestamp` (u64, milliseconds since epoch), and `type` (string).

### Message Types

| Type | Direction | Fields |
|------|-----------|--------|
| `auth` | client → server | `name`, `password` |
| `auth_result` | server → client | `success`, `client_id`, `message` |
| `chat` | both | `content` |
| `event` | server → client | `event` (`joined`/`left`), `user_id`, `user_name` |
| `error` | server → client | `code`, `message` |

### Examples

```json
{"version":1,"timestamp":1720000000000,"type":"auth","name":"Oqune","password":"secret"}
{"version":1,"timestamp":1720000000000,"type":"auth_result","success":true,"client_id":1,"message":"Authenticated"}
{"version":1,"timestamp":1720000000000,"type":"chat","content":"hello"}
{"version":1,"timestamp":1720000000000,"type":"event","event":"joined","user_id":1,"user_name":"Oqune"}
{"version":1,"timestamp":1720000000000,"type":"error","code":401,"message":"Auth failed"}
```

---

## Security

- **Mandatory password** — rejected if missing or wrong
- **bcrypt hashing** — passwords never stored in plain text
- **Connection limit** — max 100 concurrent clients
- **Message size limit** — 4 KB per message
- **Input sanitization** — usernames stripped of control chars, max 32 chars
- **Backpressure** — bounded channel (16 messages) per client
- **Overflow protection** — client ID counter guarded at `u32::MAX`

---

## TLS Support

Build with TLS feature for `wss://` support:

```bash
cargo build --release --features tls
```

Requires a certificate and private key in PEM format. See [rustls docs](https://docs.rs/rustls) for TLS config.

---

## Cross-Platform Release Build

### Using GitHub Actions (Recommended)

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            artifact: impulse-server-linux
          - os: windows-latest
            target: x86_64-pc-windows-msvc
            artifact: impulse-server-windows.exe
          - os: macos-latest
            target: x86_64-apple-darwin
            artifact: impulse-server-macos
            # For Apple Silicon:
            # - os: macos-latest
            #   target: aarch64-apple-darwin
            #   artifact: impulse-server-macos-arm64

    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      - name: Add target
        run: rustup target add ${{ matrix.target }}
      - name: Build
        run: cargo build --release --target ${{ matrix.target }}
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: ${{ matrix.artifact }}
          path: target/${{ matrix.target }}/release/impulse-server*

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: impulse-server-*
```

### Manual Cross-Compilation

```bash
# Install targets
rustup target add x86_64-unknown-linux-gnu
rustup target add x86_64-pc-windows-msvc
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

# Build for each
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
```

Binaries appear in `target/<target>/release/`.

---

## GitHub Packages

The **Packages** tab on GitHub hosts registries for:
- **Cargo crates** (`cargo publish` → crates.io or GitHub Packages)
- **Docker images** (`docker push ghcr.io/user/repo`)
- **npm packages** (`npm publish --registry=https://npm.pkg.github.com`)
- **NuGet, Maven, Rubygems**, etc.

For this project, you'd use it if you publish the server as a crate or provide a Docker image:

```toml
# Cargo.toml for publishing
[package]
name = "impulse-server"
repository = "https://github.com/youruser/impulse-server"
publish = true
```

```bash
cargo publish --registry=github  # or crates.io
```

Or build a Docker image and push to `ghcr.io`:

```dockerfile
FROM rust:1.78 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/impulse-server /usr/local/bin/
EXPOSE 8087
CMD ["impulse-server"]
```

```bash
docker build -t ghcr.io/youruser/impulse-server:v1.0.0 .
docker push ghcr.io/youruser/impulse-server:v1.0.0
```

---

## Dependencies

- [tokio](https://crates.io/crates/tokio) — async runtime
- [tokio-tungstenite](https://crates.io/crates/tokio-tungstenite) — WebSocket
- [bcrypt](https://crates.io/crates/bcrypt) — password hashing
- [serde](https://crates.io/crates/serde) — serialization
- [clap](https://crates.io/crates/clap) — CLI parsing
- [rustls](https://crates.io/crates/rustls) — TLS (optional feature)