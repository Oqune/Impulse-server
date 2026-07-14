<div align="center">

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebSocket](https://img.shields.io/badge/WebSocket-tungstenite-green)](https://github.com/snapview/tokio-tungstenite)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

WebSocket chat server with bcrypt authentication.

</div>

## Run

```bash
cargo build --release

# defaults: 0.0.0.0:8087
./target/release/Impulse-server.exe

# custom address/password
./target/release/Impulse-server.exe --host 0.0.0.0 --port 9090 -P my_secret_password

# no colors (cmd.exe)
./target/release/Impulse-server.exe --no-color
```

## CLI

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--host` | | listen address | `0.0.0.0` |
| `--port` | `-p` | port | `8087` |
| `--password` | `-P` | server password | default |
| `--no-color` | | disable colors | `false` |
| `--help` | `-h` | help | |

## Protocol

JSON with fields `version`, `timestamp` and `type`.

### Message types

| type | Direction | Fields |
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

## Security

- password required, bcrypt hash
- max 100 clients
- max 4096 bytes per message
- usernames sanitized (up to 32 chars)
- bounded channel per client (16 messages)

## Build with TLS

```bash
cargo build --release --features tls
```

## Dependencies

tokio, tokio-tungstenite, bcrypt, serde, clap, rustls (optional)
