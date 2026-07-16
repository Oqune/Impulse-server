<div align="center">

[🇺🇸 **English**](README.md) | [🇷🇺 Русский](README.ru.md) | [🇨🇳 中文](README.zh.md)

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.85%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebSocket](https://img.shields.io/badge/WebSocket-tungstenite-green)](https://github.com/snapview/tokio-tungstenite)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

WebSocket chat server with bcrypt authentication.

</div>

## Run

```bash
cargo build --release
./target/release/impulse-server
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--host` | | Listen address | `0.0.0.0` |
| `--port` | `-p` | Port | `8087` |
| `--password` | `-P` | Server password | `your_secure_password_here` |
| `--no-color` | | Disable ANSI colors | `false` |

## Protocol

Every frame is a JSON object with envelope fields `version` (`1`), `timestamp` (ms, Unix), and `type`.

| Type | Direction | Fields |
|------|-----------|--------|
| `auth` | client → server | `name`, `password` |
| `auth_result` | server → client | `success`, `client_id`, `message` |
| `chat` | both | `content`, `sender_id?`, `sender_name?` |
| `event` | server → client | `event` (`joined`/`left`), `user_id`, `user_name` |
| `error` | server → client | `code`, `message` |

Example `chat` broadcast (server → clients):

```json
{"version":1,"timestamp":1710000000000,"type":"chat","content":"hi","sender_id":3,"sender_name":"Alice"}
```

## Security

- Mandatory password, bcrypt (`DEFAULT_COST`)
- Max 100 clients
- 4 KB message limit (per frame, UTF-8 bytes)
- Username sanitization (≤32 chars, control/`"`/`\` stripped)
- Bounded channel (16 msgs/client)
- Client ID counter overflow guard

## TLS

TLS is an optional feature (not wired to a listener yet):

```bash
cargo build --release --features tls
```

## Known limitations

- No `LICENSE` file was shipped despite the MIT badge (now added).
- Historically `ServerConfig` (lib.rs) and `AppConfig`/`ServerSettings` (config.rs) duplicated settings; now `config::ServerSettings` is the single source.
- Dead connections are pruned: a failed `send` removes the client from the map.
- Heartbeat (ping every 30s, 60s timeout) now disconnects unresponsive sockets.
- `Ctrl+C` / `SIGTERM` trigger a graceful shutdown via `WsServer::shutdown()`.
- `client_id` is reused from a free-list after disconnect.
- `auth_result.message` is configurable (`server.auth_message`, defaults to English).
- TLS is an optional feature (not yet wired to a listener).

## License

MIT — see [LICENSE](LICENSE).