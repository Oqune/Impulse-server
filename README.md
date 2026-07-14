<div align="center">

[🇺🇸 **English**](README.md) | [🇷🇺 Русский](README.ru.md) | [🇨🇳 中文](README.zh.md)

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
./target/release/impulse-server
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--host` | | Listen address | `0.0.0.0` |
| `--port` | `-p` | Port | `8087` |
| `--password` | `-P` | Server password | `your_secure_password_here` |
| `--no-color` | | Disable ANSI colors | `false` |

## Protocol

JSON: `version`, `timestamp` (ms), `type`.

| Type | Direction | Fields |
|------|-----------|--------|
| `auth` | client → server | `name`, `password` |
| `auth_result` | server → client | `success`, `client_id`, `message` |
| `chat` | both | `content` |
| `event` | server → client | `event` (`joined`/`left`), `user_id`, `user_name` |
| `error` | server → client | `code`, `message` |

## Security

- Mandatory password, bcrypt
- Max 100 clients
- 4 KB message limit
- Username sanitization (≤32 chars)
- Bounded channel (16 msgs/client)

## TLS

```bash
cargo build --release --features tls
```

## License

MIT — see [LICENSE](LICENSE).