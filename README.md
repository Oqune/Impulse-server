<div align="center">

[🇺🇸 **English**](README.md) | [🇷🇺 Русский](README.ru.md) | [🇨🇳 中文](README.zh.md)

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.85%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebSocket](https://img.shields.io/badge/WebSocket-tungstenite-green)](https://github.com/snapview/tokio-tungstenite)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

Secure WebSocket (WSS) chat server with bcrypt authentication. TLS is mandatory.

</div>

## Run

```bash
cargo build --release
./target/release/impulse-server --tls-cert cert.pem --tls-key key.pem
```

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--host` | | Listen address | `0.0.0.0` |
| `--port` | `-p` | TLS listen port (WSS) | `8443` |
| `--password` | `-P` | Server password | `your_secure_password_here` |
| `--no-color` | | Disable ANSI colors | `false` |
| `--tls-cert` | | Path to TLS certificate (PEM) | `cert.pem` |
| `--tls-key` | | Path to TLS private key (PEM) | `key.pem` |
| `--tls-san` | | Extra SAN (DNS/IP) for the auto-generated self-signed cert (repeatable) | _none_ |

The server listens **only** on a secure `wss://` endpoint. A plain (unencrypted) `ws://` listener is not provided — TLS is required for the connection.

## Certificate

If `cert.pem` / `key.pem` are missing next to the executable, the server
**auto-generates a self-signed certificate** on first start. By default it is
valid for `localhost`, `127.0.0.1` and the machine hostname.

To make the certificate valid for the address your clients connect to (e.g. a
public IP behind port forwarding), pass it as a SAN:

```bash
./target/release/impulse-server --tls-san 203.0.113.45
```

You can repeat `--tls-san` for multiple names/IPs. To use your own certificate
instead, provide it explicitly:

```bash
./target/release/impulse-server --tls-cert cert.pem --tls-key key.pem
```

### Trusting the self-signed certificate

A self-signed certificate encrypts traffic but is not trusted by clients out of
the box, so they reject it with `CertificateUnknown`. For testing you can
disable certificate validation on the client (e.g. `danger_accept_invalid_certs`
/ `ssl_verify=false`) — this still encrypts, but allows MITM. For real use,
either:

- distribute the generated `cert.pem` to clients and pin/trust it (add it to the
  OS trust store, or configure the client to trust that specific cert), or
- obtain a CA-signed certificate (e.g. Let's Encrypt — requires a domain).

In production use a real certificate (e.g. Let's Encrypt). The private key must be in PKCS8/SEC1 PEM format.

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

- Mandatory TLS (WSS) transport
- Mandatory password, bcrypt (`DEFAULT_COST`)
- Max 100 clients
- 4 KB message limit (per frame, UTF-8 bytes)
- Username sanitization (≤32 chars, control/`"`/`\` stripped)
- Bounded channel (16 msgs/client)
- Client ID reuse from a free-list after disconnect
- Heartbeat (ping every 30s, 60s timeout) drops unresponsive sockets
- `Ctrl+C` / `SIGTERM` triggers a graceful shutdown

## License

MIT — see [LICENSE](LICENSE).
