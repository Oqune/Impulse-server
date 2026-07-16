<div align="center">

[🇺🇸 English](README.md) | [🇷🇺 Русский](README.ru.md) | [🇨🇳 **中文**](README.zh.md)

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.85%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebSocket](https://img.shields.io/badge/WebSocket-tungstenite-green)](https://github.com/snapview/tokio-tungstenite)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

基于 bcrypt 认证的 安全 WebSocket（WSS）聊天服务器。TLS 为强制要求。

</div>

## 运行

```bash
cargo build --release
./target/release/impulse-server --tls-cert cert.pem --tls-key key.pem
```

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--host` | | 监听地址 | `0.0.0.0` |
| `--port` | `-p` | TLS 监听端口（WSS） | `8443` |
| `--password` | `-P` | 服务器密码 | `your_secure_password_here` |
| `--no-color` | | 禁用颜色 | `false` |
| `--tls-cert` | | TLS 证书路径（PEM） | `cert.pem` |
| `--tls-key` | | TLS 私钥路径（PEM） | `key.pem` |

服务器**仅**监听安全的 `wss://` 端点。不提供明文 `ws://` 监听端口——连接必须使用 TLS。

## 证书

提供 PEM 格式的证书/密钥对。本地测试可生成自签名证书：

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

生产环境请使用真实证书（如 Let's Encrypt）。私钥须为 PKCS8/SEC1 PEM 格式。

## 协议

每个帧都是 JSON 对象，包含信封字段 `version`（`1`）、`timestamp`（毫秒，Unix）和 `type`。

| Type | 方向 | 字段 |
|------|------|------|
| `auth` | 客户端 → 服务端 | `name`, `password` |
| `auth_result` | 服务端 → 客户端 | `success`, `client_id`, `message` |
| `chat` | 双向 | `content`, `sender_id?`, `sender_name?` |
| `event` | 服务端 → 客户端 | `event` (`joined`/`left`), `user_id`, `user_name` |
| `error` | 服务端 → 客户端 | `code`, `message` |

`chat` 广播示例（服务端 → 客户端）：

```json
{"version":1,"timestamp":1710000000000,"type":"chat","content":"hi","sender_id":3,"sender_name":"Alice"}
```

## 安全

- 强制 TLS 传输（WSS）
- 必须密码，bcrypt（`DEFAULT_COST`）
- 最多 100 客户端
- 消息限制 4 KB（每帧，UTF-8 字节）
- 用户名清洗（≤32 字符，移除 control/`"`/`\`）
- 有界通道（16 条/客户端）
- `client_id` 在断开后从空闲列表中复用
- 心跳（每 30 秒 ping，60 秒超时）断开无响应的套接字
- `Ctrl+C` / `SIGTERM` 触发优雅停止

## 许可证

MIT — 参见 [LICENSE](LICENSE)。
