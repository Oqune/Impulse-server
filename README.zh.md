<div align="center">

[🇺🇸 English](README.md) | [🇷🇺 Русский](README.ru.md) | [🇨🇳 **中文**](README.zh.md)

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebSocket](https://img.shields.io/badge/WebSocket-tungstenite-green)](https://github.com/snapview/tokio-tungstenite)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

基于 bcrypt 认证的 WebSocket 聊天服务器。

</div>

## 运行

```bash
cargo build --release
./target/release/impulse-server
```

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--host` | | 监听地址 | `0.0.0.0` |
| `--port` | `-p` | 端口 | `8087` |
| `--password` | `-P` | 服务器密码 | `your_secure_password_here` |
| `--no-color` | | 禁用颜色 | `false` |

## 协议

JSON：`version`，`timestamp`（毫秒），`type`。

| Type | 方向 | 字段 |
|------|------|------|
| `auth` | 客户端 → 服务端 | `name`, `password` |
| `auth_result` | 服务端 → 客户端 | `success`, `client_id`, `message` |
| `chat` | 双向 | `content` |
| `event` | 服务端 → 客户端 | `event` (`joined`/`left`), `user_id`, `user_name` |
| `error` | 服务端 → 客户端 | `code`, `message` |

## 安全

- 必须密码，bcrypt
- 最多 100 客户端
- 消息限制 4 KB
- 用户名清洗（≤32 字符）
- 有界通道（16 条/客户端）

## TLS

```bash
cargo build --release --features tls
```

## 许可证

MIT — 参见 [LICENSE](LICENSE)。