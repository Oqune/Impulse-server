<div align="center">

[🇺🇸 English](README.md) | [🇷🇺 Русский](README.ru.md) | [🇨🇳 **中文**](README.zh.md)

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.85%2B-darkblue?logo=rust)](https://www.rust-lang.org)
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

- 必须密码，bcrypt（`DEFAULT_COST`）
- 最多 100 客户端
- 消息限制 4 KB（每帧，UTF-8 字节）
- 用户名清洗（≤32 字符，移除 control/`"`/`\`）
- 有界通道（16 条/客户端）
- 客户端 ID 计数器溢出保护

## TLS

TLS 为可选 feature（尚未接入监听端口）：

```bash
cargo build --release --features tls
```

## 已知问题

- 尽管徽章标注 MIT，此前未附带 `LICENSE` 文件（现已添加）。
- 此前 `ServerConfig`（lib.rs）与 `AppConfig`/`ServerSettings`（config.rs）重复配置；现在统一为 `config::ServerSettings`。
- 无效连接会被清理：发送失败的 `send` 会从 map 中移除客户端。
- 心跳（每 30 秒 ping，60 秒超时）会断开无响应的套接字。
- `Ctrl+C` / `SIGTERM` 通过 `WsServer::shutdown()` 优雅停止。
- `client_id` 在断开后从空闲列表中复用。
- `auth_result.message` 可配置（`server.auth_message`，默认英文）。
- TLS 为可选 feature（尚未接入监听端口）。

## 许可证

MIT — 参见 [LICENSE](LICENSE)。