<div align="center">

[🇺🇸 English](README.md) | [🇷🇺 Русский](README.ru.md) | [🇨🇳 中文](README.zh.md)

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebSocket](https://img.shields.io/badge/WebSocket-tungstenite-green)](https://github.com/snapview/tokio-tungstenite)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

WebSocket 聊天服务器，基于 bcrypt 认证。

</div>

---

## 语言

[🇺🇸 English](README.md) | [🇷🇺 Русский](README.ru.md) | [🇨🇳 中文](README.zh.md)

---

## 快速开始

```bash
# 编译发布版
cargo build --release

# 默认运行 (0.0.0.0:8087)
./target/release/impulse-server

# 自定义地址/端口
./target/release/impulse-server --host 0.0.0.0 --port 9090

# 自定义密码
./target/release/impulse-server -P my_secret_password

# 禁用颜色 (适用于 cmd.exe 或非 TTY)
./target/release/impulse-server --no-color
```

### 平台说明

| 平台 | 二进制文件 | 运行命令 |
|------|-----------|---------|
| **Windows** | `impulse-server.exe` | `.\target\release\impulse-server.exe` |
| **Linux** | `impulse-server` | `./target/release/impulse-server` |
| **macOS** | `impulse-server` | `./target/release/impulse-server` |

---

## CLI 参数

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--host` | | 监听地址 | `0.0.0.0` |
| `--port` | `-p` | 端口 | `8087` |
| `--password` | `-P` | 服务器密码 | `your_secure_password_here` |
| `--no-color` | | 禁用 ANSI 颜色 | `false` |
| `--help` | `-h` | 显示帮助 | |

---

## 协议

所有消息均为 JSON，包含三个字段：`version` (u8)、`timestamp` (u64，毫秒级时间戳)、`type` (字符串)。

### 消息类型

| Type | 方向 | 字段 |
|------|------|------|
| `auth` | 客户端 → 服务端 | `name`, `password` |
| `auth_result` | 服务端 → 客户端 | `success`, `client_id`, `message` |
| `chat` | 双向 | `content` |
| `event` | 服务端 → 客户端 | `event` (`joined`/`left`), `user_id`, `user_name` |
| `error` | 服务端 → 客户端 | `code`, `message` |

### 示例

```json
{"version":1,"timestamp":1720000000000,"type":"auth","name":"Oqune","password":"secret"}
{"version":1,"timestamp":1720000000000,"type":"auth_result","success":true,"client_id":1,"message":"认证成功"}
{"version":1,"timestamp":1720000000000,"type":"chat","content":"你好"}
{"version":1,"timestamp":1720000000000,"type":"event","event":"joined","user_id":1,"user_name":"Oqune"}
{"version":1,"timestamp":1720000000000,"type":"error","code":401,"message":"Auth failed"}
```

---

## 安全性

- **强制密码** —— 缺失或错误时拒绝连接
- **bcrypt 哈希** —— 密码不以明文存储
- **连接数限制** —— 最多 100 个并发客户端
- **消息大小限制** —— 单条消息最大 4 KB
- **输入清理** —— 用户名去除控制字符，最长 32 字符
- **背压控制** —— 每客户端有限队列 (16 条消息)
- **溢出保护** —— client_id 计数器受限于 `u32::MAX`

---

## TLS 支持

启用 TLS 特性以支持 `wss://`：

```bash
cargo build --release --features tls
```

需要 PEM 格式的证书和私钥。详见 [rustls 文档](https://docs.rs/rustls)。

---

## 跨平台构建

### 使用 GitHub Actions (推荐)

创建 `.github/workflows/release.yml`：

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
            # Apple Silicon:
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

### 手动交叉编译

```bash
# 安装目标平台
rustup target add x86_64-unknown-linux-gnu
rustup target add x86_64-pc-windows-msvc
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

# 为每个平台构建
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
```

构建产物位于 `target/<target>/release/`。

---

## GitHub Packages

GitHub 的 **Packages** 标签提供包注册表托管：
- **Cargo crates** (`cargo publish` → crates.io 或 GitHub Packages)
- **Docker 镜像** (`docker push ghcr.io/user/repo`)
- **npm 包** (`npm publish --registry=https://npm.pkg.github.com`)
- **NuGet, Maven, Rubygems** 等

将本项目发布为 crate：

```toml
# Cargo.toml
[package]
name = "impulse-server"
repository = "https://github.com/youruser/impulse-server"
publish = true
```

```bash
cargo publish --registry=github  # 或 crates.io
```

或推送 Docker 镜像：

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

## 依赖

- [tokio](https://crates.io/crates/tokio) — 异步运行时
- [tokio-tungstenite](https://crates.io/crates/tokio-tungstenite) — WebSocket
- [bcrypt](https://crates.io/crates/bcrypt) — 密码哈希
- [serde](https://crates.io/crates/serde) / [serde_json](https://crates.io/crates/serde_json) — 序列化
- [clap](https://crates.io/crates/clap) — CLI 解析
- [rustls](https://crates.io/crates/rustls) / [rustls-pemfile](https://crates.io/crates/rustls-pemfile) — 可选，用于 TLS