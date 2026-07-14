<div align="center">

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebSocket](https://img.shields.io/badge/WebSocket-tungstenite-green)](https://github.com/snapview/tokio-tungstenite)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

WebSocket-чат сервер с bcrypt-аутентификацией.

</div>

---

## Быстрый старт

```bash
# Сборка релиза
cargo build --release

# Запуск с дефолтами (0.0.0.0:8087)
./target/release/impulse-server

# Кастомный адрес/порт
./target/release/impulse-server --host 0.0.0.0 --port 9090

# Кастомный пароль
./target/release/impulse-server -P my_secret_password

# Без цветов (cmd.exe или не-TTY)
./target/release/impulse-server --no-color
```

### По платформам

| Платформа | Бинарник | Команда запуска |
|-----------|----------|-----------------|
| **Windows** | `impulse-server.exe` | `.\target\release\impulse-server.exe` |
| **Linux** | `impulse-server` | `./target/release/impulse-server` |
| **macOS** | `impulse-server` | `./target/release/impulse-server` |

---

## Язык

[English](README.md) | [Русский](README.ru.md)

---

## CLI

| Флаг | Short | Описание | Default |
|------|-------|----------|---------|
| `--host` | | адрес прослушивания | `0.0.0.0` |
| `--port` | `-p` | порт | `8087` |
| `--password` | `-P` | пароль сервера | `your_secure_password_here` |
| `--no-color` | | отключить ANSI-цвета | `false` |
| `--help` | `-h` | справка | |

---

## Протокол

Все сообщения — JSON с тремя полями: `version` (u8), `timestamp` (u64, миллисекунды с эпохи), `type` (строка).

### Типы сообщений

| type | Направление | Поля |
|------|-------------|------|
| `auth` | клиент → сервер | `name`, `password` |
| `auth_result` | сервер → клиент | `success`, `client_id`, `message` |
| `chat` | обе стороны | `content` |
| `event` | сервер → клиент | `event` (`joined`/`left`), `user_id`, `user_name` |
| `error` | сервер → клиент | `code`, `message` |

### Примеры

```json
{"version":1,"timestamp":1720000000000,"type":"auth","name":"Oqune","password":"secret"}
{"version":1,"timestamp":1720000000000,"type":"auth_result","success":true,"client_id":1,"message":"Аутентификация успешна"}
{"version":1,"timestamp":1720000000000,"type":"chat","content":"привет"}
{"version":1,"timestamp":1720000000000,"type":"event","event":"joined","user_id":1,"user_name":"Oqune"}
{"version":1,"timestamp":1720000000000,"type":"error","code":401,"message":"Auth failed"}
```

---

## Безопасность

- **Обязательный пароль** — отказ при отсутствии или неверном
- **bcrypt** — пароли никогда не хранятся в открытом виде
- **Лимит соединений** — максимум 100 клиентов одновременно
- **Лимит размера** — 4 КБ на сообщение
- **Санитизация** — имена очищаются от управляющих символов, макс. 32 символа
- **Backpressure** — ограниченный канал (16 сообщений) на клиент
- **Защита от overflow** — счётчик client_id ограничен `u32::MAX`

---

## TLS

Сборка с TLS для `wss://`:

```bash
cargo build --release --features tls
```

Требуется сертификат и приватный ключ в PEM. См. [rustls docs](https://docs.rs/rustls).

---

## Сборка релизов под разные платформы

### GitHub Actions (рекомендуется)

Создайте `.github/workflows/release.yml`:

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
            # Для Apple Silicon:
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

### Ручная кросс-компиляция

```bash
# Добавить цели
rustup target add x86_64-unknown-linux-gnu
rustup target add x86_64-pc-windows-msvc
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

# Сборка для каждой
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
```

Бинарники появятся в `target/<target>/release/`.

---

## GitHub Packages

Вкладка **Packages** в GitHub — это хостинг реестров пакетов:
- **Cargo crates** (`cargo publish` → crates.io или GitHub Packages)
- **Docker образы** (`docker push ghcr.io/user/repo`)
- **npm пакеты** (`npm publish --registry=https://npm.pkg.github.com`)
- **NuGet, Maven, Rubygems** и др.

Для этого проекта:
- Публикация как crate: `cargo publish --registry=github`
- Docker образ в `ghcr.io`:

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

## Зависимости

- [tokio](https://crates.io/crates/tokio) — async runtime
- [tokio-tungstenite](https://crates.io/crates/tokio-tungstenite) — WebSocket
- [bcrypt](https://crates.io/crates/bcrypt) — хеширование паролей
- [serde](https://crates.io/crates/serde) — сериализация
- [clap](https://crates.io/crates/clap) — CLI парсинг
- [rustls](https://crates.io/crates/rustls) — TLS (опционально)