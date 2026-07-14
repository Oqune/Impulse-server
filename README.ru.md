<div align="center">

[🇺🇸 English](README.md) | [🇷🇺 **Русский**](README.ru.md) | [🇨🇳 中文](README.zh.md)

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebSocket](https://img.shields.io/badge/WebSocket-tungstenite-green)](https://github.com/snapview/tokio-tungstenite)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

WebSocket-чат сервер с bcrypt-аутентификацией.

</div>

## Запуск

```bash
cargo build --release
./target/release/impulse-server
```

| Флаг | Short | Описание | Default |
|------|-------|----------|---------|
| `--host` | | Адрес прослушивания | `0.0.0.0` |
| `--port` | `-p` | Порт | `8087` |
| `--password` | `-P` | Пароль сервера | `your_secure_password_here` |
| `--no-color` | | Отключить цвета | `false` |

## Протокол

JSON: `version`, `timestamp` (мс), `type`.

| Type | Направление | Поля |
|------|-------------|------|
| `auth` | клиент → сервер | `name`, `password` |
| `auth_result` | сервер → клиент | `success`, `client_id`, `message` |
| `chat` | обе стороны | `content` |
| `event` | сервер → клиент | `event` (`joined`/`left`), `user_id`, `user_name` |
| `error` | сервер → клиент | `code`, `message` |

## Безопасность

- Пароль обязателен, bcrypt
- Макс. 100 клиентов
- Лимит 4 КБ/сообщение
- Имена: санитизация, ≤32 символа
- Ограниченный канал (16 сообщений/клиент)

## TLS

```bash
cargo build --release --features tls
```

## Лицензия

MIT — см. [LICENSE](LICENSE).