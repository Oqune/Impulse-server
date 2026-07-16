<div align="center">

[🇺🇸 English](README.md) | [🇷🇺 **Русский**](README.ru.md) | [🇨🇳 中文](README.zh.md)

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.85%2B-darkblue?logo=rust)](https://www.rust-lang.org)
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

Каждый фрейм — JSON-объект с полями обёртки `version` (`1`), `timestamp` (мс, Unix) и `type`.

| Type | Направление | Поля |
|------|-------------|------|
| `auth` | клиент → сервер | `name`, `password` |
| `auth_result` | сервер → клиент | `success`, `client_id`, `message` |
| `chat` | обе стороны | `content`, `sender_id?`, `sender_name?` |
| `event` | сервер → клиент | `event` (`joined`/`left`), `user_id`, `user_name` |
| `error` | сервер → клиент | `code`, `message` |

Пример `chat`-рассылки (сервер → клиенты):

```json
{"version":1,"timestamp":1710000000000,"type":"chat","content":"hi","sender_id":3,"sender_name":"Alice"}
```

## Безопасность

- Пароль обязателен, bcrypt (`DEFAULT_COST`)
- Макс. 100 клиентов
- Лимит 4 КБ/сообщение (на фрейм, UTF-8 байты)
- Имена: санитизация, ≤32 символа (убираются control/`"`/`\`)
- Ограниченный канал (16 сообщений/клиент)
- Защита от переполнения счётчика ID клиентов

## TLS

TLS — опциональный feature (пока не подключён к слушателю):

```bash
cargo build --release --features tls
```

## Известные недостатки

- Файл `LICENSE` не поставлялся при MIT-бейдже (теперь добавлен).
- Ранее `ServerConfig` (lib.rs) и `AppConfig`/`ServerSettings` (config.rs) дублировали настройки; теперь единый источник — `config::ServerSettings`.
- Мёртвые соединения очищаются: неудачный `send` удаляет клиента из map.
- Heartbeat (ping каждые 30с, таймаут 60с) отключает неотвечающие сокеты.
- `Ctrl+C` / `SIGTERM` инициируют корректную остановку через `WsServer::shutdown()`.
- `client_id` переиспользуется из свободного списка после отключения.
- `auth_result.message` настраивается (`server.auth_message`, по умолчанию английский).
- TLS — опциональный feature (пока не подключён к слушателю).

## Лицензия

MIT — см. [LICENSE](LICENSE).