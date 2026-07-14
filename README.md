<div align="center">

# Impulse Server

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebSocket](https://img.shields.io/badge/WebSocket-tungstenite-green)](https://github.com/snapview/tokio-tungstenite)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

WebSocket-чат сервер с bcrypt-аутентификацией.

</div>

## Запуск

```bash
cargo build --release

# дефолты: 0.0.0.0:8087
./target/release/Impulse-server.exe

# кастомный адрес/пароль
./target/release/Impulse-server.exe --host 0.0.0.0 --port 9090 -P my_secret_password

# без цветов (cmd.exe)
./target/release/Impulse-server.exe --no-color
```

## CLI

| Параметр | Short | Описание | Default |
|----------|-------|----------|---------|
| `--host` | | адрес прослушивания | `0.0.0.0` |
| `--port` | `-p` | порт | `8087` |
| `--password` | `-P` | пароль сервера | дефолтный |
| `--no-color` | | отключить цвета | `false` |
| `--help` | `-h` | справка | |

## Протокол

JSON с полями `version`, `timestamp` и `type`.

### Типы сообщений

| type          | Направление     | Поля                                              |
|---------------|-----------------|---------------------------------------------------|
| `auth`        | клиент → сервер | `name`, `password`                                |
| `auth_result` | сервер → клиент | `success`, `client_id`, `message`                 |
| `chat`        | обе стороны     | `content`                                         |
| `event`       | сервер → клиент | `event` (`joined`/`left`), `user_id`, `user_name` |
| `error`       | сервер → клиент | `code`, `message`                                 |

### Примеры

```json
{"version":1,"timestamp":1720000000000,"type":"auth","name":"Oqune","password":"secret"}
{"version":1,"timestamp":1720000000000,"type":"auth_result","success":true,"client_id":1,"message":"Аутентификация успешна"}
{"version":1,"timestamp":1720000000000,"type":"chat","content":"привет"}
{"version":1,"timestamp":1720000000000,"type":"event","event":"joined","user_id":1,"user_name":"Oqune"}
{"version":1,"timestamp":1720000000000,"type":"error","code":401,"message":"Auth failed"}
```

## Безопасность

- пароль обязателен, bcrypt-хеш
- максимум 100 клиентов
- максимум 4096 байт на сообщение
- имена санитизируются (до 32 символов)
- ограниченный канал на клиент (16 сообщений)

## Сборка с TLS

```bash
cargo build --release --features tls
```

## Зависимости

tokio, tokio-tungstenite, bcrypt, serde, clap, rustls (опционально)
