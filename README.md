<div align="center">

# Impulse Server

[![Rust](https://img.shields.io/badge/Rust-1.70%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebSocket](https://img.shields.io/badge/WebSocket-tungstenite-green)](https://github.com/snapview/tokio-tungstenite)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

WebSocket-чат сервер с bcrypt-аутентификацией и типизированным JSON-протоколом.

</div>

## Возможности

- Аутентификация по паролю (bcrypt)
- Рассылка сообщений всем подключенным клиентам
- События подключения и отключения
- Ограничение на 100 одновременных клиентов
- Ограничение размера сообщения (4 KB)
- Санитизация имен пользователей
- Цветной вывод логов, режим без цветов для CMD
- Опциональная поддержка TLS

## Запуск

### Сборка

```bash
cargo build --release
```

### Запуск

```bash
# дефолты: 0.0.0.0:8087
./target/release/Impulse-server.exe

# кастомный адрес
./target/release/Impulse-server.exe --host 0.0.0.0 --port 9090

# кастомный пароль
./target/release/Impulse-server.exe -P my_secret_password

# без цветов (для cmd.exe)
./target/release/Impulse-server.exe --no-color
```

## CLI параметры

| Параметр | Short | Описание | Default |
|----------|-------|----------|---------|
| `--host` | | Адрес прослушивания | `0.0.0.0` |
| `--port` | `-p` | Порт | `8087` |
| `--password` | `-P` | Пароль сервера | дефолтный |
| `--no-color` | | Отключить цвета в выводе | `false` |
| `--help` | `-h` | Справка | |

## Протокол

Все сообщения — JSON с полями `v` (версия), `ts` (timestamp в мс) и `type` (тип сообщения).

### Типы сообщений

| type | Направление | Поля |
|------|-------------|------|
| `auth` | клиент → сервер | `name`, `password` |
| `auth_result` | сервер → клиент | `success`, `client_id`, `message` |
| `chat` | обе стороны | `content` |
| `event` | сервер → клиент | `event` (`joined`/`left`), `user_id`, `user_name` |
| `error` | сервер → клиент | `code`, `message` |

### Примеры

Аутентификация:

```json
{
  "v": 1,
  "ts": 1720000000000,
  "type": "auth",
  "name": "Oqune",
  "password": "secret"
}
```

Результат аутентификации:

```json
{
  "v": 1,
  "ts": 1720000000000,
  "type": "auth_result",
  "success": true,
  "client_id": 1,
  "message": "Аутентификация успешна"
}
```

Чат:

```json
{
  "v": 1,
  "ts": 1720000000000,
  "type": "chat",
  "content": "привет"
}
```

Событие:

```json
{
  "v": 1,
  "ts": 1720000000000,
  "type": "event",
  "event": "joined",
  "user_id": 1,
  "user_name": "Oqune"
}
```

Ошибка:

```json
{
  "v": 1,
  "ts": 1720000000000,
  "type": "error",
  "code": 401,
  "message": "Auth failed"
}
```

## Безопасность

- Пароль обязателен при подключении
- Пароль хранится в bcrypt-хеше
- Максимум 100 клиентов одновременно
- Максимум 4096 байт на сообщение
- Имена пользователей санитизируются (длина до 32 символов, без управляющих символов)
- Ограниченный размер канала на клиент (16 сообщений)
- Защита от переполнения счетчика client_id

## Сборка с TLS

```bash
cargo build --release --features tls
```

## Структура проекта

```
server/
├── Cargo.toml          # зависимости и фичи
├── src/
│   ├── main.rs         # точка входа, CLI
│   ├── lib.rs          # WebSocket сервер и протокол
│   ├── config.rs       # конфигурация CLI
│   └── console.rs      # логирование и баннер
```

## Зависимости

- tokio — асинхронный рантайм
- tokio-tungstenite — WebSocket
- bcrypt — хеширование паролей
- serde / serde_json — сериализация
- clap — CLI парсинг
- rustls / rustls-pemfile — опционально, для TLS
