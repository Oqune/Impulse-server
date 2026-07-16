<div align="center">

[🇺🇸 English](README.md) | [🇷🇺 **Русский**](README.ru.md) | [🇨🇳 中文](README.zh.md)

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.85%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebSocket](https://img.shields.io/badge/WebSocket-tungstenite-green)](https://github.com/snapview/tokio-tungstenite)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

Защищённый WebSocket (WSS) чат-сервер с bcrypt-аутентификацией. TLS обязателен.

</div>

## Запуск

```bash
cargo build --release
./target/release/impulse-server --tls-cert cert.pem --tls-key key.pem
```

| Флаг | Short | Описание | Default |
|------|-------|----------|---------|
| `--host` | | Адрес прослушивания | `0.0.0.0` |
| `--port` | `-p` | TLS-порт (WSS) | `8443` |
| `--password` | `-P` | Пароль сервера | `your_secure_password_here` |
| `--no-color` | | Отключить цвета | `false` |
| `--tls-cert` | | Путь к TLS-сертификату (PEM) | `cert.pem` |
| `--tls-key` | | Путь к TLS-приватному ключу (PEM) | `key.pem` |
| `--tls-san` | | Доп. SAN (DNS/IP) для авто-сгенерированного сертификата (можно несколько) | _нет_ |

Сервер слушает **только** защищённую `wss://` конечную точку. Обычный нешифрованный `ws://` listener не предусмотрен — TLS обязателен для подключения.

## Сертификат

Если рядом с исполняемым файлом нет `cert.pem` / `key.pem`, сервер **автоматически генерирует самоподписанный сертификат** при первом запуске. По умолчанию он действителен для `localhost`, `127.0.0.1` и имени хоста машины.

Чтобы сертификат был действителен для адреса, по которому подключаются клиенты (например, публичный IP за пробросом портов), укажите его как SAN:

```bash
./target/release/impulse-server --tls-san 203.0.113.45
```

Можно указывать `--tls-san` несколько раз для нескольких имён/IP. Чтобы использовать свой сертификат, передайте его явно:

```bash
./target/release/impulse-server --tls-cert cert.pem --tls-key key.pem
```

### Доверие самоподписанному сертификату

Самоподписанный сертификат шифрует трафик, но клиенты не доверяют ему «из коробки» и отвергают его с `CertificateUnknown`. Для тестов можно отключить проверку сертификата на клиенте (`danger_accept_invalid_certs` / `ssl_verify=false`) — трафик всё равно шифруется, но появляется риск MITM. Для реальной работы либо:

- распространите сгенерированный `cert.pem` клиентам и доверьте/закрепите (pin) именно его (добавьте в хранилище доверия ОС или настройте клиент на доверие этому конкретному сертификату), либо
- получите сертификат, подписанный CA (например, Let's Encrypt — нужен домен).

В продакшене используйте реальный сертификат (например, Let's Encrypt). Приватный ключ должен быть в формате PKCS8/SEC1 PEM.

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

- Обязательный TLS-транспорт (WSS)
- Пароль обязателен, bcrypt (`DEFAULT_COST`)
- Макс. 100 клиентов
- Лимит 4 КБ/сообщение (на фрейм, UTF-8 байты)
- Имена: санитизация, ≤32 символа (убираются control/`"`/`\`)
- Ограниченный канал (16 сообщений/клиент)
- `client_id` переиспользуется из свободного списка после отключения
- Heartbeat (ping каждые 30с, таймаут 60с) отключает неотвечающие сокеты
- `Ctrl+C` / `SIGTERM` инициируют корректную остановку

## Лицензия

MIT — см. [LICENSE](LICENSE).
