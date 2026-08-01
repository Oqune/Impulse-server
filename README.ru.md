<div align="center">

[🇺🇸 **English**](README.md) | [🇷🇺 **Русский**](README.ru.md)

![logo](logo.png)

[![Rust](https://img.shields.io/badge/Rust-1.85%2B-darkblue?logo=rust)](https://www.rust-lang.org)
[![WebTransport](https://img.shields.io/badge/Transport-WebTransport%20%2F%20QUIC-green)](https://w3c.github.io/webtransport/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Oqune/Impulse-server/actions/workflows/server-build.yml/badge.svg)](https://github.com/Oqune/Impulse-server/actions/workflows/server-build.yml)
[![Release](https://img.shields.io/github/v/release/Oqune/Impulse-server?label=latest)](https://github.com/Oqune/Impulse-server/releases)

Сервер безопасного **эфемерного** мессенджера на **WebTransport (QUIC)** с
**TOFU** (trust-on-first-use) и парольной аутентификацией.

> **Клиент:** [Oqune/Impulse-client](https://github.com/Oqune/Impulse-client) —
> Android-клиент с постквантовым E2EE для этого сервера.

</div>

## Обзор

Impulse — это relay-сервер для end-to-end-encrypted мессенджера. Сервер
**никогда не видит открытый текст** — клиенты шифруют полезную нагрузку локально
и передают серверу только непрозрачные байты, идентификатор последовательности,
временную метку и публичный ключ для каждого сообщения. Сервер хранит сообщения
в RAM (TTL 72 ч), назначает монотонно возрастающие идентификаторы и рассылает
их всем подключенным клиентам.

Ключевые архитектурные решения:

- **Транспорт:** только WebTransport поверх QUIC (`wtransport` 0.7). TLS 1.3
  обязателен; старый WSS-транспорт удалён.
- **Бинарный протокол:** length-prefixed бинарные фреймы с опкодами `0x01`–`0x0C`
  (little-endian), не JSON.
- **Аутентификация:** сервер отправляет `AuthChallenge (0x0B)` с 16-байтным nonce
  и Argon2id-солью; клиент вычисляет ключ через Argon2id, HMAC-SHA-256(key, nonce)
  и отправляет `Auth (0x01)` с паролем и HMAC. Сервер проверяет HMAC в constant time
  и хранит пароли как Argon2id-хэши.
- **TLS / Сертификаты:** самоподписанные **ECDSA P-256** сертификаты, срок действия
  **14 дней**, автоматическая ротация с **2-дневным окном перекрытия**. PEM-материал
  сохраняется в `cert_dir` (путь относительно исполняемого файла, права `0600` на
  Unix, эксклюзивный DACL на Windows).
- **TOFU:** сервер отображает QR-код, содержащий `impulse-cert:<sha256>`
  (SHA-256 отпечаток DER-сертификата). Клиенты сканируют его, закрепляют
  `serverCertificateHashes` и доверяют серверу при первом использовании. При
  ротации новый отпечаток рассылается через `NewCertHash` (0x07).
- **Хранилище:** in-RAM ring buffer, сообщения истекают через 72 ч (`TTL`),
  ограничено количеством (`10_000`) и размером полезной нагрузки (`1 MB`).
  KeyExchange-данные кэшируются per-сессия (DashMap) и replay'ятся новым клиентам.
- **Relay:** broadcast всем активным сессиям; поздние подключающиеся догоняют
  через `Sync { last_seen_id }`. Один `Sync` возвращает не более `2000` сообщений.
  Ключевые обмены также ретранслируются всем подключённым клиентам.
- **Администрирование:** **TUI** с двухколоночным layout:
  - **Левая колонка** (Info + QR + Certificate): адрес прослушивания, транспорт
    (`WebTransport/QUIC TLS1.3 (h3)`), версия crate, количество SAN, текущие
    `сессии / MAX_SESSIONS`, количество хранящихся сообщений, TTL сообщений,
    максимальный размер полезной нагрузки, SHA-256 отпечаток сертификата (сокращённый),
    обратный отсчёт до истечения сертификата, индикатор ⚠ во время перекрытия ключей
    и сканируемый QR-код.
  - **Правая колонка** (Help bar + Logs): поток логов сервера в реальном времени
    с фильтрацией по уровням (`1`–`5`), прокруткой (`↑↓`/`PgUp`/`PgDn`/`Home`/`End`)
    и `Shift+C` для копирования логов в буфер обмена.
  `Ctrl+C` / `q` — корректное завершение работы.

## Сборка и запуск

```bash
cargo build --release
./target/release/Impulse-server --config config.toml
# или через CLI-флаги (переопределяют конфиг-файл):
./target/release/Impulse-server --port 4433 --cert-dir cert_data \
    --password-hash "$(./target/release/Impulse-server --hash-password yourpassword)"
```

| Флаг | Короткий | Описание | По умолчанию |
|------|----------|----------|-------------|
| `--host` | | Хост для привязки (переопределяет `server.address` в конфиге) | из конфига / `0.0.0.0` |
| `--port` | `-p` | Порт WebTransport (QUIC) (переопределяет порт в конфиге) | из конфига / `4433` |
| `--cert-dir` | | Каталог для генерируемых сертификата/ключа | `cert_data` |
| `--san` | | Дополнительный SAN (DNS или IP) для самоподписанного сертификата (повторяемый) | _нет_ |
| `--password-hash` | | Argon2id хэш пароля клиента (обязателен) | _нет_ |
| `--config` | | Путь к TOML-конфигу; авто-поиск `config.toml` в рабочем каталоге, затем рядом с исполняемым файлом | авто-поиск |

`password_hash` **обязателен** — небезопасного значения по умолчанию нет.
Сгенерируйте встроенным хелпером:

```bash
./target/release/Impulse-server --hash-password yourpassword
```

При старте сервер выводит `Using config file: <путь>`, если конфиг загружен.
Конфиг, заданный явно (`--config`) или найденный автоматически, но не читаемый
или не парсящийся — фатальная ошибка запуска: сервер никогда не откатывается
к значениям по умолчанию молча.

## Продакшен-развёртывание

### Требования

- **Rust 1.85+** (edition 2024) для сборки из исходников.
- **Доступный по UDP** порт (QUIC работает поверх UDP). Откройте/пробросьте порт в фаерволе / security groups.
- На **Unix** файл приватного ключа автоматически создаётся с правами `0600`; на Windows DACL ограничивается текущим пользователем через `icacls`.
- **Root/administrator НЕ требуется** — используйте высокий порт (например, `4433`) вместо `443`. QR/TOFU-поток позволяет клиентам доверять самоподписанному сертификату, поэтому публичный CA не нужен.

### Рекомендуемые флаги запуска

В продакшене используйте `RUST_LOG=info` или `RUST_LOG=warn`, чтобы избежать лишнего I/O от hex-дампа в debug-режиме:

```bash
RUST_LOG=info ./target/release/Impulse-server --config config.toml
```

Сервер ведёт rolling-логи в `logs/` (суточная ротация, retention 7 дней).

### Systemd-сервис (Linux)

Создайте `/etc/systemd/system/impulse-server.service`:

```ini
[Unit]
Description=Impulse Server
After=network.target

[Service]
Type=simple
User=impulse
WorkingDirectory=/opt/impulse-server
ExecStart=/opt/impulse-server/Impulse-server --config /opt/impulse-server/config.toml
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now impulse-server
```

### Docker

```dockerfile
FROM rust:1.85-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/Impulse-server /usr/local/bin/impulse-server
COPY config.toml /etc/impulse-server/config.toml
VOLUME /var/lib/impulse-server/cert_data /var/log/impulse-server
EXPOSE 4433/udp
ENV RUST_LOG=info
ENTRYPOINT ["impulse-server", "--config", "/etc/impulse-server/config.toml"]
```

```bash
docker build -t impulse-server .
docker run -d \
  --name impulse \
  --restart unless-stopped \
  -v cert_data:/var/lib/impulse-server/cert_data \
  -v impulse_logs:/var/log/impulse-server \
  -p 4433:4433/udp \
  impulse-server
```

### NixOS

```console
$ nix build github:Oqune/Impulse-server
$ ./result/bin/impulse-server --help
```

Или установите в свой профиль:

```console
$ nix profile install github:Oqune/Impulse-server
```

### Фаервол

QUIC использует UDP. Убедитесь, что выбранный порт открыт:

```bash
# ufw (Ubuntu/Debian)
sudo ufw allow 4433/udp

# firewalld (RHEL/CentOS/Fedora)
sudo firewall-cmd --add-port=4433/udp --permanent && sudo firewall-cmd --reload

# Windows PowerShell
New-NetFirewallRule -DisplayName "Impulse QUIC" -Direction Inbound -Protocol UDP -LocalPort 4433 -Action Allow
```

## Поддерживаемые платформы

Impulse-server написан на переносимом Rust (edition 2024) и собирается на целях
ниже при наличии рабочей Rust-тулчейна и UDP/QUIC сети. CI публикует релизные
бинарники и `.deb`/`.rpm` пакеты для Linux на x86-64 и ARM64, а также релизные
бинарники для Linux ARMv7/RISC-V 64 и Windows на x86-64 и ARM64.

| Платформа | Target triple | Статус | Примечания |
|-----------|---------------|--------|------------|
| Linux (x86-64) | `x86_64-unknown-linux-gnu` | ✅ CI tested | Рекомендуется для серверов |
| Linux (ARM64) | `aarch64-unknown-linux-gnu` | ✅ CI tested (cross) | AWS Graviton, Raspberry Pi 4 (64-bit OS) |
| Linux (ARMv7) | `armv7-unknown-linux-gnueabihf` | ✅ CI tested (cross) | Raspberry Pi 2/3, 32-bit OS |
| Linux (RISC-V 64) | `riscv64gc-unknown-linux-gnu` | ✅ CI tested (cross) | например VisionFive 2 |
| Windows (x86-64) | `x86_64-pc-windows-msvc` | ✅ CI tested | Консольное приложение; биндится на UDP/QUIC порт напрямую |
| Windows (ARM64) | `aarch64-pc-windows-msvc` | ✅ CI tested | Устройства на Windows on ARM |
| FreeBSD / BSD | `x86_64-unknown-freebsd` | ⚠️ Manual only | У `aws-lc-sys` нет FreeBSD sysroot для кросс-компиляции; требуется нативная тулчейн |

Готовые бинарники для всех ✅ и ⚠️ строк (кроме FreeBSD) прикреплены к каждому
GitHub Release; `.deb` и `.rpm` пакеты собираются для Linux x86-64 и ARM64.

### Требования

- **Rust 1.85+** (edition 2024).
- **Доступный по UDP** порт (QUIC работает поверх UDP). Откройте/пробросьте настроенный порт в файрволах.
- На **Unix** файл приватного ключа автоматически создаётся с правами `0600`; на Windows DACL ограничивается текущим пользователем.
- **Root/administrator НЕ требуется** — биндитесь на высокий порт (например, `4433`) вместо `443`. QR/TOFU-поток позволяет клиентам доверять самоподписанному сертификату, поэтому публичный CA не нужен.

## Протокол (бинарный, little-endian)

Все фреймы: `[opcode: u8][...поля]`. Length-prefixed блобы — `u32 len` затем `len` байт.

| Opcode | Напр. | Имя | Поля |
|--------|-------|-----|------|
| `0x01` | C→S | Auth | `u32 LE pwd_len`, `pwd_len` байт пароля (UTF-8), 32 сырых байта HMAC-SHA-256 |
| `0x02` | S→C | AuthResult | `u8` статус (`0`=ok, `1`=fail) + опциональный `len`-prefixed текст |
| `0x03` | C→S | Sync | `u64` last_seen_id |
| `0x04` | S→C | SyncResponse | `u32` count, затем для каждого сообщения: `u64 id`, `u64 ts`, `len`-prefixed payload |
| `0x05` | C→S / S→C | Data | C→S: `len`-prefixed payload. S→C: `u64 id`, `u64 ts`, `len`-prefixed payload |
| `0x06` | обе | Heartbeat | `u64` client_timestamp (эхо-ответ) |
| `0x07` | S→C | NewCertHash | ровно 32 сырых байта SHA-256 + `u64` unix expiry |
| `0x0B` | S→C | AuthChallenge | 16 байт nonce + `u32 LE salt_len`, `salt_len` байт B64 Argon2id соли |
| `0x0C` | C→S / S→C | KeyExchangeKemDsa | `len`-prefixed комбинированный ML-KEM + ML-DSA-65 публичные ключи (ретранслируется атомарно) |

Неизвестные/невалидные опкоды от клиента закрывают соединение. Простаивающие
стримы закрываются через 300 с. Сессии лимитированы 1024; агрегатный буфер
ограничен 512 МБ (`AtomicUsize`), идентификаторы сессий уникальны
(`AtomicU64` счётчик). Оверсайзные полезные нагрузки (>1 MB) отбрасываются. Один `Sync` возвращает не более 2000 сообщений.
Wire-parser валидирует заявленную длину пакета против того же лимита в 1 MB
до любой аллокации, предотвращая CPU-DoS через inflation length-префиксов (C1).

## Безопасность

- Обязательный QUIC/TLS 1.3 транспорт (WebTransport).
- Краткоживущие ECDSA P-256 сертификаты (14 дн.) с автоматической ротацией
  (2 дн. перекрытие); новый сертификат применяется к **рабочему** TLS resolver'у
  (без рестарта) и анонсируется через `NewCertHash`.
- TOFU pinning отпечатка через QR-код + контрольный пакет `NewCertHash`.
- Гибридный постквантовый обмен ключами (X25519Kyber768, ML-KEM, ML-DSA-65) через `aws-lc-rs`.
- Эфемерное RAM-only хранилище, TTL 72 ч, ограниченный ring buffer и размер
  полезной нагрузки.
- Argon2id для хэширования паролей с constant-time сравнением HMAC.
- Replay-защита ключевых обменов: сервер кэширует KeyExchange по сессиям
  (DashMap) и replay'ит их вновь подключившимся клиентам.
- Blind relay — сервер **никогда не расшифровывает** полезные нагрузки сообщений.
- Файл приватного ключа ограничен `0600` на Unix; эксклюзивный DACL на Windows.
- Per-IP rate limiting (10 соединений / 10 сек) и лимит сессий для защиты от DoS.
- Неактивные сессии закрываются через 300 с для предотвращения утечек ресурсов.
- Открытый текст, пароли или полезные нагрузки не логируются.

## Корректное завершение работы

`Ctrl+C` / `SIGTERM` (или `q` в TUI) запускают graceful shutdown: эндпойнт
перестаёт принимать новые сессии, активные writer'ы дрейнятся. Логи пишутся в
`logs/` с суточной ротацией и retention 7 дней.

## Структура проекта

```
src/
  cert.rs      — генерация ECDSA P-256 сертификатов, ротация, SHA-256 TOFU отпечаток, FS персист
  storage.rs   — эфемерный in-RAM лог сообщений (TTL 72ч, sequence ids)
  protocol.rs  — бинарные wire-фреймы (опкоды 0x01–0x0C)
  server.rs    — WebTransport эндпойнт, обработка сессий, broadcast relay
  tui.rs       — терминальный UI: Server Info header, лог-стрим, TOFU QR / fingerprint панель
  logging.rs   — мост tracing → TUI / rolling-файл
  config.rs    — загрузка CLI + config.toml
  lib.rs       — связка + run() entry point
  main.rs      — бинарный entry point
  tests.rs     — юнит-тесты (протокол + хранилище)
```

## Лицензия

MIT — см. [LICENSE](LICENSE).
