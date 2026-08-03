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
(Per-Recipient KEM Wrapping, ML-KEM-768 + AES-256-GCM) и передают серверу только
непрозрачные байты, идентификатор последовательности, временную метку и
публичный ключ для каждого сообщения. Сообщения хранятся в RAM (TTL 72 ч),
идентификаторы монотонны, рассылка идёт всем подключённым клиентам.

Ключевые архитектурные решения:

- **Транспорт:** только WebTransport поверх QUIC (`wtransport` 0.7), TLS 1.3 обязателен.
- **Протокол:** length-prefixed бинарные фреймы, опкоды `0x01`–`0x0C`, little-endian.
- **Аутентификация:** `AuthChallenge` (0x0B) с 16-байтным nonce и Argon2id-солью →
  клиент отвечает HMAC-SHA-256 (`Auth`, 0x01) → проверка в constant time.
- **TLS / Сертификаты:** самоподписанные **ECDSA P-256**, срок **14 дней**,
  автоматическая ротация с **2-дневным окном перекрытия**. PEM сохраняется с
  правами `0600` (Unix) / эксклюзивным DACL (Windows).
- **TOFU:** QR-код с `impulse-cert:<sha256>`; клиенты закрепляют
  `serverCertificateHashes`. Ротация анонсируется через `NewCertHash` (0x07).
- **Хранилище:** in-RAM ring buffer, TTL 72 ч, ограничение `10_000` сообщений и
  `1 MB` на сообщение.
- **Relay:** broadcast + догонка через `Sync { last_seen_id }` (≤ 2000 сообщений);
  ключевые обмены replay'ятся новым клиентам.
- **Администрирование:** адаптивная **трёхколоночная TUI** — Info/QR/Cert |
  Users + Sessions | Logs — с живой статистикой пользователей, фильтрами логов,
  поиском и фокусом на QR.

## Сборка и запуск

```bash
cargo build --release
./target/release/Impulse-server
```

При первом запуске (нет `config.toml`, нет `--password-hash`) сервер
интерактивно запрашивает пароль клиента, записывает минимальный `config.toml`
и стартует. Для явной настройки:

```bash
./target/release/Impulse-server --init
```

`--init` запрашивает пароль и, опционально, адрес привязки, каталог
сертификатов и дополнительные SAN, затем записывает `config.toml` (`--force`
перезаписывает). В средах без терминала (systemd, Docker) хэш пароля нужно
настроить заранее — сервер отказывается стартовать без него:

```bash
./target/release/Impulse-server --hash-password yourpassword
```

CLI-флаги всегда переопределяют конфиг; `--license` выводит текст лицензии MIT.

| Флаг | Короткий | Описание | По умолчанию |
|------|----------|----------|-------------|
| `--host` | | Хост для привязки (переопределяет `server.address`) | из конфига / `0.0.0.0` |
| `--port` | `-p` | Порт WebTransport (QUIC) | из конфига / `4433` |
| `--cert-dir` | | Каталог для генерируемых сертификата/ключа | `cert_data` |
| `--san` | | Дополнительный SAN (DNS или IP) для самоподписанного сертификата (повторяемый) | _нет_ |
| `--password-hash` | | Argon2id хэш пароля клиента (обязателен) | _нет_ |
| `--config` | | Путь к TOML-конфигу; авто-поиск `config.toml` в рабочем каталоге, затем рядом с исполняемым файлом | авто-поиск |
| `--init` | | Интерактивно создать `config.toml` (пароль, адрес, SAN), затем выйти | _нет_ |
| `--force` | | Перезаписать существующий `config.toml` при использовании с `--init` | _нет_ |
| `--license` | | Вывести текст лицензии MIT и выйти | _нет_ |

`password_hash` **обязателен** — небезопасного значения по умолчанию нет.
Настройте его через `--init`, `--password-hash <hash>` или
`server.password_hash` в `config.toml`.

## Продакшен-развёртывание

### Требования

- **Rust 1.85+** (edition 2024) для сборки из исходников.
- **Доступный по UDP** порт (QUIC работает поверх UDP). Откройте/пробросьте его
  в фаерволе / security groups.
- **Root/administrator НЕ требуется** — используйте высокий порт (например,
  `4433`) вместо `443`. QR/TOFU-поток позволяет доверять самоподписанному
  сертификату, поэтому публичный CA не нужен.

Запускайте с `RUST_LOG=info` (или `warn`), чтобы избежать I/O от hex-дампа
debug-уровня; фильтр применяется и к потоку логов в TUI. Rolling-логи пишутся в
`logs/` (суточная ротация, retention 7 дней).

```bash
RUST_LOG=info ./target/release/Impulse-server --config config.toml
```

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

## Платформы и загрузка

Impulse-server написан на переносимом Rust (edition 2024). CI собирает релизные
бинарники и `.deb`/`.rpm` пакеты для целей ниже на каждом теге релиза.

| Платформа | Target triple | Статус | Примечания |
|-----------|---------------|--------|------------|
| Linux (x86-64) | `x86_64-unknown-linux-gnu` | ✅ CI tested | Рекомендуется для серверов |
| Linux (ARM64) | `aarch64-unknown-linux-gnu` | ✅ CI tested (cross) | AWS Graviton, Raspberry Pi 4 (64-bit OS) |
| Linux (ARMv7) | `armv7-unknown-linux-gnueabihf` | ✅ CI tested (cross) | Raspberry Pi 2/3, 32-bit OS |
| Linux (RISC-V 64) | `riscv64gc-unknown-linux-gnu` | ✅ CI tested (cross) | VisionFive 2 |
| Windows (x86-64) | `x86_64-pc-windows-msvc` | ✅ CI tested | Консольное приложение, бинд на UDP/QUIC |
| Windows (ARM64) | `aarch64-pc-windows-msvc` | ✅ CI tested | Устройства на Windows on ARM |
| FreeBSD / BSD | `x86_64-unknown-freebsd` | ⚠️ Manual only | У `aws-lc-sys` нет FreeBSD sysroot для кросса; нужен нативный тулчейн |

Готовые бинарники для всех ✅/⚠️ строк (кроме FreeBSD) прикреплены к каждому
GitHub Release; `.deb`/`.rpm` пакеты собираются для Linux x86-64 и ARM64.
Артефакты следуют схеме `ImpulseServer-<версия>-<os>-<arch>.<ext>`, например
`ImpulseServer-2.7.2-linux-amd64.tar.gz` или
`ImpulseServer-2.7.2-windows-arm64.zip`. Архивы содержат только бинарник и
`LICENSE` — конфиг создаётся при первом запуске или через `--init`.

## Протокол (бинарный, little-endian)

Все фреймы: `[opcode: u8][...поля]`. Length-prefixed блобы — `u32 len` затем `len` байт.

| Opcode | Напр. | Имя | Поля |
|--------|-------|-----|------|
| `0x01` | C→S | Auth | `u32 LE pwd_len`, `pwd_len` байт пароля (UTF-8), 32 сырых байта HMAC-SHA-256 |
| `0x0B` | S→C | AuthChallenge | 16 байт nonce + `u32 LE salt_len`, `salt_len` байт B64 Argon2id соли |
| `0x02` | S→C | AuthResult | `u8` статус (`0`=ok, `1`=fail) + опциональный `len`-prefixed текст |
| `0x03` | C→S | Sync | `u64` last_seen_id |
| `0x04` | S→C | SyncResponse | `u32` count, затем для каждого сообщения: `u64 id`, `u64 ts`, `len`-prefixed payload |
| `0x05` | C→S / S→C | Data | C→S: `len`-prefixed payload. S→C: `u64 id`, `u64 ts`, `len`-prefixed payload |
| `0x06` | обе | Heartbeat | `u64` client_timestamp (эхо-ответ) |
| `0x07` | S→C | NewCertHash | ровно 32 сырых байта SHA-256 + `u64` unix expiry |
| `0x08` | обе | Disconnect | без payload (корректное закрытие с любой стороны) |
| `0x0C` | C→S / S→C | KeyExchangeKemDsa | комбинированный ML-KEM + ML-DSA-65 публичные ключи (ретранслируется атомарно) |

Неизвестные/невалидные опкоды от клиента закрывают соединение. Простаивающие
стримы закрываются через 300 с. Сессии лимитированы 1024 (уникальные
`AtomicU64` id); агрегатный буфер ограничен 512 МБ; полезные нагрузки более
1 MB отбрасываются; один `Sync` возвращает не более 2000 сообщений. Парсер
валидирует заявленную длину пакета против лимита в 1 MB до любой аллокации,
предотвращая CPU-DoS через раздутые length-префиксы.

## Безопасность

- Обязательный QUIC/TLS 1.3 транспорт (WebTransport).
- Краткоживущие ECDSA P-256 сертификаты (14 дн.) с автоматической ротацией
  (2 дн. перекрытие), применяемой к **рабочему** TLS resolver'у без рестарта и
  анонсируемой через `NewCertHash`.
- TOFU pinning отпечатка через QR-код + `NewCertHash`.
- Гибридный постквантовый обмен ключами (X25519Kyber768) через `aws-lc-rs`.
- **Blind relay** — сервер никогда не расшифровывает полезные нагрузки; он видит
  только непрозрачные байты.
- Эфемерное RAM-only хранилище, TTL 72 ч, ограниченный ring buffer и размер payload.
- Пароли хранятся как Argon2id-хэши; сравнение HMAC в constant time.
- Per-IP rate limiting (10 соединений / 10 с) и лимит сессий против DoS.
- Неактивные сессии закрываются через 300 с.
- Файл приватного ключа `0600` на Unix; эксклюзивный DACL на Windows.
- Открытый текст, пароли и полезные нагрузки не логируются.

## Корректное завершение работы

`Ctrl+C` / `SIGTERM` (или `q` в TUI) останавливает приём новых сессий и
дренирует активных writer'ов. Логи ротируются ежедневно в `logs/` с retention
7 дней.

## Структура проекта

```
src/
  cert/        — генерация ECDSA P-256 сертификатов, ротация, TOFU отпечаток, FS персист
  storage/     — эфемерный in-RAM лог сообщений (TTL 72ч, sequence ids)
  protocol.rs  — бинарные wire-фреймы; framing/limits находятся в protocol/
  relay/       — WebTransport эндпойнт, обработка сессий, auth и broadcast relay
  ui/          — терминальный UI: панели Server/Users/Sessions, логи, TOFU QR и live stats
  logging/     — мост tracing → TUI / rolling-файл
  config/      — разбор CLI и загрузка config.toml
  cli/         — first-run и --init wizard'ы, запись конфига
  lib.rs       — связка + run() entry point
  main.rs      — бинарный entry point
tests/         — интеграционные тесты (handshake, relay, config, storage)
```

## Лицензия

MIT — см. [LICENSE](LICENSE).
