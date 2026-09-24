---
title: "Impulse — Post-Quantum Secure E2EE LAN Messenger"
tags:
  - impulse
  - post-quantum
  - cryptography
  - rust
  - kotlin
  - android
  - webtransport
  - quic
status: production-ready-hardening
version: "Client v3.1.2 / Server v3.0.0 (Protocol v3)"
updated: 2026-09-14
---

# Impulse — Post-Quantum E2EE LAN Messenger

> **О проекте:** Децентрализованный сквозно-шифрованный LAN-мессенджер на базе протокола WebTransport (QUIC) с аппаратной устойчивостью к квантовым компьютерам.  
> **Инженерный регламент и видение:** Разработка ведётся в соответствии с [[AI_MANIFESTO|Манифестом AI-Assisted Engineering]], [[docs/VISION|Документом видения (Vision & Roadmap)]] и [[docs/SYSTEM_REGISTRY|Единым реестром системных параметров]] по строгой методологии **Spec-First** и **Test-Gated**.

---

## 1. Архитектурный обзор

```mermaid
graph TD
    subgraph Client["Android Client (Kotlin 2.0+ / Compose M3)"]
        UI[Jetpack Compose UI] --> VM[ChatViewModel]
        VM --> CC[ChatController / AppContainer]
        CC --> SKM[SecureKeyManager\nML-KEM-768 / ML-DSA-65]
        CC --> ME[MessageEncryptor\nAES-256-GCM]
        CC --> MD[MessageDecryptor\nSig Verification & Replay Cache]
        CC --> WTC[WebTransportClient\n(socket-http3 over QUIC)]
        CC --> ROOM[(Room DB\nEncrypted At-Rest)]
    end

    subgraph Transport["Сетевой уровень (LAN, Port 4433 UDP)"]
        WTC <===>|WebTransport / QUIC Bi-directional Stream| WTServer
    end

    subgraph Server["Relay Host (Rust 2024 / Tokio)"]
        WTServer[wtransport QUIC Listener] --> Relay[Relay Core]
        Relay --> Auth[Auth & Argon2id Gate\nOWASP m=47104, t=3, p=1]
        Relay --> Store[(In-Memory Ring Buffer\nTTL 72h, Opaque Ciphertext)]
        Relay --> Registry[User Session Registry]
    end
```

### Главный инвариант безопасности (Zero-Knowledge Relay)
- Сервер является **100% непрозрачным релеем (Opaque Relay)**.
- Сервер **никогда** не расшифровывает, не парсит и не логирует полезную нагрузку сообщений.
- Вся метаинформация (отправитель, получатель, временная метка клиента, одноразовый номер `nonce`, подпись ML-DSA-65) запечатана внутри зашифрованного конверта полезной нагрузки фрейма `0x32 Data`.

---

## 2. Криптографический стек

| Примитив | Алгоритм | Назначение | Параметры / Стандарт |
| :--- | :--- | :--- | :--- |
| **KEM** | **ML-KEM-768** (FIPS 203 / Kyber) | Инкапсуляция общих ключей собеседников | Постквантовая стойкость NIST Категория 3 |
| **DSA** | **ML-DSA-65** (FIPS 204 / Dilithium) | Цифровая подпись сообщений и аттестация ключей | Постквантовая стойкость, обязательная проверка перед показом |
| **Симметричное шифрование** | **AES-256-GCM** | Шифрование тела сообщений | 256-битный ключ, уникальный 96-битный IV на каждое сообщение |
| **Хэширование & KDF** | **HKDF-SHA256** | Получение симметричных сессионных ключей из секрета KEM | RFC 5869 |
| **Хэш пароля релея** | **Argon2id** | Защита от перебора пароля сервера | OWASP: $m=47104$ KiB, $t=3$ итерации, $p=1$ параллелизм |
| **Транспортное TLS** | **TLS 1.3 / X25519Kyber768** | Защита QUIC-соединения | Самоподписанные сертификаты с TOFU и ротацией хешей |

---

## 3. Спецификация Wire-протокола (WebTransport Streams)

Все целочисленные поля передаются в формате **Little-Endian**.
Опкоды иерархически структурированы по доменам: старший полубайт определяет категорию (`0x1_` Auth, `0x2_` Session, `0x3_` Data & Relay), младший — действие. На wire-уровне размер опкода строго 1 байт.

| Опкод | Домен | Название | Направление | Формат полезной нагрузки |
| :---: | :---: | :--- | :---: | :--- |
| `0x11` | Auth | **AuthChallenge** | Server $\rightarrow$ Client | `[16 bytes nonce][u32 salt_len][salt_bytes][u32 params_len][params_tag]` |
| `0x12` | Auth | **Auth** | Client $\rightarrow$ Server | `[u32 hmac_len=32][32 bytes HMAC-SHA-256(Argon2id(pw), nonce)]` |
| `0x13` | Auth | **AuthResult** | Server $\rightarrow$ Client | `[u8 status: 0x01=OK, 0x00=FAIL][u32 err_len][optional err_msg]` |
| `0x21` | Session | **Heartbeat** | Оба | `[u64 client_timestamp]` |
| `0x22` | Session | **NewCertHash** | Server $\rightarrow$ Client | `[32 bytes raw SHA-256][u64 expiry_ts]` |
| `0x23` | Session | **Disconnect** | Оба | _Без полезной нагрузки (0 байт)_ |
| `0x31` | Data | **KeyExchangeKemDsa** | Оба | `[u32 total_len][u32 kem_len][kem_pub][u32 dsa_len][dsa_pub][u32 sig_len][sig]` |
| `0x32` | Data | **Data** | Client $\rightarrow$ Server<br>Server $\rightarrow$ Client | Client: `[u32 len][per_recipient_ciphertext_blob]`<br>Server: `[u64 id][u64 server_ts][u32 len][payload_bytes]` |
| `0x33` | Data | **Sync** | Client $\rightarrow$ Server | `[u64 last_seen_server_id]` |
| `0x34` | Data | **SyncResponse** | Server $\rightarrow$ Client | `[u32 count] { [u64 id][u64 server_ts][u32 len][payload_bytes] }*` |

### Историческая эволюция версий и совместимости
- **v0.x.y (Legacy WS):** Начальный прототип на базе незашифрованных WebSocket (`ws://`).
- **v1.x.y (Legacy WSS):** Переписывание транспорта на WebSocket Secure (`wss://`) с шифрованием канала TLS.
- **v2.x.y (Transitional WebTransport):** Переход на WebTransport (QUIC / UDP 4433). Активные эксперименты с E2EE и постквантовыми примитивами ML-KEM/ML-DSA. Из-за динамичной эволюции архитектуры совместимость между промежуточными сборками v2.x не всегда была взаимной (клиент развился до v2.9.x, сервер — до v2.7.x).
- **v3.0.0+ (Protocol-Locked SemVer Era):** Старт новой эры со строгой сетевой совместимостью. Первая цифра (3) фиксирует неизменный бинарный Wire-протокол. Любой клиент `v3.x` на 100% совместим с любым сервером `v3.y`.

---

## 4. Структура репозиториев

```
D:\Data\Projects\ImpulseProject\
├── AGENTS.md                  # Главный регламент и роли для AI-агентов
├── AI_MANIFESTO.md            # Манифест инженерной прозрачности разработки
├── PROJECT.md                 # Этот сводный файл проекта (Obsidian Vault)
├── docs/
│   ├── VISION.md              # Документ видения, стандарты UI и Roadmap
│   ├── policies/              # Политики безопасности, релизов и деплоя
│   ├── specs/                 # Спецификации функционала (Spec-First)
│   └── audit/                 # Отчёты аудита безопасности и архитектуры
├── scripts/
│   ├── check-environment.ps1  # Экспресс-проверка тулчейна (Rust, JDK, SDK)
│   └── setup-toolchain.ps1    # Скрипт быстрой установки недостающих утилит
├── server/                    # ХОСТ (Rust 2024 / MSRV 1.85 / Tokio)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── relay/             # Управление сессиями, пользователями, аутентификацией
│   │   ├── protocol/          # Бинарный фрейминг и лимиты пакетов
│   │   ├── storage/           # In-memory кольцевой буфер с TTL 24ч
│   │   ├── crypto/            # Argon2id и ротация TLS-сертификатов
│   │   └── ui/                # Консольный терминальный интерфейс (Ratatui TUI)
│   └── tests/                 # Интеграционные тесты и симуляции атак
└── client/                    # КЛИЕНТ (Android / Kotlin 2.0+ / Compose M3)
    ├── app/build.gradle.kts
    └── app/src/main/java/com/example/impulse/
        ├── ChatController.kt  # Главный фасад и координатор чата
        ├── transport/         # WebTransportClient и Protocol.kt
        ├── security/          # PqcCrypto (ML-KEM/DSA), SecureKeyManager, KeyStore
        ├── data/db/           # Room DB (MessageEntity, PublicKeyEntity)
        └── ui/                # Jetpack Compose экраны (M3 Expressive)
```

---

## 5. Статус безопасности и аудит (Матрица исправлений)

| ID | Уязвимость / Узкое место | Статус | Реализация |
| :---: | :--- | :---: | :--- |
| **C1** | Подмена открытых ключей (Key Substitution / MITM) | **ЗАКРЫТО** | Добавлена аттестация ML-DSA-65 в пакете `0x31 KeyExchangeKemDsa`; поиск по `dsaPublicKey` исключает обход TOFU |
| **C2** | Открытый текст в outbox | **ЗАКРЫТО** | Outbox изолирован по `serverId` и хранит только зашифрованные фреймы; TTL унифицирован до 72ч (с нахлестом ротации сертификатов 4 дня) |
| **C3** | Передача открытого пароля в `OP_AUTH` | **ЗАКРЫТО** | Переход на HMAC-SHA-256 (`0x12 Auth`) по вызову от сервера `0x11 AuthChallenge` с очисткой ключа в памяти |
| **C4** | Повтор сообщений (Replay Attacks) | **ЗАКРЫТО** | Добавлен LRU-кэш `seenNonces` в `ChatController.kt` и верификация skew времени (4 дня / 96ч) |
| **ANR** | Блокировки UI потока `runBlocking` при отключении | **ЗАКРЫТО** | Переход на неблокирующие корутины `Dispatchers.IO + NonCancellable`, дешифрование на `Dispatchers.Default` |
| **ID** | Коллизии временных ID сообщений | **ЗАКРЫТО** | Внедрен монотонный потокобезопасный счётчик `AtomicLong` |
| **N2** | Рассинхрон лимита полезной нагрузки | **ЗАКРЫТО** | Строго зафиксирован `MAX_PAYLOAD_BYTES = 1_000_000` байт в обоих проектах |
| **PERF-DB** | Замедление запросов истории при росте БД | **ЗАКРЫТО** | Добавлены индексы `(server_id, conversation_id)` и `timestamp` (Room v5) |
| **SEC-BCK** | Использование PBKDF2 в резервных копиях ключей | **ЗАКРЫТО** | Переход на Argon2id v4 ($m=47104, t=3, p=1$) в `SecureKeyManager.kt` |
| **NET-LAN** | Сбои в изолированных офлайн-сетях LAN | **ЗАКРЫТО** | Удалено требование валидированного Интернет-подключения в `NetworkMonitor.kt` |
| **BUILD-CI**| Сбои KAPT, 16 KB native alignment и CI подписи APK | **ЗАКРЫТО** | Стабилизация KAPT, автоматический 16KB ELF-пайплайн, гибкая сборка подписанных/неподписанных APK в GitHub Actions |

---

## 6. Команды для локальной сборки и тестирования

### Проверка тулчейна:
```powershell
.\scripts\check-environment.ps1
```

### Сборка и тесты сервера (Rust):
```powershell
cd server
cargo check
cargo test
cargo clippy -- -D warnings
```

### Сборка и тесты клиента (Android):
```powershell
cd client
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot"
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
.\gradlew.bat testDebugUnitTest
.\gradlew.bat assembleDebug
```
