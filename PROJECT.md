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
status: research-prototype
version: "Published Client v3.2.1 / Server v3.1.1 (Protocol v3; verified release gates and assets, runtime limits documented)"
updated: 2026-10-14
---

# Impulse — Post-Quantum E2EE LAN Messenger

> **2026-10-09 — Branding validation:** Client PR #1 и Server PR #2 опубликованы, проверки CI кода проходят. Новый знак проверен на launcher, splash и Home отдельного Android API 36 AVD в обеих темах. Защита скриншотов восстановлена; эмулятор выключен. Master и GitHub social preview пока не обновлены. См. [[docs/audit/2026-10-09-brand-live-validation]].

> **2026-10-08 — Identity V18:** общий оптический знак внедрён в launcher/adaptive/themed icons, splash и Home клиента, Windows EXE icon / TUI / Linux packaging сервера и README-шапки обоих репозиториев. Динамические UI-цвета клиента сохранены. Client: 127 tests, assembleDebug/lintDebug; Server: 126 passed / 2 expected ignored, build/clippy. Проверены готовые APK/PE, safe zone и TUI snapshot. 09.10.2026 launcher/splash/Home проверены на Android API 36 AVD, включая светлую/тёмную тему; защита скриншотов восстановлена, эмулятор выключен. См. [[docs/specs/2026-10-08-brand-identity-integration]] и [[docs/audit/2026-10-08-brand-identity-integration]].

> **2026-10-02 — Rust host UI:** палитра cobalt/graphite, исправленная прокрутка с учётом переносов, поиск по фильтрованным логам, видимая полоса прокрутки и восстановление терминала при ошибках. Полный тестовый набор: 126 успешных, 2 намеренно пропущенных клиентских теста. Добавлен реальный loopback WebTransport/QUIC-тест с pinning, auth, heartbeat, opaque relay и replay после переподключения. См. [[docs/specs/2026-10-02-tui-brand-scroll]] и [[docs/audit/2026-10-02-tui-functional-review]]. Динамическая палитра клиента и Wire v3 не менялись.

> **О проекте:** Исследовательский E2EE LAN-мессенджер на WebTransport/QUIC с постквантовыми примитивами. Это не заявление об аппаратной защите, сертификации или готовности к высоконадёжной эксплуатации.
> **Инженерный регламент и видение:** Разработка ведётся в соответствии с [[AI_MANIFESTO|Манифестом AI-Assisted Engineering]], [[docs/VISION|Документом видения (Vision & Roadmap)]] и [[docs/SYSTEM_REGISTRY|Единым каноническим реестром системных параметров]] по строгой методологии **Spec-First** и **Test-Gated**.

---

## 1. Архитектурный обзор

```mermaid
graph TD
    subgraph Client["Android Client (Kotlin 2.0+ / Compose M3)"]
        UI[Jetpack Compose UI] --> VM[ChatViewModel]
        VM --> CC[ChatController]
        CC --> SKM[SecureKeyManager\nML-KEM-768 / Dilithium3]
        CC --> WTC[WebTransportClient\n(socket-http3 over QUIC)]
        CC --> ROOM[(Room DB\nEncrypted At-Rest)]
    end

    subgraph Transport["Сетевой уровень (LAN / WAN, Port 4433 UDP)"]
        WTC <===>|WebTransport / QUIC Bi-directional Stream| WTServer
    end

    subgraph Server["Relay Host (Rust 2024 / Tokio)"]
        WTServer[wtransport QUIC Listener] --> Relay[Relay Core]
        Relay --> Auth[Auth & Argon2id Gate\nOWASP m=47104, t=3, p=1]
        Relay --> Store[(In-Memory Ring Buffer\nTTL 72h, Opaque Ciphertext)]
        Relay --> Registry[User Session Registry]
    end
```

### Текущая граница приватности
- Сервер ретранслирует зашифрованное тело сообщения и не расшифровывает его; внешние поля пакетов, сетевые соединения, время и идентификаторы получателей остаются видимыми.
- Пакеты рассылаются подключённым клиентам, а клиент выбирает подходящие ему записи по идентификатору получателя. Это не обеспечивает сокрытие связей и метаданных.
- Эта граница описывает текущий прототип, а не гарантию Zero-Knowledge/Zero-Metadata или пригодности для высоконадёжной эксплуатации.

### 1.1 Модели взаимодействия: Личные диалоги (1:1) и Групповые чаты (1:N)
Клиент реализует прямую отправку и групповой fan-out по известным ему открытым ключам. Текущая реализация не предоставляет серверную модель членства/маршрутизации групп:
1. **Личные диалоги (1-to-1 Direct E2EE):**
   - Отправитель формирует зашифрованную запись для известного открытого ключа собеседника.
   - Сервер рассылает пакет подключённым клиентам; получатель выбирается клиентской проверкой идентификатора, серверной адресной маршрутизации нет.
2. **Групповые чаты (1-to-N Per-Recipient KEM Wrapping):**
   - Клиент создаёт записи для известных ему ключей; сервер не проверяет членство группы и ретранслирует общий пакет всем подключённым клиентам.
   - Офлайн-пакеты буферизуются в памяти с настроенным TTL 72 часа; это не является гарантией точного удаления в заданный момент или защиты от иных копий/снимков памяти.

---

## 2. Криптографический стек

| Примитив | Алгоритм | Назначение | Параметры / Стандарт |
| :--- | :--- | :--- | :--- |
| **KEM** | **ML-KEM-768** (FIPS 203 / Kyber) | Инкапсуляция общих ключей собеседников | Постквантовая стойкость NIST Категория 3 |
| **Подпись** | **Dilithium3** (Bouncy Castle legacy API) | Цифровая подпись сообщений и аттестация ключей | Не заявляется как ML-DSA-65 / FIPS 204 implementation; проверка подписи обязательна. Переход требует утверждённой protocol SPEC и синхронной миграции. |
| **Симметричное шифрование** | **AES-256-GCM** | Шифрование тела сообщений | 256-битный ключ, уникальный 96-битный IV на каждое сообщение |
| **Хэширование & KDF** | **HKDF-SHA256** | Получение симметричных сессионных ключей из секрета KEM | RFC 5869 |
| **Хэш пароля релея** | **Argon2id** | Защита от перебора пароля сервера | OWASP: $m=47104$ KiB, $t=3$ итерации, $p=1$ параллелизм |
| **Транспортное TLS** | **TLS 1.3 / X25519Kyber768** | Защита QUIC-соединения | Самоподписанные ECDSA P-256 (срок 14 дней, нахлест ротации 4 дня / 96ч) |
| **Верификация времени**| **Clock Skew Tolerance** | Защита от Replay-атак | Окно 4 дня (96ч): покрывает 72ч TTL буфера + 24ч запас на дрейф часов |
| **Буфер сообщений** | **In-Memory Ring Buffer** | Офлайн-доставка без дисковых БД | 1024 пакета в ОЗУ сервера (макс. 10 000 емкость), TTL 72 часа, 0 байт на диске |

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
- **v3.0.0+ (Protocol-Locked SemVer era):** версия протокола обозначается первой цифрой, но это не доказывает совместимость каждой пары релизов. Поддерживаемые пары Client/Server подтверждаются матрицей межверсионных интеграционных проверок.

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
├── server/                    # ХОСТ (Rust 2024 / MSRV 1.88 / Tokio)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── relay/             # Управление сессиями, пользователями, аутентификацией
│   │   ├── protocol/          # Бинарный фрейминг и лимиты пакетов
│   │   ├── storage/           # In-memory кольцевой буфер с TTL 72ч
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
| **C1** | Подмена открытых ключей (Key Substitution / MITM) | **МЕХАНИЗМ РЕАЛИЗОВАН** | Добавлена аттестация Dilithium3 в пакете `0x31 KeyExchangeKemDsa`; поиск по `dsaPublicKey` снижает риск подмены в покрытом проверкой сценарии |
| **C2** | Открытый текст в outbox | **ЗАКРЫТО** | Outbox изолирован по `serverId` и хранит только зашифрованные фреймы; TTL унифицирован до 72ч (с нахлестом ротации сертификатов 4 дня) |
| **C3** | Передача открытого пароля в `OP_AUTH` | **ЗАКРЫТО** | Переход на HMAC-SHA-256 (`0x12 Auth`) по вызову от сервера `0x11 AuthChallenge` с очисткой ключа в памяти |
| **C4** | Повтор сообщений (Replay Attacks) | **РЕАЛИЗОВАНО С ОГРАНИЧЕНИЯМИ** | В Room 6 добавлен долговременный журнал по ключу `sender + SHA-256(nonce)` с атомарным приёмом сообщения и маркера; область защиты — локальное хранилище клиента. Конверты без nonce обходят журнал, исторические строки при миграции не размечаются; универсальная защита от replay не заявляется. `seenNonces` — только LRU-ускоритель. |
| **ANR** | Блокировки UI потока `runBlocking` при отключении | **ЗАКРЫТО** | Переход на неблокирующие корутины `Dispatchers.IO + NonCancellable`, дешифрование на `Dispatchers.Default` |
| **ID** | Коллизии временных ID сообщений | **ЗАКРЫТО** | Внедрен монотонный потокобезопасный счётчик `AtomicLong` |
| **N2** | Рассинхрон лимита полезной нагрузки | **ЗАКРЫТО** | Строго зафиксирован `MAX_PAYLOAD_BYTES = 1_000_000` байт в обоих проектах |
| **PERF-DB** | Замедление запросов истории при росте БД | **ЗАКРЫТО** | Добавлены индексы `(server_id, conversation_id)` и `timestamp` (Room v5) |
| **SEC-BCK** | Защита резервного экспорта ключей | **ЗАКРЫТО** | Экспорт/backup v4 использует Argon2id `m=47104, t=3, p=1` в `SecureKeyManager.kt`. Импорт старых форматов v1–v3 сохраняет PBKDF2-HMAC-SHA256 (600 000 итераций) для совместимости. |
| **NET-LAN** | Сбои в изолированных офлайн-сетях LAN | **ЗАКРЫТО** | Удалено требование валидированного Интернет-подключения в `NetworkMonitor.kt` |
| **BUILD-CI**| Сбои KAPT, 16 KB native alignment и CI подписи APK | **ЗАКРЫТО** | Стабилизация KAPT, автоматический 16KB ELF-пайплайн, гибкая сборка подписанных/неподписанных APK в GitHub Actions |
| **SEC-SCR** | Утечка данных через скриншоты ОС и переключатель задач | **ЗАКРЫТО** | Добавлен `FLAG_SECURE` по умолчанию с конфигурируемым тумблером в настройках (`AppSettingsScreen.kt`, `UserSettingsScreen.kt`) |
| **SEC-BIO** | Ложное чувство безопасности биометрии при слабом пароле | **ОГРАНИЧЕННАЯ UI-мера** | Есть предупреждение и экранная блокировка системной биометрией. Это не криптографическая привязка к мастер-паролю; такая привязка не заявляется как реализованная. |
| **UI-SCRIM**| Наслоение и прозрачность меню при открытии QR-сканера | **ЗАКРЫТО** | Устранена прозрачность оверлея в `QrScanScreen.kt`, диалоги унифицированы под `CardShape` + `surfaceContainerHigh` + затемнение фона |
| **NET-AGNOSTIC**| Непонимание сетевой независимости архитектуры | **ЗАКРЫТО** | Формализована IP-агностичная модель: полная LAN-суверенность без внешних серверов + поддержка глобального WAN/VPN (`docs/SYSTEM_REGISTRY.md`) |
| **PROD-AUDIT** | Историческая проверка кода и тестов на 2026-09-26 | **ВЫПОЛНЕНА** | В отчёте зафиксированы тогдашние 228 тестов и указанные проверки; это не независимый криптографический аудит, сертификация или подтверждение готовности к высоконадёжной эксплуатации (`docs/audit/2026-09-26-production-readiness-audit.md`) |
| **NET-DUALSTACK**| Переход на универсальный транспорт (IPv4/IPv6 Dual-Stack) | **ЗАКРЫТО** | Dual-Stack сокеты `[::]:4433` (Quinn/Tokio) с fallback на `0.0.0.0`, парсер RFC 3986 (IPv4, `[IPv6]`, link-local, mDNS), 234+ тестов (`docs/specs/2026-09-26-universal-transport-dual-stack.md`) |

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
# JAVA_HOME указывает на установленный JDK 21, как в CI
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
.\gradlew.bat testDebugUnitTest
.\gradlew.bat assembleDebug
```

## Проверка перед защитой 14 октября 2026

Текущий итог и границы проверки: [отчёт аудита](docs/audit/2026-10-14-defense-readiness.md). Все изменения перечислены отдельно в [реестре изменений](docs/audit/2026-10-14-change-register.md). Исправления сохраняют Wire v3 и криптографические минимумы; производственная готовность не заявляется по одному локальному прогону. Школьные DOCX и видео сохранены, сопоставление вынесено в отдельный отчёт.
