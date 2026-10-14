# SYSTEM_REGISTRY.md — Единый канонический реестр системных параметров и контекста

> **Статус документа:** ДЕЙСТВУЮЩИЙ КАНОН И ЕДИНЫЙ ИСТОЧНИК ИСТИНЫ (SINGLE SOURCE OF TRUTH)
> **Версия реестра:** 1.0.0
> **Дата актуализации:** 2026-10-14
> **Связанные документы:** `PROJECT.md`, `AGENTS.md`, `docs/VISION.md`. Учебные документы являются отдельными публикационными материалами и могут отставать от текущего кода.

Настоящий реестр фиксирует все сквозные константы, параметры безопасности, сетевые лимиты и метаданные проекта **Impulse**. Любое изменение значения в коде, спецификациях или сопроводительной документации **обязано** производиться синхронно по всей матрице трассировки данного реестра.

---

## 1. Паспорт автора и учебного проекта

| Параметр | Каноническое значение | Файлы упоминания | Примечания |
| :--- | :--- | :--- | :--- |
| **Автор** | Окунев Михаил Александрович | Все docx и md школьного проекта | Автор и разработчик архитектуры |
| **Класс** | **11 класс** (XI класс) | `school-project/Проект.docx`, `school-project/Сценарий_и_Шпора_Импульс.docx`, `school-project/Тезисы_Импульс.docx`, `school-project/СЦЕНАРИЙ_И_ШПОРА_К_ЗАЩИТЕ.md` | Строго 11 класс (не 10-й) |
| **Учебный год** | **2026–2027 учебный год** | `school-project/Проект.docx` (титул) | Текущий период защиты выпускной работы |
| **Учреждение** | МБОУ БГО «Борисоглебская гимназия № 1» | `school-project/Проект.docx`, `school-project/Сценарий_и_Шпора_Импульс.docx` | Городской округ Борисоглебск |
| **Руководитель** | Степаненко Ольга Владимировна | Все титульные листы и паспорта | Учитель информатики |

### 1.1. Toolchain

| Компонент | Минимальная версия | Примечание |
| :--- | :--- | :--- |
| **Server Rust MSRV** | **1.88** (edition 2024) | `server/Cargo.toml` задаёт `rust-version = "1.88"`; более старый бейдж/образ сборки не является поддерживаемой версией. |

---

## 2. Временные параметры, TTL и окна перекрытия

Android ограничивает установление WebTransport соединения 15 секундами с отменой
setup coroutine. Действующая сессия не имеет фиксированного 300-секундного срока:
timeout scope библиотеки отключён, а read-idle ограничен 90 секундами, QUIC idle —
120 секундами, keepalive — 15 секундами. Пользовательский disconnect и lifecycle
по-прежнему закрывают сессию. Поля/методы: `WebTransportClient.startConnectTimeout`,
`withHttp3Connection`, `runReadLoop`; SPEC `2026-10-14-webtransport-session-lifetime.md`.

Sync и live broadcast могут перемежаться; порядок listener callbacks не является
глобальным порядком relay-ID. История сортируется по ID в DAO и времени в UI.
TTL задаёт максимальный возраст, а count/byte caps могут вытеснить backlog раньше.

| Параметр | Каноническое значение | Физический смысл | Точные места в коде и документации |
| :--- | :--- | :--- | :--- |
| **Message TTL (Сервер)** | **72 часа** (3 суток)<br>`Duration::from_secs(60 * 60 * 72)` | Время удержания зашифрованных сообщений в оперативной памяти (In-RAM Ring Buffer) для доставки офлайн-клиентам. | • `server/src/storage/mod.rs:20` (`MESSAGE_TTL`)<br>• `server/src/storage/mod.rs:177` (unit test)<br>• `server/tests/exploits.rs:254`<br>• `server/src/lib.rs:6`<br>• `server/README.md:32, 43, 56, 275, 292`<br>• `PROJECT.md:45, 137`<br>• `school-project/Проект.docx:p73` |
| **Message TTL (Клиент)** | **72 часа** (3 суток)<br>`const val TTL_HOURS = 72L` | Период локального хранения зашифрованных сообщений в базе Room до очистки просроченных записей (`purgeExpired`). Это не гарантия физического стирания носителя или отсутствия иных копий. | • `client/app/src/main/java/com/example/impulse/data/MessageRepository.kt:72`<br>• `client/app/src/main/java/com/example/impulse/data/db/MessageDatabase.kt:91`<br>• `client/app/src/main/java/com/example/impulse/data/db/MessageEntity.kt:17`<br>• `client/README.md:33, 42, 125`<br>• `client/README.ru.md:33, 42, 125` |
| **Room Replay Journal** | **DB v6**, до **250 000** живых маркеров | Долговременный fail-closed журнал повторов. Freshness окна подписанного времени: ±96 ч; маркер хранится 96 ч после более поздней из точек принятия и signed timestamp, поэтому допустимый timestamp из будущего может дать удержание почти **192 ч от приёма**. При достижении ёмкости новая nonce-bearing запись отклоняется; существующие маркеры не вытесняются. | • `client/app/src/main/java/com/example/impulse/data/db/MessageDatabase.kt` (`version = 6`)<br>• `client/app/src/main/java/com/example/impulse/data/ReplayNonce.kt`<br>• `client/app/src/main/java/com/example/impulse/data/db/MessageDao.kt` |
| **Replay Key Scope** | `(sender fingerprint, SHA-256(nonce))` — глобально для локальной БД устройства | В `seen_nonces` нет `server_id`: один и тот же sender/nonce считается повтором между серверами. Сырые nonce не сохраняются. Пустой nonce не получает durable replay marker; `clientTs = 0` сохраняет legacy-путь без проверки freshness. Это известный legacy gap, а не replay-гарантия для старых конвертов. | • `client/app/src/main/java/com/example/impulse/data/db/SeenMessageNonceEntity.kt`<br>• `client/app/src/main/java/com/example/impulse/ChatController.kt` (`verifyFreshAndPersist`) |
| **Certificate Overlap** | **4 дня** (96 часов)<br>`Duration::from_secs(60 * 60 * 24 * 4)` | Окно перекрытия при ротации сертификата хоста. Новый сертификат создается за 4 дня до истечения старого, оба активны одновременно. Полностью покрывает 3-дневный офлайн TTL. | • `server/src/cert/mod.rs:36` (`CERT_OVERLAP`)<br>• `server/src/cert/mod.rs:39` (`ROTATE_BEFORE_EXPIRY`)<br>• `server/src/lib.rs:5`<br>• `server/README.md:31, 52, 270`<br>• `PROJECT.md:137` |
| **Certificate Lifetime** | **14 дней**<br>`Duration::from_secs(60 * 60 * 24 * 14)` | Полный срок действия выпускаемого сервером самоподписанного TLS-сертификата ECDSA P-256. | • `server/src/cert/mod.rs:32` (`CERT_VALIDITY`)<br>• `server/src/lib.rs:4`<br>• `server/README.md:31, 51, 270` |
| **Clock Skew Tolerance** | **4 дня** (96 часов)<br>`4 * 24 * 3600 * 1000L` | Допустимое отклонение времени клиента при верификации подписи сообщения. Включает 72ч TTL + 24ч запас на дрейф часов. | • `client/app/src/main/java/com/example/impulse/ChatController.kt:899`<br>• `PROJECT.md:139` |

---

## 3. Сетевые лимиты и защита от DoS

| Константа | Значение | Назначение | Файлы кода |
| :--- | :--- | :--- | :--- |
| **`MAX_PAYLOAD_BYTES`** | `1_000_000` байт (1 МБ) | Верхний предел тела любого пакета. Защита от OOM при раздутых длинах. | • `server/src/protocol/limits.rs:4`<br>• `client/app/src/main/java/com/example/impulse/transport/Protocol.kt:50` |
| **MessageStore count** | `10_000` сообщений | Количественный предел RAM ring buffer. | • `server/src/storage/mod.rs` (`MAX_MESSAGES`) |
| **MessageStore payload bytes** | **64 MiB** | Суммарный бюджет retained payload bytes; не включает overhead `Vec`, записей и runtime. Вместе с count cap и TTL 72 ч ограничивает хранилище. | • `server/src/storage/mod.rs` (`MAX_STORE_BYTES`) |
| **`MAX_STREAM_BUFFER`** | **8 MiB на сессию** | Предел незавершённого входящего фрейм-буфера сессии. | • `server/src/protocol/limits.rs` |
| **`MAX_TOTAL_BUFFERED_BYTES`** | **512 MiB** | Общий budget входящих reader buffers всех сессий; это не hard cap всей памяти процесса или QUIC runtime. | • `server/src/protocol/limits.rs` |
| **Sessions / IP rate** | **1024** сессии; **10** новых соединений на IP за **10 с** | Ограничения admission, дополненные тайм-аутами handshake/auth/idle. | • `server/src/relay/mod.rs` |
| **Session deadlines** | stream **15 с**, auth **30 с абсолютный**, idle **300 с** | `accept_bi` и challenge/auth processing bounded; auth deadline прекращает действовать после успешной аутентификации, затем применяется idle timeout. | • `server/src/relay/mod.rs`<br>• `server/src/relay/session.rs` |
| **Auth attempts** | **5** попыток на сессию; challenge nonce до **30 с** | HMAC mismatch/invalid response отклоняется; сессия не может продлевать абсолютный unauthenticated deadline трафиком. | • `server/src/relay/mod.rs` (`NONCE_MAX_AGE`, `MAX_AUTH_ATTEMPTS`)<br>• `server/src/relay/auth.rs` |
| **Sync admission / frames** | **16** concurrent Sync; **499** сообщений и **4 MiB** на response frame; **16** buffered/writing frames | Frame permits удерживаются до write/flush/drop: не более 64 MiB encoded Sync frames в приложении. Sync operation и write/flush ограничены **30 с**; оценка application working set до ~128 MiB с transient pages/copies, без transport/runtime overhead. | • `server/src/relay/mod.rs`<br>• `server/src/protocol/limits.rs`<br>• `server/src/relay/session.rs` |
| **Key-exchange replay cache** | **16** пакетов / **64 KiB** на сессию | Старейшие записи вытесняются; кеш удаляется при disconnect. | • `server/src/relay/mod.rs` |
| **Client pending-key queue** | **128** всего, **16** на sender key, **8 MiB**, **30 с** | Временный in-memory queue для сообщений, ожидающих неизвестный sender key; по expiry или превышению capacity новые сообщения отклоняются. | • `client/app/src/main/java/com/example/impulse/PendingMessageBuffer.kt` |
| **Client inbound stream accumulator** | **8 MiB** | Максимум накопленных байтов незавершённого/ожидающего разбора входящего потока; при превышении клиент сбрасывает accumulator и закрывает соединение. Это отдельный лимит от pending-key queue. | • `client/app/src/main/java/com/example/impulse/transport/WebTransportClient.kt` (`handleInboundChunk`) |
| **`seenNonces` memory cache** | **2000** записей | Вспомогательный process-local dedup cache; долговременная защита задаётся Room Replay Journal выше. | • `client/app/src/main/java/com/example/impulse/ChatController.kt` |
| **Default Port** | `4433 UDP` | Сетевой порт WebTransport (QUIC). | • `server/src/config/mod.rs`<br>• `client/app/src/main/java/com/example/impulse/transport/WebTransportClient.kt` |

### 3.1. Сетевая архитектура: IP-Agnostic Reachability vs LAN-суверенность

> **Текущая граница:** клиент и сервер используют WebTransport/QUIC поверх UDP. Подключение зависит от доступной IP-связности и корректной маршрутизации между клиентом и самостоятельно развёрнутым хостом. В локальной сети может работать без внешнего интернета и сторонних серверов. Это не гарантия работы поверх любой сети или сокрытия сетевых метаданных.

* **Работа через глобальный Интернет (WAN / Internet):**
  Возможна при доступности хоста по адресу и UDP-порту 4433, корректной маршрутизации и разрешении трафика сетевой политикой. Универсальная доступность из любой сети не гарантируется.
* **Работа через VPN / оверлейные сети (Tailscale, WireGuard, ZeroTier):**
  Связывает распределенные узлы в защищенный закрытый контур по внутренним IP-адресам.
* **Работа в изолированной локальной сети (Sovereign LAN):**
  Хотспот смартфона, домашний роутер, полевой коммутатор без выхода в глобальный интернет.
* **Сетевые зависимости:**
  Для самостоятельного LAN-развёртывания требуется доступная локальная сеть и хост; глобальный интернет и сторонний сервер не обязательны. Настройка адресов, маршрутизации, firewall и первичная проверка отпечатка сертификата остаются ответственностью оператора.
* **Синтаксис RFC 3986 для конфигурационных профилей и адресов:**
  * IPv4: `192.168.1.1` или `192.168.1.1:4433`
  * IPv6 в квадратных скобках: `[2001:db8::1]` или `[2001:db8::1]:4433`
  * IPv6 Link-Local с идентификатором зоны (Zone ID): `[fe80::1%wlan0]:4433` (в URL экранируется как `%25wlan0` по RFC 6874)
  * Доменные имена / mDNS: `impulse.local` или `impulse.local:4433`, FQDN
* **Стратегия сокетов хоста (Dual-Stack Wildcard):**
  * По умолчанию сокет связывается с `[::]:4433` со снятым флагом `IPV6_V6ONLY` (сокет одновременно принимает датаграммы IPv4 и IPv6 на одном порту).
  * Graceful fallback: если в ОС отключен стек IPv6, сервер прозрачно откатывается на `0.0.0.0:4433`.
  * Явный выбор адреса в CLI: `--bind [::]:4433`, `--bind 0.0.0.0:4433`, `--bind 127.0.0.1:4433`.
* **Другие IP-сети:**
  Адресный парсер поддерживает IPv4, IPv6 (включая Link-Local с Zone ID) и локальные mDNS-имена. Совместимость с конкретной VPN, mesh-сетью или ad-hoc конфигурацией зависит от их сетевой связности и отдельно не гарантируется.

---

## 4. Криптографические параметры

| Компонент | Стандарт / Спецификация | Конфигурация / Параметры | Назначение |
| :--- | :--- | :--- | :--- |
| **KEM** | **FIPS 203 (ML-KEM-768)** | Решетки (Kyber-768), NIST Категория 3 | Инкапсуляция симметричных ключей для каждого получателя (`PqcCrypto.kt`) |
| **Подпись** | **Dilithium3 (Bouncy Castle legacy API)** | `DilithiumParameterSpec.dilithium3`; не заявляется как ML-DSA-65 / FIPS 204 implementation | Подпись сообщений и аттестация открытых ключей. Проверка подписей обязательна; переход на ML-DSA-65 требует утверждённой protocol SPEC и синхронной миграции. |
| **Symmetric** | **AES-256-GCM** | 256-битный ключ, 12-байтный random IV, 128-битный auth tag | Шифрование тела сообщений и резервных копий |
| **Key Derivation** | **HKDF-SHA256** | RFC 5869 | Извлечение симметричных сессионных ключей из секрета KEM |
| **Argon2id server auth** | Argon2id v19, 32-byte output, salt ≥16 bytes | Generated hash baseline: $m=47104$ KiB, $t=3$, $p=1$. Accepted configured range: $m=47104..65536$ KiB, $t=3..6$, $p=1..2$; challenge advertises the exact validated tuple. Client backup KDF parameters are separate. | • `server/src/crypto/mod.rs`<br>• `server/src/protocol.rs`<br>• `client/app/src/main/java/com/example/impulse/transport/Protocol.kt` |
| **Transport TLS** | **TLS 1.3 via WebTransport** | `aws-lc-rs`/TLS dependency or build configuration alone does not prove a particular PQ group was negotiated. Runtime hybrid post-quantum TLS negotiation is **not verified**; do not claim X25519Kyber768 as an observed connection property. | • `server/README.md` / `server/README.ru.md` security limitations |
| **TLS Cert** | **ECDSA P-256** | Self-signed, TOFU SHA-256 fingerprint | Сертификат хоста (Chromium WebTransport совместимость) |
| **Android Keystore** | **AndroidKeyStore AES master key** | AES-256-GCM используется для шифрования сохранённого PQ key material и TOFU-отпечатков; фактический security level зависит от устройства | Шифрование значений в локальном secure storage. Это не означает, что алгоритмы ML-KEM/подписи выполняются аппаратно или что каждый девайс использует TEE. |

---

## 5. Спецификация Wire-протокола (Protocol v3)

* **Порядок байт:** Little-Endian для всех целочисленных типов (`u8`, `u32`, `u64`).
* **Размер опкода:** Ровно 1 байт.
* **Иерархия опкодов:**
  * `0x11` — `OP_AUTH_CHALLENGE` (Server $\rightarrow$ Client: nonce, salt, argon2 params)
  * `0x12` — `OP_AUTH` (Client $\rightarrow$ Server: 32 bytes HMAC-SHA-256)
  * `0x13` — `OP_AUTH_RESULT` (Server $\rightarrow$ Client: status byte, err)
  * `0x21` — `OP_HEARTBEAT` (Оба направления: timestamp)
  * `0x22` — `OP_NEW_CERT_HASH` (Server $\rightarrow$ Client: 32 bytes SHA-256, expiry)
  * `0x23` — `OP_DISCONNECT` (Оба направления: 0 байт)
  * `0x31` — `OP_KEY_EXCHANGE_KEM_DSA` (Оба направления: KEM pub + DSA pub + signature)
  * `0x32` — `OP_DATA` (Client → Server: внешние идентификаторы получателей и encrypted per-recipient entries; Server → Client: server message ID, server timestamp и opaque payload)
  * `0x33` — `OP_SYNC` (Client $\rightarrow$ Server: last_seen_id)
  * `0x34` — `OP_SYNC_RESPONSE` (Server $\rightarrow$ Client: count + messages)

---

## 6. Чеклист при изменении любого параметра

Если требуется изменить системный параметр (например, TTL или параметры шифрования):
1. **Открыть `docs/SYSTEM_REGISTRY.md`** и найти строку параметра.
2. **Внести изменения в код сервера** (`server/src/...`).
3. **Внести изменения в код клиента** (`client/app/src/...`).
4. **Запустить тесты обоих репозиториев:**
   - Server: `cargo test && cargo clippy -- -D warnings`
   - Client: `./gradlew testDebugUnitTest`
5. **Обновить документацию:**
   - `PROJECT.md`
   - `server/README.md`
   - `client/README.md` и `client/README.ru.md`
   - Поддерживаемые технические документы и новые публикационные копии. Не перезаписывать исходные школьные DOCX или видеоисточники при синхронизации фактов: создавать новую редакцию и помечать старую как архивную только по отдельному решению владельца.
6. Зафиксировать изменения атомарными Conventional Commits.

Release receipt14Oct2026: Clientv3.2.1 / Serverv3.1.1 published after CI and asset checks. All authenticated relay handlers have a30s per-operation deadline; normal active session lifetime is unrestricted by the client setup timer. Detailed runtime limits and final paired evidence: docs/audit/2026-10-14-defense-readiness.md.
