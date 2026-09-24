# SYSTEM_REGISTRY.md — Единый канонический реестр системных параметров и контекста

> **Статус документа:** ДЕЙСТВУЮЩИЙ КАНОН И ЕДИНЫЙ ИСТОЧНИК ИСТИНЫ (SINGLE SOURCE OF TRUTH)  
> **Версия реестра:** 1.0.0  
> **Дата фиксации:** 2026-09-24  
> **Связанные документы:** `PROJECT.md`, `AGENTS.md`, `docs/VISION.md`, `school-project/Проект.docx`

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

---

## 2. Временные параметры, TTL и окна перекрытия

| Параметр | Каноническое значение | Физический смысл | Точные места в коде и документации |
| :--- | :--- | :--- | :--- |
| **Message TTL (Сервер)** | **72 часа** (3 суток)<br>`Duration::from_secs(60 * 60 * 72)` | Время удержания зашифрованных сообщений в оперативной памяти (In-RAM Ring Buffer) для доставки офлайн-клиентам. | • `server/src/storage/mod.rs:20` (`MESSAGE_TTL`)<br>• `server/src/storage/mod.rs:177` (unit test)<br>• `server/tests/exploits.rs:254`<br>• `server/src/lib.rs:6`<br>• `server/README.md:32, 43, 56, 275, 292`<br>• `PROJECT.md:45, 137`<br>• `school-project/Проект.docx:p73` |
| **Message TTL (Клиент)** | **72 часа** (3 суток)<br>`const val TTL_HOURS = 72L` | Период локального хранения зашифрованных сообщений в базе данных Room до автоматического безвозвратного затирания (`purgeExpired`). | • `client/app/src/main/java/com/example/impulse/data/MessageRepository.kt:72`<br>• `client/app/src/main/java/com/example/impulse/data/db/MessageDatabase.kt:91`<br>• `client/app/src/main/java/com/example/impulse/data/db/MessageEntity.kt:17`<br>• `client/README.md:33, 42, 125`<br>• `client/README.ru.md:33, 42, 125` |
| **Certificate Overlap** | **4 дня** (96 часов)<br>`Duration::from_secs(60 * 60 * 24 * 4)` | Окно перекрытия при ротации сертификата хоста. Новый сертификат создается за 4 дня до истечения старого, оба активны одновременно. Полностью покрывает 3-дневный офлайн TTL. | • `server/src/cert/mod.rs:36` (`CERT_OVERLAP`)<br>• `server/src/cert/mod.rs:39` (`ROTATE_BEFORE_EXPIRY`)<br>• `server/src/lib.rs:5`<br>• `server/README.md:31, 52, 270`<br>• `PROJECT.md:137` |
| **Certificate Lifetime** | **14 дней**<br>`Duration::from_secs(60 * 60 * 24 * 14)` | Полный срок действия выпускаемого сервером самоподписанного TLS-сертификата ECDSA P-256. | • `server/src/cert/mod.rs:32` (`CERT_VALIDITY`)<br>• `server/src/lib.rs:4`<br>• `server/README.md:31, 51, 270` |
| **Clock Skew Tolerance** | **4 дня** (96 часов)<br>`4 * 24 * 3600 * 1000L` | Допустимое отклонение времени клиента при верификации подписи сообщения. Включает 72ч TTL + 24ч запас на дрейф часов. | • `client/app/src/main/java/com/example/impulse/ChatController.kt:899`<br>• `PROJECT.md:139` |

---

## 3. Сетевые лимиты и защита от DoS

| Константа | Значение | Назначение | Файлы кода |
| :--- | :--- | :--- | :--- |
| **`MAX_PAYLOAD_BYTES`** | `1_000_000` байт (1 МБ) | Верхний предел тела любого пакета. Защита от OOM при раздутых длинах. | • `server/src/protocol/limits.rs:4`<br>• `client/app/src/main/java/com/example/impulse/transport/Protocol.kt:50` |
| **`MAX_MESSAGES`** | `10_000` | Максимальная емкость кольцевого буфера сообщений в памяти сервера. | • `server/src/storage/mod.rs:23` |
| **`MAX_STREAM_BUFFER`** | `8 * 1024 * 1024` (8 МБ) | Буфер одного потока WebTransport. | • `server/src/protocol/limits.rs:7` |
| **`MAX_TOTAL_BUFFERED_BYTES`** | `512 * 1024 * 1024` (512 МБ) | Суммарный лимит ОЗУ на буферизацию всех входящих соединений. | • `server/src/protocol/limits.rs:15` |
| **`seenNonces` LRU Cap** | `2000` записей | Емкость кэша обнаружения повторных сообщений на клиенте. | • `client/app/src/main/java/com/example/impulse/ChatController.kt:914` |
| **Default Port** | `4433 UDP` | Сетевой порт WebTransport (QUIC). | • `server/src/config/mod.rs`<br>• `client/app/src/main/java/com/example/impulse/transport/WebTransportClient.kt` |

---

## 4. Криптографические параметры

| Компонент | Стандарт / Спецификация | Конфигурация / Параметры | Назначение |
| :--- | :--- | :--- | :--- |
| **KEM** | **FIPS 203 (ML-KEM-768)** | Решетки (Kyber-768), NIST Категория 3 | Инкапсуляция симметричных ключей для каждого получателя (`PqcCrypto.kt`) |
| **DSA** | **FIPS 204 (ML-DSA-65)** | Решетки (Dilithium3), NIST Категория 3 | Цифровая подпись каждого сообщения и аттестация открытых ключей |
| **Symmetric** | **AES-256-GCM** | 256-битный ключ, 12-байтный random IV, 128-битный auth tag | Шифрование тела сообщений и резервных копий |
| **Key Derivation** | **HKDF-SHA256** | RFC 5869 | Извлечение симметричных сессионных ключей из секрета KEM |
| **Argon2id** | **RFC 9106 / OWASP** | $m=47104$ KiB (46 МБ), $t=3$ итерации, $p=1$ параллелизм | Защита мастер-пароля сервера и шифрование резервных копий |
| **Transport TLS** | **TLS 1.3 / X25519Kyber768** | Hybrid Post-Quantum Key Exchange (`aws-lc-rs`) | Защита QUIC-канала от атак «Harvest Now, Decrypt Later» |
| **TLS Cert** | **ECDSA P-256** | Self-signed, TOFU SHA-256 fingerprint | Сертификат хоста (Chromium WebTransport совместимость) |
| **Android Keystore** | **Android KeyStore (Hardware TEE)** | `KeyProperties.PURPOSE_ENCRYPT or DECRYPT`, AES-256-GCM | Аппаратная изоляция мастер-ключей на смартфонах |

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
  * `0x32` — `OP_DATA` (Оба направления: Per-Recipient KEM blob)
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
   - Школьные материалы: `school-project/Проект.docx`, `Сценарий_и_Шпора_Импульс.docx`, `Тезисы_Импульс.docx`
6. Зафиксировать изменения атомарными Conventional Commits.
