# AGENTS.md — Impulse Server (Rust)

Дополнение к корневому `../AGENTS.md`. Специфика server-части.

## Стек
- Rust (edition 2024, MSRV 1.85), `cargo`, `tokio`, `wtransport` (WebTransport/QUIC).
- Точка входа: `src/main.rs`. Логика релея: `src/relay/{mod,session,auth,housekeeping,stats}.rs`.
- Конфиг: `src/config/{mod,cli,file}.rs` + `config.toml.example`.
- Crypto: `src/crypto/mod.rs` (Argon2id, сертификаты).

## Команды
- Сборка: `cargo build` (dev) / `cargo build --release`
- Тесты: `cargo test`
- Линт: `cargo clippy -- -D warnings`
- Запуск: `impulse-server --init` (мастер пароля) или `--config <path>`

## Правила
- **Асинхронность:** в async-контексте — только `tokio::sync::Mutex`,
  НЕ `std::sync::Mutex` (исправлено в аудите).
- **Паники:** сессионные таски — оборачивать в `tracing::error!`, не глотать молча.
- **Логи:** не hex-dump сырые auth-пакеты; уровни через `RUST_LOG`.
- **Argon2id:** параметры OWASP (m=47104, t=3, p=1). Сервер шлёт свои параметры
  в `AuthChallenge` (опкод 0x0B) — клиент обязан их использовать.
- **Wire-протокол:** опкоды `0x01`–`0x0C`. Любое изменение — только с client + SPEC.

## Тесты (покрыть, из аудита)
- Обработка сессий, rate-limiter, ротация сертификатов, lifecycle storage.
- Интеграционные с реальным WebTransport — пока нет (TODO).
