# Contributing — Impulse Server (Rust)

> Дополнение к корневому `../AGENTS.md` и `server/AGENTS.md`.
> Процесс релиза описан ниже.

## Commits
- Conventional Commits: `feat:` `fix:` `docs:` `refactor:` `style:` `test:` `chore(release):`
- Английский, без эмодзи, атомарно.
- **НЕ коммить:** `config.toml` (Argon2-hash пароля), `*.log`, `server_out.log`,
  `server_err.log`, `.superpowers/`, `docs/superpowers/`.

## Branching (trunk-based)
- `master` — стабильная. Фича/фикс → короткая ветка → merge в `master`.
- Старые `v26-wip` удалены/потеряны — не искать.

## Test-gate (ОБЯЗАТЕЛЬНО перед коммитом)
```bash
cargo build
cargo test
cargo clippy -- -D warnings
```
Проверено 2026-08-15: `cargo test` → 19 passed, 0 failed.

## Forbidden zones
- Wire-протокол (опкоды 0x01–0x0C) — только с client + SPEC.
- Crypto (Argon2id, сертификаты) — только через SPEC + аудит.
  Параметры Argon2id OWASP: m=47104, t=3, p=1.

## Релиз
1. Поднять `version` в `Cargo.toml` (сейчас "2.7.2").
2. Закоммитить (`chore(release): vX.Y.Z`).
3. Создать git-tag `vX.Y.Z`, запушить: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. **GitHub CI (`server-build.yml`): работает ✅** (последние runs success).
   - job `test`: `cargo test --locked`.
   - job `build`: матрица (linux x86/arm64/armv7/riscv64 + windows x64/arm64),
     пакует tar.gz/zip.
   - job `package` (при tag): собирает `.deb`/`.rpm` (cargo-deb, cargo-generate-rpm).
   - job `release` (при tag): создаёт GitHub Release с артефактами.
5. Деплой на Windows-сервер (1.100): скрипт `scripts/deploy-server.ps1`
   (см. `docs/policies/deploy.md`). Секреты (`config.toml`) НЕ в git.

## Commit/tag → CI автоматически собирает и публикует релиз (server).
