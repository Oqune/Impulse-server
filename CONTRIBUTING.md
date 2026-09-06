# Contributing — Impulse Server (Rust)

> Разработка ведется по стандартам **AI-Assisted Engineering** (см. `../AI_MANIFESTO.md` и `../AGENTS.md`).

## Процесс работы над кодом
1. **Spec-First:** Любые изменения wire-протокола (`0x11`–`0x34`), криптографических инвариантов или архитектуры хранилища начинаются со спецификации в `docs/specs/`.
2. **Conventional Commits:** 
   - Префиксы: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore(release):`.
   - Язык: английский. Атомарно, без эмодзи.
   - Запрещено коммитить: `config.toml`, логи (`*.log`), временные артефакты агентов.
3. **Trunk-Based:** Ветка `master` стабильна. Работа идет в ветках `feat/*` или `fix/*` с последующим слиянием.

## Test-Gate
Перед отправкой изменений обязательно:
```powershell
cargo build
cargo test
cargo clippy -- -D warnings
```

## Релиз и сборка
- Текущая версия: `2.7.4` (MSRV 1.85).
- Релиз сопровождается синхронным бампом версии в `Cargo.toml`, созданием тега `vX.Y.Z` и генерацией бинарников через GitHub Actions (`server-build.yml`).
- Развертывание на Windows-хосте выполняется через проверенный скрипт `scripts/deploy-server.ps1` (см. `docs/policies/deploy.md`).
