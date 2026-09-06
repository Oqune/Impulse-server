# Политика деплоя Impulse Server (Windows)

Целевая машина: Windows-ПК / сервер (порт 4433 WebTransport/QUIC).
Конфигурация: `config.toml` (Argon2-hash пароля + сертификаты).

## Процесс деплоя
Автоматизированный запуск выполняется через скрипт `scripts/deploy-server.ps1`:

```powershell
# Из корня репозитория:
.\scripts\deploy-server.ps1 -TargetDir "C:\ImpulseServer"
```

Скрипт выполняет:
1. Запуск обязательного тестового гейта (`cargo test` + `cargo clippy --all-targets -- -D warnings`).
2. Сборку release-бинаря (`cargo build --release`).
3. Копирование `impulse-server.exe` в целевую директорию (`$TargetDir`).
4. Проверку наличия `config.toml` и готовности окружения.

## Правила
- ❌ `config.toml` с секретами НЕ коммитится в git и не логируется.
- ❌ Запрещено деплоить без прохождения test-gate (`cargo test`).
- ✅ Деплой выполняется воспроизводимо через `scripts/deploy-server.ps1`.
- ✅ Перед деплоем рабочий каталог чист, изменения зафиксированы в `master`.
