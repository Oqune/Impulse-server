# Impulse identity V18 — внедрение и проверка

Дата: 2026-10-08. Владелец явно разрешил финальное усиление импульса и немедленное внедрение в оба проекта. Основная подложка — graphite, основной знак общий; динамические цвета интерфейса клиента сохранены.

## Итоговые изменения

- Импульс примерно на 16% тоньше в середине относительно V17 (26% относительно V16). Центральная прозрачность усилена, исток мягче затухает в освещённом нижнем левом секторе; наконечник сохранён исходным.
- Client: legacy/round/adaptive icons, monochrome, статический splash, Home logo. На светлой теме цветной знак имеет графитовую рамку для контраста. Старая неиспользуемая Canvas-эмблема и Android-placeholder drawables заменены.
- Server: 7-размерный ICO встроен в Windows EXE, малый цветной знак в TUI без увеличения высоты Info/уменьшения QR и логов. Linux desktop entry и hicolor SVG/PNG включены в deb/rpm metadata; переносимые архивы содержат README и assets.
- Обоим репозиториям добавлены одинаковые редактируемые master/icon SVG, PNG, параметры и контрольные суммы. README обоих языков используют новые шапки. Social cards готовы в assets/brand.

## Проверки

| Проверка | Результат |
|---|---|
| Client testDebugUnitTest | 127 passed, 0 failed, 0 skipped |
| Client assembleDebug | Success; universal + ABI APK |
| Client lintDebug | 0 errors; 0 warnings на новых branding resources; существующие предупреждения проекта не подавлялись |
| APK resources | mark, frame, adaptive foreground, splash, monochrome, adaptive v26/v33 присутствуют; mark PNG совпадает с исходником побайтно |
| Android safe zone | foreground внутри 66 dp safe circle, запас проверен по реальным пикселям |
| Android compact vector | 36 cubic segments / 1756 chars вместо 20 491 chars; sampled boundary error 0.0307 source units; full-colour PNG/SVG не упрощены |
| Server cargo build | Success |
| Server cargo test | 126 passed; 2 intentional client-side attestation tests ignored |
| Server clippy --all-targets -- -D warnings | Success, 0 warnings |
| Windows PE icon | 7 ICON resources, GROUP_ICON с 7 frames; ProductName присутствует |
| TUI | Full/two-column/compact tests pass; QR на полном snapshot помещается; transport/version/uptime/TTL читаемы; scroll/search tests pass |
| Live relay regression | QUIC/pinning/auth/heartbeat/opaque relay/sync loopback passed |
| Shared assets | master/icon SVG и PNG Client/Server побайтно одинаковы |

Геометрия и наконечник проверены также в сериализованном SVG. Краевые световые поля ограничены исходной сферой; 0 пикселей оболочки за радиусом 316 px + 2 px сглаживания при рендере 1024 px. Свет художественно приближён, физическая трассировка стекла не заявляется.

MSVC при build/test выдаёт информационное сообщение о создании import libraries, отображаемое текущим rustc как linker stdout warning; ошибок линковки нет, clippy с -D warnings проходит. Предупреждения не отключались. Runtime dependency/crypto/wire changes отсутствуют; winresource — только build dependency. Его новые TOML build-зависимости сохраняют MSRV 1.85.

## Практические ограничения

- На хосте не было подключённого Android-устройства или настроенного AVD, поэтому реальный launcher/splash/Home launch не выполнялся. Проверены сборка, содержимое APK, ресурсы, геометрия и mask previews.
- Linux и Windows ARM64 packages не устанавливались на этом Windows AMD64-хосте; ресурсы и упаковка подготовлены, текущий Windows PE проверен.
- Публикация релиза, push/merge удалённых веток и загрузка GitHub social-preview settings не выполнялись. Шапки внедрены в README исходников, карточки сохранены отдельно.

## Источники

- [Android adaptive icons](https://developer.android.com/develop/ui/compose/system/icon_design_adaptive) — 108 dp layers, 66 dp safe zone, monochrome.
- [Android splash](https://developer.android.com/develop/ui/views/launch/splash-screen) — static VectorDrawable и безопасная область.
- [Android 9 AdaptiveIconDrawable source](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-9.0.0_r1/graphics/java/android/graphics/drawable/AdaptiveIconDrawable.java) — старый inflater пропускает неизвестные layer tags, что позволяет оставить monochrome в базовом adaptive XML.
- [winresource 0.1.31](https://docs.rs/winresource/0.1.31/winresource/) — Windows resource build integration.

Расчётный пакет: output/identity-v1/final-v18. Отдельные результаты: integration-validation.json, platform/android-path-validation.json, tui.svg/png. Полный исходный пакет: output/identity-v1/impulse-identity-v18.zip.
