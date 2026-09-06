# scripts/deploy-server.ps1
# Автоматизированный деплой Impulse Server на Windows-хосте
# Политика: docs/policies/deploy.md

param (
    [string]$TargetDir = "",
    [string]$RemoteHost = "",
    [string]$User = $env:WINSRV_USER,
    [string]$Pass = $env:WINSRV_PASS,
    [int]$Port = 4433,
    [switch]$SkipTests = $false
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "       Impulse Server Deploy Script       " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Определение каталога сервера относительно скрипта
$ServerDir = if (Test-Path (Join-Path $PSScriptRoot "..\Cargo.toml")) {
    $PSScriptRoot | Split-Path -Parent
} elseif (Test-Path (Join-Path $PSScriptRoot "..\server\Cargo.toml")) {
    Join-Path $PSScriptRoot "..\server"
} else {
    $PWD.Path
}

if (!(Test-Path (Join-Path $ServerDir "Cargo.toml"))) {
    Write-Error "Каталог сервера с Cargo.toml не найден: $ServerDir"
    exit 1
}

# 1. Test-Gate
if (-not $SkipTests) {
    Write-Host "[1/4] Запуск проверочных тестов (Test-Gate)..." -ForegroundColor Yellow
    Push-Location $ServerDir
    try {
        cargo test
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Тесты завершились с ошибкой. Деплой прерван!"
            exit 1
        }
        cargo clippy --all-targets -- -D warnings
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Clippy обнаружил предупреждения. Деплой прерван!"
            exit 1
        }
    } finally {
        Pop-Location
    }
    Write-Host " Тест-гейт успешно пройден." -ForegroundColor Green
} else {
    Write-Host "[1/4] Пропуск тестов (--SkipTests указан)..." -ForegroundColor DarkGray
}

# 2. Release Build
Write-Host "[2/4] Сборка release-бинаря (cargo build --release)..." -ForegroundColor Yellow
Push-Location $ServerDir
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Сборка завершилась с ошибкой!"
        exit 1
    }
} finally {
    Pop-Location
}

$BinaryPath = Join-Path $ServerDir "target\release\impulse-server.exe"
if (!(Test-Path $BinaryPath)) {
    Write-Error "Исполняемый файл не найден: $BinaryPath"
    exit 1
}
Write-Host " Бинарь успешно собран: $BinaryPath" -ForegroundColor Green

# 3. Деплой (локальный или удаленный)
if ($RemoteHost -and $RemoteHost.Trim() -ne "") {
    Write-Host "[3/4] Удаленный деплой на $RemoteHost..." -ForegroundColor Yellow
    if (-not $User -or -not $Pass) {
        Write-Error "Для удаленного деплоя необходимо указать WINSRV_USER и WINSRV_PASS (через параметры или переменные окружения)."
        exit 1
    }
    $securePass = ConvertTo-SecureString $Pass -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($User, $securePass)

    $remotePath = if ($TargetDir) { $TargetDir } else { "\\$RemoteHost\C$\Users\$User\Desktop\ImpulseServer" }
    
    # Остановка старого процесса
    Write-Host " Остановка старого процесса impulse-server на $RemoteHost..."
    $stopScript = "Stop-Process -Name impulse-server -Force -ErrorAction SilentlyContinue"
    Invoke-Command -ComputerName $RemoteHost -Credential $cred -ScriptBlock { param($s) iex $s } -ArgumentList $stopScript

    # Копирование бинаря
    Write-Host " Копирование бинаря на $remotePath..."
    if (!(Test-Path $remotePath)) {
        New-Item -ItemType Directory -Force -Path $remotePath | Out-Null
    }
    Copy-Item $BinaryPath -Destination "$remotePath\impulse-server.exe" -Force

    # Копирование config.toml если есть локально и отсутствует удаленно
    $localCfg = Join-Path $ServerDir "config.toml"
    if (Test-Path $localCfg) {
        Copy-Item $localCfg -Destination "$remotePath\config.toml" -Force
    }

    # Запуск процесса
    Write-Host " Запуск сервера на $RemoteHost..."
    $startScript = "Start-Process -FilePath '$remotePath\impulse-server.exe' -WorkingDirectory '$remotePath' -WindowStyle Hidden"
    Invoke-Command -ComputerName $RemoteHost -Credential $cred -ScriptBlock { param($s) iex $s } -ArgumentList $startScript

    # Health-check
    Start-Sleep -Seconds 3
    $ok = Test-NetConnection -ComputerName $RemoteHost -Port $Port -InformationLevel Quiet
    if ($ok) {
        Write-Host " OK: сервер отвечает на $RemoteHost:$Port" -ForegroundColor Green
    } else {
        Write-Warning " Сервер не отвечает на порту $Port — проверьте логи на $RemoteHost"
    }
} elseif ($TargetDir -and $TargetDir.Trim() -ne "") {
    Write-Host "[3/4] Локальное копирование бинаря в целевую директорию: $TargetDir..." -ForegroundColor Yellow
    if (!(Test-Path $TargetDir)) {
        New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
    }
    Copy-Item -Path $BinaryPath -Destination $TargetDir -Force
    Write-Host " Файл скопирован в $TargetDir" -ForegroundColor Green

    # Проверка конфигурации
    Write-Host "[4/4] Проверка окружения сервера..." -ForegroundColor Yellow
    $ConfigPath = Join-Path $TargetDir "config.toml"
    if (Test-Path $ConfigPath) {
        Write-Host " Конфигурационный файл $ConfigPath обнаружен." -ForegroundColor Green
    } else {
        Write-Host " Внимание: config.toml не найден в $TargetDir. Создайте его через 'impulse-server --init' или скопируйте вручную." -ForegroundColor Yellow
    }
} else {
    Write-Host "[3/4] Целевая папка не указана. Бинарь готов в $BinaryPath" -ForegroundColor Cyan
    Write-Host "[4/4] Проверка локального config.toml..." -ForegroundColor Yellow
    $ConfigPath = Join-Path $ServerDir "config.toml"
    if (Test-Path $ConfigPath) {
        Write-Host " Конфигурационный файл $ConfigPath обнаружен." -ForegroundColor Green
    } else {
        Write-Host " Внимание: config.toml не найден. Создайте его через 'impulse-server --init'." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host " Деплой завершён успешно!" -ForegroundColor Green
