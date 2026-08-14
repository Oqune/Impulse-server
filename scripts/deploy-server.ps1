<System_Note>
# deploy-server.ps1 — автоматизация деплоя Impulse Server на Win-сервер 192.168.1.100
# Запускать НА ПК (192.168.1.50), откуда собирается код.
# Требует: Rust/cargo в PATH, доступ по SSH к 192.168.1.100 (локальный аккаунт).
#
# ПЕРЕД ПЕРВЫМ ЗАПУСКОМ заполнить переменные ниже (или через env):
#   $env:WINSRV_USER = "локальный_юзер_на_1.100"
#   $env:WINSRV_PASS = "пароль"   # лучше через pass: sshpass -p (pass show hermes/winserver) ...
#
# Безопасность: config.toml (с Argon2-hash пароля) копируется ТОЛЬКО на 1.100,
# не попадает в git/OKF/логи. Не светить пароль в командной строке.
</System_Note>

param(
    [string]$WinSrv   = "192.168.1.100",
    [string]$User     = $env:WINSRV_USER,
    [string]$Pass     = $env:WINSRV_PASS,
    [string]$RemoteDir = "C:\Users\$env:USERNAME\Desktop\ImpulseServer",
    [string]$LocalServerDir = "D:\Data\projects\ImpulseProject\server",
    [int]$Port = 4433
)

$ErrorActionPreference = "Stop"

if (-not $User -or -not $Pass) {
    Write-Error "Не заданы WINSRV_USER / WINSRV_PASS. Задайте переменные окружения."
    exit 1
}

$securePass = ConvertTo-SecureString $Pass -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($User, $securePass)

Write-Host "[1/5] Сборка server (cargo build --release)..."
Push-Location $LocalServerDir
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
} finally {
    Pop-Location
}
$bin = Join-Path $LocalServerDir "target\release\impulse-server.exe"
if (-not (Test-Path $bin)) { throw "Бинарь не собран: $bin" }

Write-Host "[2/5] Остановка старого процесса на $WinSrv..."
$stopScript = "Stop-Process -Name impulse-server -Force -ErrorAction SilentlyContinue"
Invoke-Command -ComputerName $WinSrv -Credential $cred -ScriptBlock { param($s) iex $s } -ArgumentList $stopScript

Write-Host "[3/5] Копирование бинаря + config.toml на $WinSrv..."
# Создаём папку и копируем через SMB admin-share (C$)
$remotePath = "\\$WinSrv\C$\Users\$User\Desktop\ImpulseServer"
New-Item -ItemType Directory -Force -Path $remotePath | Out-Null
Copy-Item $bin -Destination "$remotePath\impulse-server.exe" -Force
Copy-Item (Join-Path $LocalServerDir "config.toml") -Destination "$remotePath\config.toml" -Force

Write-Host "[4/5] Запуск сервера на $WinSrv (фоново)..."
$startScript = "Start-Process -FilePath '$remotePath\impulse-server.exe' -WorkingDirectory '$remotePath' -WindowStyle Hidden"
Invoke-Command -ComputerName $WinSrv -Credential $cred -ScriptBlock { param($s) iex $s } -ArgumentList $startScript

Write-Host "[5/5] Health-check: порт $Port..."
Start-Sleep -Seconds 3
$ok = Test-NetConnection -ComputerName $WinSrv -Port $Port -InformationLevel Quiet
if ($ok) { Write-Host "OK: сервер отвечает на $WinSrv:$Port" }
else    { Write-Warning "Сервер не отвечает на порту $Port — проверь логи на 1.100" }

Write-Host "Деплой завершён."
