# SniShaper + T-Line shutdown
# Disables the local proxy and stops the SniShaper service.
# The T-Line SOCKS5 service on 127.0.0.1:10809 is intentionally left running.

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe  = Join-Path $root 'snishaper.exe'

if (-not (Test-Path -LiteralPath $exe)) {
    Write-Host "[ERROR] snishaper.exe not found: $exe" -ForegroundColor Red
    exit 1
}

Write-Host "[1/2] Disabling SniShaper proxy..." -ForegroundColor Cyan
& $exe proxy off
if ($LASTEXITCODE -ne 0) {
    Write-Host ("[ERROR] snishaper.exe proxy off failed (exit " + $LASTEXITCODE + ").") -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[2/2] Stopping SniShaper service..." -ForegroundColor Cyan
& $exe stop
if ($LASTEXITCODE -ne 0) {
    Write-Host ("[ERROR] snishaper.exe stop failed (exit " + $LASTEXITCODE + ").") -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "SniShaper stopped." -ForegroundColor Green
Write-Host "T-Line SOCKS5 remains running at 127.0.0.1:10809."
Write-Host ""
