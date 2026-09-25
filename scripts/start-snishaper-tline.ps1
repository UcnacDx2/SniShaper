# SniShaper + T-Line launcher
# Starts SniShaper with the T-Line SOCKS5 upstream on 127.0.0.1:10809,
# then enables the local proxy with: snishaper.exe proxy on

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe  = Join-Path $root 'snishaper.exe'

if (-not (Test-Path -LiteralPath $exe)) {
    Write-Host "[ERROR] snishaper.exe not found: $exe" -ForegroundColor Red
    exit 1
}

$hostName = '127.0.0.1'
$port = 10809

Write-Host ("[1/4] Checking T-Line SOCKS5: " + $hostName + ":" + $port) -ForegroundColor Cyan
$ready = $false
try {
    $ready = Test-NetConnection -ComputerName $hostName -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
} catch {
    $ready = $false
}

if (-not $ready) {
    Write-Host ("[ERROR] T-Line SOCKS5 is not listening on " + $hostName + ":" + $port) -ForegroundColor Red
    Write-Host "       Start your T-Line service first, then run this script again." -ForegroundColor Yellow
    exit 2
}

$env:SNISHAPER_TLINE_SOCKS5 = $hostName + ':' + $port
Write-Host ("[2/4] SNISHAPER_TLINE_SOCKS5=" + $env:SNISHAPER_TLINE_SOCKS5) -ForegroundColor Green

Write-Host "[3/4] Starting SniShaper service..." -ForegroundColor Cyan
& $exe start
if ($LASTEXITCODE -ne 0) {
    Write-Host ("[ERROR] 'snishaper.exe start' failed (exit " + $LASTEXITCODE + ").") -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "[4/4] Enabling SniShaper proxy (proxy on)..." -ForegroundColor Cyan
& $exe proxy on
if ($LASTEXITCODE -ne 0) {
    Write-Host ("[ERROR] 'snishaper.exe proxy on' failed (exit " + $LASTEXITCODE + ").") -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "SniShaper + T-Line started." -ForegroundColor Green
Write-Host ("T-Line SOCKS5 : " + $env:SNISHAPER_TLINE_SOCKS5)
Write-Host "HTTP proxy    : 127.0.0.1:8080"
Write-Host "SOCKS5 proxy  : 127.0.0.1:8081"
Write-Host ""
Write-Host "Stop proxy   : .\snishaper.exe proxy off"
Write-Host "Stop service : .\snishaper.exe stop"
