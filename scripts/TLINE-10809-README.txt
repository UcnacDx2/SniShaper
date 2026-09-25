SniShaper Windows CLI + T-Line 10809

One-click startup:
  start-snishaper-tline.cmd

One-click shutdown:
  stop-snishaper-tline.cmd

PowerShell:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\start-snishaper-tline.ps1
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\stop-snishaper-tline.ps1

The startup launcher:
  1. Checks 127.0.0.1:10809 is listening.
  2. Sets SNISHAPER_TLINE_SOCKS5=127.0.0.1:10809.
  3. Runs: snishaper.exe start
  4. Runs: snishaper.exe proxy on

The shutdown launcher:
  1. Runs: snishaper.exe proxy off
  2. Runs: snishaper.exe stop

The T-Line executable itself is not bundled; the startup launcher expects an
already-running T-Line SOCKS5 listener on 127.0.0.1:10809.

The shutdown launcher intentionally leaves T-Line running.

Local SniShaper endpoints:
  HTTP  127.0.0.1:8080
  SOCKS 127.0.0.1:8081
