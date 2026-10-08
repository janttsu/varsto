# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Runs on a fresh Windows Server build instance over SSH: smoke-tests the
# cross-compiled Windows zip on real Windows (command line, vault, sync,
# background service and its local API, self-update check).
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-Location C:\build
Expand-Archive -Force varsto-windows.zip -DestinationPath .\unzipped
$dir = Get-ChildItem .\unzipped | Select-Object -First 1
$exe = Join-Path $dir.FullName "varsto.exe"
Write-Host "== $(Get-ComputerInfo | Select-Object -ExpandProperty OsName) $([Environment]::OSVersion.Version)"
& $exe --version
$env:VARSTO_PASSPHRASE = "cloud-test-passphrase-123"
$home1 = "C:\build\home-a"; $home2 = "C:\build\home-b"; $st = "C:\build\storage"; $fa = "C:\build\files-a"; $fb = "C:\build\files-b"
New-Item -ItemType Directory -Force $st, $fa, $fb | Out-Null
$init = & $exe --home $home1 init --name win-a --json | ConvertFrom-Json
& $exe --home $home1 storage add-local box $st
& $exe --home $home1 folder add docs $fa
"hello from windows" | Set-Content "$fa\note.txt"
& $exe --home $home1 sync
& $exe --home $home2 join --name win-b --vault-key $init.vault_key --storage-path $st
& $exe --home $home2 folder attach docs $fb
& $exe --home $home2 sync
if ((Get-Content "$fb\note.txt") -ne "hello from windows") { throw "sync across two device directories failed" }
Write-Host "== two-device sync on Windows: OK"
$svc = Start-Process -FilePath $exe -ArgumentList "--home", $home1, "service", "run", "--port", "17899", "--interval", "300" -PassThru -RedirectStandardOutput C:\build\service.log -RedirectStandardError C:\build\service.err
Start-Sleep -Seconds 6
$sf = Get-Content "$home1\service.json" | ConvertFrom-Json
$r = Invoke-RestMethod -Uri "http://127.0.0.1:$($sf.port)/api/state" -Headers @{ "X-Varsto-Token" = $sf.token; "Host" = "127.0.0.1:$($sf.port)" }
Write-Host "== service API on Windows: has_vault=$($r.has_vault) unlocked=$($r.unlocked)"
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$($sf.port)/api/quit" -Headers @{ "X-Varsto-Token" = $sf.token } | Out-Null
Start-Sleep -Seconds 2
& $exe --home $home1 update --check
& $exe --home $home1 status --json | Out-File -Encoding utf8 C:\build\status.json
Write-Host "== Windows smoke test finished"
