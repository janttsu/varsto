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

# Explorer integration: context-menu verbs on all files and the placeholder
# association, run the way Explorer runs them (Shell.Application verbs and
# ShellExecute), first on the vault directly, then through the service.
& $exe --home $home1 install
if ($LASTEXITCODE -ne 0) { throw "varsto install failed" }
$verb = (Get-ItemProperty -LiteralPath "HKCU:\Software\Classes\*\shell\Varsto.Fetch").MUIVerb
if ($verb -ne "Download with Varsto") { throw "context-menu verb missing: $verb" }
Write-Host "free verb: $((Get-ItemProperty -LiteralPath 'HKCU:\Software\Classes\*\shell\Varsto.Free\command').'(default)')"
if ((Get-ItemProperty -LiteralPath "HKCU:\Software\Classes\.varsto-placeholder").'(default)' -ne "Varsto.Placeholder") { throw "placeholder association missing" }
"@echo off`r`necho %~1>> C:\build\opened.txt`r`n" | Set-Content -Encoding ascii C:\build\opener.cmd
$env:VARSTO_OPENER = "C:\build\opener.cmd"
function Wait-For($test, $what) {
  for ($i = 0; $i -lt 90; $i++) { if (& $test) { return }; Start-Sleep -Seconds 1 }
  Get-ChildItem $fa | Format-Table Name, Length | Out-String | Write-Host
  if (Test-Path "$home1\filemanager.log") { Write-Host "filemanager.log:"; Get-Content "$home1\filemanager.log" | Write-Host }
  Get-Process varsto -ErrorAction SilentlyContinue | Format-Table Id, StartTime | Out-String | Write-Host
  throw "timed out: $what"
}
$shell = New-Object -ComObject Shell.Application
function Invoke-Verb($dir, $name, $verb) { $shell.Namespace($dir).ParseName($name).InvokeVerb($verb) }
Invoke-Verb $fa "note.txt" "Varsto.Free"
Wait-For { Test-Path "$fa\note.txt.varsto-placeholder" } "Free up space with Varsto (no service)"
Write-Host "== Explorer verb Free up space (no service): OK"
# The verb's process may still be committing its ledger batch.
Wait-For { -not (Get-Process varsto -ErrorAction SilentlyContinue) } "the Free verb's process to exit"
Start-Process -FilePath "$fa\note.txt.varsto-placeholder"
Wait-For { (Test-Path "$fa\note.txt") -and (Test-Path C:\build\opened.txt) } "double-click on a placeholder (no service)"
if ((Get-Content "$fa\note.txt") -ne "hello from windows") { throw "fetched content differs" }
Write-Host "== double-click on a placeholder (no service): OK, opened $(Get-Content C:\build\opened.txt)"
$svc = Start-Process -FilePath $exe -ArgumentList "--home", $home1, "service", "run", "--port", "0", "--interval", "300" -PassThru -RedirectStandardOutput C:\build\service2.log -RedirectStandardError C:\build\service2.err
Start-Sleep -Seconds 6
$env:VARSTO_PASSPHRASE = "wrong-so-only-the-service-can-do-it"
Invoke-Verb $fa "note.txt" "Varsto.Free"
Wait-For { Test-Path "$fa\note.txt.varsto-placeholder" } "Free up space with Varsto (through the service)"
Invoke-Verb $fa "note.txt.varsto-placeholder" "Varsto.Fetch"
Wait-For { (Test-Path "$fa\note.txt") -and -not (Test-Path "$fa\note.txt.varsto-placeholder") } "Download with Varsto (through the service)"
Write-Host "== Explorer verbs through the service: OK"
$env:VARSTO_PASSPHRASE = "cloud-test-passphrase-123"
$sf = Get-Content "$home1\service.json" | ConvertFrom-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$($sf.port)/api/quit" -Headers @{ "X-Varsto-Token" = $sf.token } | Out-Null
Start-Sleep -Seconds 2
& $exe --home $home1 uninstall
if (Test-Path -LiteralPath "HKCU:\Software\Classes\*\shell\Varsto.Fetch") { throw "uninstall left the verb" }
if (Test-Path -LiteralPath "HKCU:\Software\Classes\Varsto.Placeholder") { throw "uninstall left the association" }
Write-Host "== Explorer integration removed by uninstall: OK"
Write-Host "== Windows smoke test finished"
