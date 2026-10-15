# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Smoke test of the Windows installer, for a Windows machine with a desktop
# session (a GitHub runner). It installs silently into a temporary folder,
# starts the service, upgrades in place with a setup of a newer version,
# repairs, refuses a downgrade, opens the window (and checks that a second
# launch does not make a second one), and uninstalls (keeping the data folder,
# then deleting it when asked).
#
#   installer\windows\smoke-test.ps1 -Setup Varsto-<v>-setup.exe -Newer Varsto-99.0.0-setup.exe -Version <v> -NewerVersion 99.0.0 -Work C:\smoke
param(
  [Parameter(Mandatory)] [string]$Setup,
  [Parameter(Mandatory)] [string]$Newer,
  [Parameter(Mandatory)] [string]$Version,
  [Parameter(Mandatory)] [string]$NewerVersion,
  [Parameter(Mandatory)] [string]$Work
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force $Work | Out-Null
$Work = (Resolve-Path $Work).Path
$app = Join-Path $Work "Varsto app"          # a path with a space on purpose
$home1 = Join-Path $Work "device"
New-Item -ItemType Directory -Force $home1 | Out-Null
$env:VARSTO_HOME = $home1
$env:VARSTO_PASSPHRASE = "smoke-test-passphrase-123"
$uninstKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{96573B8D-1FD3-43CC-A3E7-81032D8F53B8}_is1"
$startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Varsto.lnk"
$startupCmd = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\Varsto.cmd"

function Step($t) { Write-Host "== $t" }
function Check($ok, $what) { if (-not $ok) { Show-Logs; throw "FAILED: $what" } else { Write-Host "   ok: $what" } }
function Show-Logs {
  Get-ChildItem $Work -Filter "*.log" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "--- $($_.Name)"; Get-Content $_.FullName -Tail 40 }
  foreach ($f in "service.log", "tray.log") { $p = Join-Path $home1 $f; if (Test-Path $p) { Write-Host "--- $f"; Get-Content $p -Tail 40 } }
}
function Run-Setup($exe, $log, [string[]]$extra = @()) {
  $a = @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CLOSEAPPLICATIONS", "/LOG=$log") + $extra
  # Not Start-Process -Wait: that waits for every process the setup started too (the tray).
  $p = Start-Process -FilePath $exe -ArgumentList $a -PassThru
  if (-not $p.WaitForExit(300000)) { throw "setup did not finish in 5 minutes" }
  return $p.ExitCode
}
function Wait-Until([scriptblock]$test, [string]$what, [int]$seconds = 90) {
  for ($i = 0; $i -lt $seconds; $i++) { if (& $test) { return }; Start-Sleep -Seconds 1 }
  Show-Logs; throw "timed out: $what"
}
function Service-Pid() { if (Test-Path "$home1\service.json") { return (Get-Content "$home1\service.json" -Raw | ConvertFrom-Json).pid } return $null }
function Service-Alive() {
  $sf = $null; try { $sf = Get-Content "$home1\service.json" -Raw | ConvertFrom-Json } catch { return $false }
  try { Invoke-RestMethod -Uri "http://127.0.0.1:$($sf.port)/api/service" -Headers @{ "X-Varsto-Token" = $sf.token } | Out-Null; return $true } catch { return $false }
}
function Installed-Procs() { Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($app, [StringComparison]::OrdinalIgnoreCase) } }

Step "fresh install into $app"
$code = Run-Setup $Setup "$Work\setup1.log" @("/DIR=`"$app`"")
Check ($code -eq 0) "setup exit code 0 (got $code)"
foreach ($f in "varsto.exe", "varsto-window.exe", "varsto.ico", "unins000.exe") { Check (Test-Path "$app\$f") "$f installed" }
$v = (& "$app\varsto.exe" --version) -join " "
Check ($v -match [regex]::Escape($Version)) "varsto.exe --version says $Version ($v)"
$wv = (& "$app\varsto-window.exe" --version) -join " "
Write-Host "   varsto-window --version: $wv"
Check ((Get-ItemProperty $uninstKey).DisplayVersion -eq $Version) "uninstall entry has version $Version"
Check ((Get-ItemProperty "HKCU:\Software\Varsto").InstallPath -eq $app) "install location is in the registry"
Check ((Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run").Varsto -like "*varsto-window.exe*--background*") "autostart entry"
Check (Test-Path $startMenu) "Start menu shortcut"
Check (Test-Path (Join-Path ([Environment]::GetFolderPath("Desktop")) "Varsto.lnk")) "desktop shortcut"
Check (-not (Test-Path $startupCmd)) "no console starter in the Startup folder"
Check ($null -ne (Get-ItemProperty -LiteralPath "HKCU:\Software\Classes\*\shell\Varsto.Fetch" -ErrorAction SilentlyContinue)) "Explorer verbs set up by varsto install"

Step "the service and tray run after the install"
Wait-Until { Service-Alive } "the service to answer"
$pid1 = Service-Pid
Write-Host "   service pid $pid1"
Check (@(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq "varsto.exe" -and $_.CommandLine -match "\btray\b" }).Count -eq 1) "one tray process"

Step "a vault and user data that must survive"
& "$app\varsto.exe" init --name smoke | Out-Null
Check ($LASTEXITCODE -eq 0 -and (Test-Path "$home1\vault.json")) "vault created"
Set-Content "$home1\smoke-marker.txt" "keep me"

Step "auto-update setting"
Check (((& "$app\varsto.exe" config) -join " ") -match "auto-update: on") "auto-update is on by default"
& "$app\varsto.exe" config auto-update off | Out-Null
Check (((& "$app\varsto.exe" config) -join " ") -match "auto-update: off") "varsto config auto-update off"
& "$app\varsto.exe" config auto-update on | Out-Null

Step "window: opens, is the only one, remembers its place"
$w1 = Start-Process -FilePath "$app\varsto-window.exe" -PassThru
Wait-Until { $w1.Refresh(); $w1.MainWindowHandle -ne 0 } "the window to appear" 60
Check ($w1.MainWindowTitle -eq "Varsto") "window title is Varsto ($($w1.MainWindowTitle))"
$w2 = Start-Process -FilePath "$app\varsto-window.exe" -PassThru
Check ($w2.WaitForExit(30000)) "a second launch exits (it only focuses the first window)"
Check (-not $w1.HasExited) "the first window stays"
Start-Sleep 3
Check ($w1.CloseMainWindow()) "close the window"
Check ($w1.WaitForExit(20000)) "the window process ends"
Check (Test-Path "$env:LOCALAPPDATA\Varsto\window.json") "window.json written"
Check (Service-Alive) "closing the window leaves the service running"

Step "upgrade in place with a newer setup"
$code = Run-Setup $Newer "$Work\setup2.log"
Check ($code -eq 0) "upgrade exit code 0 (got $code)"
Check ((Get-ItemProperty $uninstKey).DisplayVersion -eq $NewerVersion) "uninstall entry now has version $NewerVersion"
Check ((Get-ItemProperty "HKCU:\Software\Varsto").InstallPath -eq $app) "same install location (used the previous folder)"
Wait-Until { (Service-Alive) -and ((Service-Pid) -ne $pid1) } "a restarted service"
Check (-not (Get-Process -Id $pid1 -ErrorAction SilentlyContinue)) "the old service process is gone"
Check (@(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq "varsto.exe" -and $_.CommandLine -match "\btray\b" }).Count -eq 1) "one tray process after the upgrade"
Check ((Get-Content "$home1\smoke-marker.txt") -eq "keep me" -and (Test-Path "$home1\vault.json")) "data and vault untouched"

Step "repair (same version again)"
$code = Run-Setup $Newer "$Work\setup3.log"
Check ($code -eq 0) "repair exit code 0 (got $code)"
Wait-Until { Service-Alive } "the service after the repair"

Step "a silent downgrade is refused"
$code = Run-Setup $Setup "$Work\setup4.log"
Check ($code -ne 0) "older setup refused (exit code $code)"
Check ((Get-ItemProperty $uninstKey).DisplayVersion -eq $NewerVersion) "still version $NewerVersion"

Step "uninstall keeps the data folder"
$unins = "$app\unins000.exe"
Start-Process -FilePath $unins -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/LOG=$Work\unins1.log" | Out-Null
Wait-Until { -not (Test-Path "$app\varsto.exe") } "the program files to go"
Wait-Until { -not (Test-Path $app) -or -not (Get-ChildItem $app -ErrorAction SilentlyContinue) } "the folder to empty"
Check (@(Installed-Procs).Count -eq 0) "no Varsto process left"
Check (-not (Test-Path $uninstKey)) "uninstall entry removed"
Check (-not (Test-Path "HKCU:\Software\Varsto")) "install location removed from the registry"
Check ($null -eq (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue).Varsto) "autostart entry removed"
Check (-not (Test-Path $startMenu)) "Start menu shortcut removed"
Check (-not (Test-Path -LiteralPath "HKCU:\Software\Classes\*\shell\Varsto.Fetch")) "Explorer verbs removed"
Check (Test-Path "$home1\smoke-marker.txt") "the data folder is kept"

Step "uninstall with /DELETEDATA=1 removes the data folder"
$code = Run-Setup $Setup "$Work\setup5.log" @("/DIR=`"$app`"")
Check ($code -eq 0) "fresh install again (exit code $code)"
Start-Process -FilePath "$app\unins000.exe" -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/DELETEDATA=1", "/LOG=$Work\unins2.log" | Out-Null
Wait-Until { -not (Test-Path "$app\varsto.exe") } "the program files to go"
Wait-Until { -not (Test-Path $home1) } "the data folder to go" 60
Write-Host "== installer smoke test finished"
