# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# The Windows tray icon and the interface in its own window (Edge app mode),
# on a Windows machine with a desktop session (a GitHub runner or a VM).
#   scripts/screenshots/windows-desktop.ps1 -Exe <varsto.exe> -Work <dir> -Out <dir>
# Creates a small invented vault, starts the tray app (which starts the
# service), and writes windows-tray.png and windows-app.png.
param([Parameter(Mandatory)] [string]$Exe, [Parameter(Mandatory)] [string]$Work, [Parameter(Mandatory)] [string]$Out)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force $Work, $Out, "$Out\raw" | Out-Null
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type @"
using System; using System.Runtime.InteropServices;
public static class W32 {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int hh, bool repaint);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
"@
[W32]::SetProcessDPIAware() | Out-Null
function Shot([string]$path, [System.Drawing.Rectangle]$r) {
  $bmp = New-Object System.Drawing.Bitmap $r.Width, $r.Height
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.CopyFromScreen($r.X, $r.Y, 0, 0, $bmp.Size)
  $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
  $g.Dispose(); $bmp.Dispose()
}
try { Set-DisplayResolution -Width 1920 -Height 1080 -Force -ErrorAction Stop } catch { Write-Host "display resolution unchanged: $($_.Exception.Message)" }
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
Write-Host "screen $($screen.Width)x$($screen.Height)"
# Show every notification icon instead of hiding new ones in the overflow.
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name EnableAutoTray -Value 0 -PropertyType DWord -Force | Out-Null

$env:VARSTO_PASSPHRASE = "shots-passphrase-123"
$h = "$Work\home"; $st = "$Work\storage"; $docs = "$Work\Documents"
New-Item -ItemType Directory -Force $st, "$docs\Invoices" | Out-Null
"# Quarterly report`nSummary of the quarter: revenue grew, costs steady, three new hires." | Set-Content "$docs\Quarterly-report.md"
"- The Design of Everyday Things`n- Thinking in Systems`n- A Pattern Language" | Set-Content "$docs\Reading-list.txt"
"Invoice 2026-041`nTotal 1 240,00 EUR" | Set-Content "$docs\Invoices\2026-041.txt"
$bytes = New-Object byte[] 6000000; (New-Object Random 7).NextBytes($bytes); [IO.File]::WriteAllBytes("$docs\Archive-2025.zip", $bytes)
& $Exe --home $h init --name laptop | Out-Null
& $Exe --home $h storage add-local box $st | Out-Null
& $Exe --home $h folder add Documents $docs | Out-Null
& $Exe --home $h sync | Out-Null
Start-Process -FilePath $Exe -ArgumentList "--home", $h, "tray" -RedirectStandardOutput "$Work\tray.log" -RedirectStandardError "$Work\tray.err"
for ($i = 0; $i -lt 60 -and -not (Test-Path "$h\service.json"); $i++) { Start-Sleep 1 }
Start-Sleep 8
# Windows 11 / Server 2025 hide new notification icons in the overflow:
# promote Varsto's (the per-icon setting the taskbar settings page writes).
Get-ChildItem "HKCU:\Control Panel\NotifyIconSettings" -ErrorAction SilentlyContinue | ForEach-Object {
  $path = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ExecutablePath
  if ($path -and $path -like "*varsto*") { Set-ItemProperty $_.PSPath -Name IsPromoted -Value 1 -Type DWord; Write-Host "promoted tray icon of $path" }
}
Start-Sleep 4
Shot "$Out\raw\windows-desktop.png" $screen
# The taskbar corner with the notification area.
$tw = [Math]::Min(840, $screen.Width); $th = 120
Shot "$Out\windows-tray.png" (New-Object System.Drawing.Rectangle ($screen.Width - $tw), ($screen.Height - $th), $tw, $th)

# Also the overflow flyout, in case the icon stayed hidden.
try {
  Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
  $cond = New-Object System.Windows.Automation.PropertyCondition ([System.Windows.Automation.AutomationElement]::NameProperty), "Show Hidden Icons", ([System.Windows.Automation.PropertyConditionFlags]::IgnoreCase)
  $btn = [System.Windows.Automation.AutomationElement]::RootElement.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
  if ($btn) {
    $btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke(); Start-Sleep 2
    Shot "$Out\raw\windows-tray-overflow.png" (New-Object System.Drawing.Rectangle ($screen.Width - 840), ($screen.Height - 400), 840, 400)
    [System.Windows.Forms.SendKeys]::SendWait("{ESC}"); Start-Sleep 1
  } else { Write-Host "no Show Hidden Icons button" }
} catch { Write-Host "overflow capture: $($_.Exception.Message)" }
$sf = Get-Content "$h\service.json" | ConvertFrom-Json
$url = "http://127.0.0.1:$($sf.port)/?token=$($sf.token)"
$edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
$w = [Math]::Min(1280, $screen.Width); $hh = [Math]::Min(752, $screen.Height - 60)
$p = Start-Process -FilePath $edge -PassThru -ArgumentList "--app=$url", "--no-first-run", "--user-data-dir=$Work\edge-profile", "--window-size=$w,$hh", "--window-position=0,0"
Start-Sleep 15
$win = Get-Process msedge -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
if ($win) {
  [W32]::MoveWindow($win.MainWindowHandle, 0, 0, $w, $hh, $true) | Out-Null
  [W32]::SetForegroundWindow($win.MainWindowHandle) | Out-Null
  Start-Sleep 3
  $r = New-Object W32+RECT
  [W32]::GetWindowRect($win.MainWindowHandle, [ref]$r) | Out-Null
  # Windows 11 windows carry an invisible 7 px resize border left, right and bottom.
  $x = [Math]::Max(0, $r.L + 7); $y = [Math]::Max(0, $r.T); $cw = [Math]::Min($r.R - $r.L - 14, $screen.Width - $x); $ch = [Math]::Min($r.B - $r.T - 7, $screen.Height - $y)
  Shot "$Out\windows-app.png" (New-Object System.Drawing.Rectangle $x, $y, $cw, $ch)
  Write-Host "app window $cw x $ch at $x,$y"
} else {
  Write-Host "Edge window not found"
}
Shot "$Out\raw\windows-desktop-app.png" $screen
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$($sf.port)/api/quit" -Headers @{ "X-Varsto-Token" = $sf.token } -ErrorAction SilentlyContinue | Out-Null
Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-ChildItem $Out -Recurse | Format-Table FullName, Length | Out-String | Write-Host
