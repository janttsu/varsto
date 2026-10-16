# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Build Varsto-<version>-setup.exe with Inno Setup.
#
#   installer\windows\build.ps1 -Version 0.0.1-alpha.14 -Source <folder> [-Out dist\installer]
#
# <folder> holds varsto.exe, varsto-window.exe and the licence files (CI: the
# windows-programs artifact, made by website/build-release.sh). The script makes the multi-size icon from the brand
# PNG files, fetches Microsoft's WebView2 bootstrapper for the installer to
# carry (skipped with -NoWebView2; the installer then runs without that
# check), finds or installs Inno Setup 6, and compiles installer\windows\varsto.iss.
param(
  [Parameter(Mandatory)] [string]$Version,
  [Parameter(Mandatory)] [string]$Source,
  [string]$Out = "dist\installer",
  [switch]$NoWebView2
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = (Resolve-Path (Join-Path $here "..\..")).Path
$Source = (Resolve-Path $Source).Path
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$build = Join-Path $here "build"
New-Item -ItemType Directory -Force $build | Out-Null

foreach ($f in "varsto.exe", "varsto-window.exe") {
  if (-not (Test-Path (Join-Path $Source $f))) { throw "$f is not in $Source" }
}

# 0.0.1-alpha.14 -> 0.0.1.14 (Windows file version: four numbers).
if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)(?:-[A-Za-z]+\.(\d+))?$') { throw "unexpected version $Version" }
$numeric = "$($Matches[1]).$($Matches[2]).$($Matches[3]).$(if ($Matches[4]) { $Matches[4] } else { 0 })"

$py = (Get-Command python3 -ErrorAction SilentlyContinue) ?? (Get-Command python -ErrorAction Stop)
& $py.Source -I (Join-Path $here "make-ico.py") (Join-Path $build "varsto.ico")
if ($LASTEXITCODE -ne 0) { throw "make-ico.py failed" }

$boot = Join-Path $build "MicrosoftEdgeWebview2Setup.exe"
if (-not $NoWebView2) {
  if (-not (Test-Path $boot)) {
    Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile $boot
  }
  $sig = Get-AuthenticodeSignature $boot
  if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "Microsoft Corporation") {
    Remove-Item $boot -Force
    throw "the WebView2 bootstrapper is not signed by Microsoft ($($sig.Status))"
  }
} elseif (Test-Path $boot) { Remove-Item $boot -Force }

$iscc = (Get-Command iscc -ErrorAction SilentlyContinue).Source
if (-not $iscc) {
  $iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $iscc) {
  Write-Host "installing Inno Setup"
  choco install innosetup -y --no-progress | Out-Host
  $iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $iscc) { throw "Inno Setup (ISCC.exe) not found" }
Write-Host "compiler: $iscc"

& $iscc "/DAppVersion=$Version" "/DNumericVersion=$numeric" "/DSourceDir=$Source" "/DBuildDir=$build" "/DOutputDir=$Out" "/Qp" (Join-Path $here "varsto.iss")
if ($LASTEXITCODE -ne 0) { throw "ISCC failed ($LASTEXITCODE)" }
$setup = Join-Path $Out "Varsto-$Version-setup.exe"
if (-not (Test-Path $setup)) { throw "$setup was not produced" }
Write-Host "built $setup ($([math]::Round((Get-Item $setup).Length / 1MB, 1)) MB)"
