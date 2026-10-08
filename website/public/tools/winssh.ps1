# Varsto build helper for fresh Windows Server machines on Scaleway: install
# and enable OpenSSH Server, trust the project's SSH keys from the instance
# metadata, make PowerShell the SSH shell. Run from an interactive session:
#   powershell -ep bypass -c "iwr -useb https://varsto.soderlund.in/tools/winssh.ps1 | iex"
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
Start-Transcript -Path C:\winssh.log -Append | Out-Null
try {
  $svc = Get-Service sshd -ErrorAction SilentlyContinue
  if (-not $svc) {
    Write-Host "Installing OpenSSH Server capability"
    try { Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null } catch { Write-Host "capability install failed: $_" }
    $svc = Get-Service sshd -ErrorAction SilentlyContinue
  }
  if (-not $svc) {
    Write-Host "Falling back to the Win32-OpenSSH MSI from GitHub"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $rel = Invoke-RestMethod -UseBasicParsing https://api.github.com/repos/PowerShell/Win32-OpenSSH/releases/latest
    $asset = $rel.assets | Where-Object { $_.name -like "OpenSSH-Win64*.msi" } | Select-Object -First 1
    Invoke-WebRequest -UseBasicParsing $asset.browser_download_url -OutFile C:\openssh.msi
    Start-Process msiexec.exe -ArgumentList "/i C:\openssh.msi /qn ADDLOCAL=Server" -Wait
  }
  Set-Service sshd -StartupType Automatic
  Start-Service sshd
  New-Item -ItemType Directory -Force C:\ProgramData\ssh | Out-Null
  $keys = @()
  try {
    $conf = Invoke-RestMethod -UseBasicParsing http://169.254.42.42/conf?format=json
    $keys = @($conf.ssh_public_keys | ForEach-Object { $_.key })
  } catch { Write-Host "metadata keys unavailable: $_" }
  if ($env:K) { $keys += $env:K }
  if ($keys.Count -gt 0) {
    Set-Content -Path C:\ProgramData\ssh\administrators_authorized_keys -Value ($keys -join "`n") -Encoding ascii
    icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null
  }
  New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -PropertyType String -Force | Out-Null
  if (-not (Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name sshd -DisplayName "OpenSSH" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
  }
  Restart-Service sshd
  Write-Host "OpenSSH ready: $((Get-Service sshd).Status), keys: $($keys.Count)"
} finally { Stop-Transcript | Out-Null }
