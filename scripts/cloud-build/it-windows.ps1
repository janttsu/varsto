# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Cross-platform integration test, Windows side: join the vault through the S3
# bucket, pull the Linux file, push one back, enable p2p and run the service.
param([string]$VaultKey, [string]$S3Endpoint, [string]$S3Region, [string]$S3Bucket, [string]$S3Key, [string]$S3Secret, [string]$PublicIp)
$ErrorActionPreference = "Stop"; $ProgressPreference = "SilentlyContinue"
Set-Location C:\it
Expand-Archive -Force varsto-windows.zip -DestinationPath .\unzipped
$exe = Join-Path (Get-ChildItem .\unzipped | Select-Object -First 1).FullName "varsto.exe"
$env:VARSTO_PASSPHRASE = "integration-test-passphrase"; $env:VARSTO_S3_SECRET = $S3Secret
$H = "C:\it\home"; New-Item -ItemType Directory -Force C:\it\files | Out-Null
& $exe --home $H join --name windows --vault-key $VaultKey --storage-name cloud --s3-endpoint $S3Endpoint --s3-region $S3Region --s3-bucket $S3Bucket --s3-access-key-id $S3Key
& $exe --home $H folder attach shared C:\it\files
& $exe --home $H sync
if (-not (Test-Path C:\it\files\from-linux.bin)) { throw "file from Linux did not arrive through S3" }
(Get-FileHash C:\it\files\from-linux.bin -Algorithm SHA256).Hash.ToLower() | Set-Content C:\it\from-linux.sha
$bytes = New-Object byte[] 1500000; (New-Object Random).NextBytes($bytes); [IO.File]::WriteAllBytes("C:\it\files\from-windows.bin", $bytes)
(Get-FileHash C:\it\files\from-windows.bin -Algorithm SHA256).Hash.ToLower() | Set-Content C:\it\from-windows.sha
& $exe --home $H sync
& $exe --home $H p2p enable --port 17893 --public "$($PublicIp):17893"
New-NetFirewallRule -DisplayName "Varsto p2p" -Direction Inbound -Protocol TCP -LocalPort 17893 -Action Allow | Out-Null
Start-Process -FilePath $exe -ArgumentList "--home", $H, "service", "run", "--port", "17890", "--interval", "60" -RedirectStandardOutput C:\it\service.log -RedirectStandardError C:\it\service.err
Start-Sleep -Seconds 6
Get-Content C:\it\service.log | Select-String "p2p" | Select-Object -First 1
Write-Host "WINDOWS_READY"
