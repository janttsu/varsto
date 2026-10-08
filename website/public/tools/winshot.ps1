# Varsto build helper: in an interactive Windows session, download the Windows
# package, create a demo vault with invented files, start the tray app and
# capture the screen and the notification area. Results in C:\shots.
#   powershell -ep bypass -c "iwr -useb https://varsto.soderlund.in/tools/winshot.ps1 | iex"
$ErrorActionPreference = "Continue"; $ProgressPreference = "SilentlyContinue"
Start-Transcript -Path C:\winshot.log -Append | Out-Null
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  New-Item -ItemType Directory -Force C:\shots, C:\demo\files, C:\demo\storage | Out-Null
  $m = Invoke-RestMethod -UseBasicParsing https://varsto.soderlund.in/downloads/manifest.json
  $zipName = ($m.PSObject.Properties.Name | Where-Object { $_ -like "*windows*.zip" } | Select-Object -First 1)
  Invoke-WebRequest -UseBasicParsing "https://varsto.soderlund.in/downloads/$zipName" -OutFile C:\demo\varsto.zip
  Expand-Archive -Force C:\demo\varsto.zip -DestinationPath C:\demo\app
  $exe = Get-ChildItem C:\demo\app -Recurse -Filter varsto.exe | Select-Object -First 1 -ExpandProperty FullName
  $env:VARSTO_PASSPHRASE = "demo-passphrase-123"
  & $exe --home C:\demo\home init --name laptop | Out-Null
  & $exe --home C:\demo\home storage add-local box C:\demo\storage | Out-Null
  & $exe --home C:\demo\home folder add Documents C:\demo\files | Out-Null
  "notes" | Set-Content C:\demo\files\notes.md
  & $exe --home C:\demo\home sync | Out-Null
  Start-Process -FilePath $exe -ArgumentList "--home", "C:\demo\home", "tray" -WorkingDirectory C:\demo
  Start-Sleep -Seconds 10
  Add-Type -AssemblyName System.Windows.Forms, System.Drawing
  function Shot($path) {
    $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $bmp.Dispose()
  }
  Shot "C:\shots\windows-desktop.png"
  # The interface in its own window (Edge app mode: no tabs, no address bar).
  $sf = Get-Content C:\demo\home\service.json | ConvertFrom-Json
  $url = "http://127.0.0.1:$($sf.port)/?token=$($sf.token)"
  $edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
  if (-not (Test-Path $edge)) { $edge = "C:\Program Files\Microsoft\Edge\Application\msedge.exe" }
  Start-Process -FilePath $edge -ArgumentList "--app=$url", "--window-size=1280,820", "--window-position=0,0", "--no-first-run"
  Start-Sleep -Seconds 12
  Shot "C:\shots\windows-app.png"
  # Open the hidden-icons flyout (the chevron left of the system icons) and capture it.
  $sig = '[DllImport("user32.dll")] public static extern void mouse_event(int f, int x, int y, int d, int e);'
  $u = Add-Type -MemberDefinition $sig -Name M -Namespace W -PassThru
  $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point(($b.Width - 180), ($b.Height - 24))
  $u::mouse_event(2, 0, 0, 0, 0); $u::mouse_event(4, 0, 0, 0, 0)
  Start-Sleep -Seconds 2
  Shot "C:\shots\windows-tray-flyout.png"
  # Right-click the first icon of the flyout for its menu (best effort).
  [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point(($b.Width - 200), ($b.Height - 120))
  $u::mouse_event(8, 0, 0, 0, 0); $u::mouse_event(16, 0, 0, 0, 0)
  Start-Sleep -Seconds 2
  Shot "C:\shots\windows-tray-menu.png"
  Write-Host "shots done"
} finally { Stop-Transcript | Out-Null }
