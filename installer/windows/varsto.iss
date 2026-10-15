; SPDX-License-Identifier: PolyForm-Shield-1.0.0
; Inno Setup script of the Varsto installer for Windows.
;
;   iscc /DAppVersion=0.0.1-alpha.14 /DSourceDir=<folder with varsto.exe and varsto-window.exe> installer\windows\varsto.iss
;
; installer\windows\build.ps1 does the whole build (icon, WebView2 bootstrapper,
; compiler). Output: Varsto-<AppVersion>-setup.exe.
;
; Per-user by default (no administrator rights, %LOCALAPPDATA%\Programs\Varsto);
; the first page offers "for all users" with elevation. The AppId below never
; changes: it is how a new version finds the old installation and replaces it.

#ifndef AppVersion
  #error Pass the version: iscc /DAppVersion=0.0.1-alpha.14 ...
#endif
#ifndef NumericVersion
  #define NumericVersion "0.0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist\windows\app"
#endif
#ifndef BuildDir
  #define BuildDir "build"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist\installer"
#endif
#define AppGuid "{96573B8D-1FD3-43CC-A3E7-81032D8F53B8}"
#define WebView2Setup BuildDir + "\MicrosoftEdgeWebview2Setup.exe"

[Setup]
AppId={{96573B8D-1FD3-43CC-A3E7-81032D8F53B8}
AppName=Varsto
AppVersion={#AppVersion}
AppVerName=Varsto {#AppVersion}
AppPublisher=Varsto
AppPublisherURL=https://varsto.net
AppSupportURL=https://varsto.net
AppUpdatesURL=https://varsto.net/downloads/
AppCopyright=Varsto
VersionInfoVersion={#NumericVersion}
VersionInfoProductName=Varsto
VersionInfoDescription=Varsto setup
DefaultDirName={autopf}\Varsto
DefaultGroupName=Varsto
DisableProgramGroupPage=yes
UsePreviousAppDir=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
SetupIconFile={#BuildDir}\varsto.ico
UninstallDisplayIcon={app}\varsto.ico
UninstallDisplayName=Varsto
OutputDir={#OutputDir}
OutputBaseFilename=Varsto-{#AppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Running Varsto (service, tray, window) is closed before the files are
; replaced, with the Restart Manager as a second line after the explicit stop
; in [Code]. Varsto is started again by [Run], so no application restart.
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "{#SourceDir}\varsto.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\varsto-window.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\varsto.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceDir}\NOTICE"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceDir}\TRADEMARK.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
#if FileExists(WebView2Setup)
; Microsoft's Evergreen bootstrapper: only run when no WebView2 runtime is installed.
Source: "{#WebView2Setup}"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: WebView2Missing
#endif

[InstallDelete]
; Leftovers of the zip updater (the old binary is renamed aside while it runs).
Type: files; Name: "{app}\varsto.old"
Type: files; Name: "{app}\varsto.new"
Type: files; Name: "{app}\varsto-window.old"
Type: files; Name: "{app}\varsto-window.new"
Type: files; Name: "{app}\*.old"

[Icons]
; The AppUserModelID lets the service's notifications ("update available")
; come from Varsto with its icon.
Name: "{autoprograms}\Varsto"; Filename: "{app}\varsto-window.exe"; WorkingDir: "{app}"; IconFilename: "{app}\varsto.ico"; AppUserModelID: "Varsto.Notifier"
Name: "{autoprograms}\Uninstall Varsto"; Filename: "{uninstallexe}"; IconFilename: "{app}\varsto.ico"
Name: "{autodesktop}\Varsto"; Filename: "{app}\varsto-window.exe"; WorkingDir: "{app}"; IconFilename: "{app}\varsto.ico"; Tasks: desktopicon; AppUserModelID: "Varsto.Notifier"

[Registry]
; Where Varsto is installed, for scripts and other programs.
Root: HKA; Subkey: "Software\Varsto"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Varsto"; ValueType: string; ValueName: "Version"; ValueData: "{#AppVersion}"
; Start the background service and tray at login (no console window flashes:
; varsto-window.exe --background starts the tray app invisibly and exits).
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Varsto"; ValueData: """{app}\varsto-window.exe"" --background"; Flags: uninsdeletevalue
; The sender name of notifications.
Root: HKCU; Subkey: "Software\Classes\AppUserModelId\Varsto.Notifier"; ValueType: string; ValueName: "DisplayName"; ValueData: "Varsto"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\AppUserModelId\Varsto.Notifier"; ValueType: string; ValueName: "IconUri"; ValueData: "{app}\varsto.ico"

[Run]
#if FileExists(WebView2Setup)
Filename: "{tmp}\MicrosoftEdgeWebview2Setup.exe"; Parameters: "/silent /install"; StatusMsg: "Installing the Microsoft Edge WebView2 Runtime..."; Flags: waituntilterminated runhidden; Check: WebView2Missing
#endif
; Explorer integration and the other login-time pieces `varsto install` sets
; up for this user, then drop its console-window starter in favour of the Run key.
Filename: "{app}\varsto.exe"; Parameters: "install"; StatusMsg: "Setting up Varsto for this user..."; Flags: waituntilterminated runhidden runasoriginaluser
Filename: "{cmd}"; Parameters: "/C del /Q ""%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\Varsto.cmd"""; Flags: waituntilterminated runhidden runasoriginaluser
; Varsto is running again after an upgrade (also a silent one).
Filename: "{app}\varsto.exe"; Parameters: "tray"; Flags: nowait runhidden runasoriginaluser
Filename: "{app}\varsto-window.exe"; Description: "Open Varsto"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{app}\varsto.exe"; Parameters: "uninstall"; RunOnceId: "VarstoUninstall"; Flags: waituntilterminated runhidden

[UninstallDelete]
; Window position and the WebView2 profile are caches, not user data.
Type: filesandordirs; Name: "{localappdata}\Varsto"

[Code]
const
  UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#AppGuid}_is1';
  WebView2Id = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';

// ---- versions -----------------------------------------------------------

function TakeNumber(var S: String): Integer;
var
  P: Integer;
begin
  P := 1;
  while (P <= Length(S)) and (S[P] >= '0') and (S[P] <= '9') do
    P := P + 1;
  Result := StrToIntDef(Copy(S, 1, P - 1), 0);
  Delete(S, 1, P - 1);
  if (Length(S) > 0) and (S[1] = '.') then
    Delete(S, 1, 1);
end;

// "0.0.1-alpha.14" as numbers: major, minor, patch, pre-release rank
// (none ranks above alpha < beta < rc), pre-release number.
procedure SplitVersion(V: String; var K: array of Integer);
var
  P, I: Integer;
  Pre, Tag: String;
begin
  P := Pos('-', V);
  Pre := '';
  if P > 0 then
  begin
    Pre := Copy(V, P + 1, Length(V));
    V := Copy(V, 1, P - 1);
  end;
  for I := 0 to 2 do
    K[I] := TakeNumber(V);
  if Pre = '' then
  begin
    K[3] := 9;
    K[4] := 0;
  end
  else
  begin
    P := Pos('.', Pre);
    if P > 0 then
    begin
      Tag := Copy(Pre, 1, P - 1);
      Delete(Pre, 1, P);
      K[4] := TakeNumber(Pre);
    end
    else
    begin
      Tag := Pre;
      K[4] := 0;
    end;
    if Tag = 'alpha' then K[3] := 1
    else if Tag = 'beta' then K[3] := 2
    else if Tag = 'rc' then K[3] := 3
    else K[3] := 0;
  end;
end;

// -1 when A is older than B, 0 when equal, 1 when newer.
function CompareVersions(A, B: String): Integer;
var
  KA, KB: array of Integer;
  I: Integer;
begin
  SetArrayLength(KA, 5);
  SetArrayLength(KB, 5);
  SplitVersion(A, KA);
  SplitVersion(B, KB);
  Result := 0;
  for I := 0 to 4 do
  begin
    if KA[I] < KB[I] then
    begin
      Result := -1;
      Exit;
    end;
    if KA[I] > KB[I] then
    begin
      Result := 1;
      Exit;
    end;
  end;
end;

// ---- the installation that is there already -------------------------------

function ReadUninstallValue(Name: String): String;
begin
  Result := '';
  if not RegQueryStringValue(HKCU, UninstallKey, Name, Result) then
    if not RegQueryStringValue(HKLM, UninstallKey, Name, Result) then
      Result := '';
end;

function InstalledVersion(): String;
begin
  Result := ReadUninstallValue('DisplayVersion');
end;

function InstalledDir(): String;
begin
  Result := RemoveBackslash(ReadUninstallValue('InstallLocation'));
end;

// ---- stopping Varsto -------------------------------------------------------

function Quote(S: String): String;
begin
  Result := S;
  StringChangeEx(Result, '''', '''''', True);
end;

function RunPowerShell(Script: String): Integer;
var
  Code: Integer;
begin
  Code := -1;
  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Script + '"',
    '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := Code;
end;

// Lists the processes that run from Dir (this PowerShell excluded).
function ProcessesIn(Dir: String): String;
begin
  Result := '$d = ''' + Quote(Dir) + '\'';' +
    '$p = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and ' +
    '$_.ExecutablePath.StartsWith($d, [StringComparison]::OrdinalIgnoreCase) -and $_.ProcessId -ne $PID });';
end;

// Closes the window, the tray and the service of the installation in Dir,
// in that order: the tray would start a stopped service again. The service
// is asked to quit (it finishes what it writes); what is left after twenty
// seconds is ended.
procedure StopVarsto(Dir: String);
var
  Code: Integer;
begin
  if (Dir = '') or not DirExists(Dir) then Exit;
  RunPowerShell(ProcessesIn(Dir) +
    '$p | Where-Object { $_.Name -eq ''varsto-window.exe'' -or ($_.Name -eq ''varsto.exe'' -and $_.CommandLine -match ''\btray\b'') } | ' +
    'ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }');
  if FileExists(Dir + '\varsto.exe') then
    Exec(Dir + '\varsto.exe', 'service stop', '', SW_HIDE, ewWaitUntilTerminated, Code);
  RunPowerShell(ProcessesIn(Dir) +
    'for ($i = 0; $i -lt 40 -and $p.Count -gt 0; $i++) { Start-Sleep -Milliseconds 500; ' +
    '$d = ''' + Quote(Dir) + '\''; ' +
    '$p = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($d, [StringComparison]::OrdinalIgnoreCase) -and $_.ProcessId -ne $PID }) }; ' +
    '$p | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }');
end;

// ---- WebView2 ----------------------------------------------------------------

function WebView2Missing(): Boolean;
var
  V: String;
begin
  Result := True;
  if RegQueryStringValue(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\' + WebView2Id, 'pv', V) and (V <> '') and (V <> '0.0.0.0') then Result := False
  else if RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\' + WebView2Id, 'pv', V) and (V <> '') and (V <> '0.0.0.0') then Result := False
  else if RegQueryStringValue(HKCU, 'Software\Microsoft\EdgeUpdate\Clients\' + WebView2Id, 'pv', V) and (V <> '') and (V <> '0.0.0.0') then Result := False;
end;

// ---- setup ---------------------------------------------------------------------

// Is Varsto installed already? Say what Setup is about to do (upgrade, repair,
// downgrade). Silent runs take the default answer: upgrade and repair go on,
// a downgrade does not.
function InitializeSetup(): Boolean;
var
  Old: String;
  C: Integer;
begin
  Result := True;
  Old := InstalledVersion();
  if Old = '' then Exit;
  C := CompareVersions(Old, '{#AppVersion}');
  if C = 0 then
    Result := SuppressibleMsgBox('Varsto ' + Old + ' is already installed.' + #13#10#13#10 +
      'Setup will repair the installation: it replaces the program files with a fresh copy and starts Varsto again. ' +
      'Your vault, settings and files are not touched.' + #13#10#13#10 + 'Continue?',
      mbConfirmation, MB_YESNO, IDYES) = IDYES
  else if C < 0 then
    Result := SuppressibleMsgBox('Varsto ' + Old + ' is installed. Setup will upgrade it to {#AppVersion}.' + #13#10#13#10 +
      'Varsto is closed for a moment and starts again afterwards. Your vault, settings and files are kept.' + #13#10#13#10 + 'Continue?',
      mbConfirmation, MB_YESNO, IDYES) = IDYES
  else
    Result := SuppressibleMsgBox('A newer Varsto, ' + Old + ', is installed; this Setup would install the older {#AppVersion}.' + #13#10#13#10 +
      'Install the older version anyway?', mbConfirmation, MB_YESNO, IDNO) = IDYES;
end;

// Varsto must not be running when its files are replaced.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Old: String;
begin
  Result := '';
  Old := InstalledDir();
  if Old <> '' then StopVarsto(Old);
  if CompareText(Old, RemoveBackslash(WizardDirValue)) <> 0 then StopVarsto(RemoveBackslash(WizardDirValue));
end;

// ---- uninstall -----------------------------------------------------------------

function DataDir(): String;
begin
  Result := GetEnv('VARSTO_HOME');
  if Result = '' then Result := GetEnv('APPDATA') + '\Varsto';
end;

function InitializeUninstall(): Boolean;
begin
  Result := True;
  StopVarsto(RemoveBackslash(ExpandConstant('{app}')));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Dir: String;
  Wipe: Boolean;
begin
  if CurUninstallStep <> usPostUninstall then Exit;
  Dir := DataDir();
  if not DirExists(Dir) then Exit;
  Wipe := ExpandConstant('{param:DELETEDATA|0}') = '1';
  if (not Wipe) and (not UninstallSilent) then
    Wipe := MsgBox('Varsto has been removed. Delete its data folder too?' + #13#10#13#10 + Dir + #13#10#13#10 +
      'It holds this device''s key, settings and caches. Your files in your own folders and in your storages are not touched, ' +
      'but without this folder (or the vault key) this device cannot open the vault again.' + #13#10#13#10 +
      'Keep it unless you are sure.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
  if Wipe then DelTree(Dir, True, True, True);
end;
