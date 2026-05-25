; Inno Setup script for Privet Windows installer.
;
; Build order:
;   1. cargo build --release -p privet-ffi      # Rust FFI library
;   2. flutter build windows --release           # Flutter app
;   3. ISCC.exe scripts\innosetup.iss            # Package installer
;
; Optional: Download the VC++ Redistributable (vc_redist.x64.exe) from
; https://aka.ms/vs/17/release/vc_redist.x64.exe and place it next to
; this script so the installer can deploy it on machines that don't
; already have the runtime.
;
; NOTE: This script uses ISPP (Inno Setup Preprocessor). Requires
; Inno Setup 6 (or later).

#define MyAppName      "Privet"
#define MyAppVersion   GetFileVersion("..\privet_app\build\windows\x64\runner\Release\Privet.exe")
#define MyAppPublisher "Privet"
#define MyAppURL       "https://github.com/zerosignal/privet"
#define MyAppExeName   "Privet.exe"
#define MyAppId        "E6E4D5A6-8B2C-4A3D-9F1E-7C5D8B3A2F4E"

#define BuildDir       "..\privet_app\build\windows\x64\runner\Release"
#define RedistFile     "vc_redist.x64.exe"

[Setup]
AppName                    = {#MyAppName}
AppVersion                 = {#MyAppVersion}
AppVerName                 = {#MyAppName} {#MyAppVersion}
AppPublisher               = {#MyAppPublisher}
AppPublisherURL            = {#MyAppURL}
AppSupportURL              = {#MyAppURL}
AppUpdatesURL              = {#MyAppURL}
DefaultDirName             = {autopf}\{#MyAppName}
DefaultGroupName           = {#MyAppName}
DisableProgramGroupPage    = yes
DisableDirPage             = auto
OutputDir                  = ..\dist
OutputBaseFilename         = Privet-Setup-{#MyAppVersion}
SetupIconFile              = ..\privet_app\windows\runner\resources\app_icon.ico
UninstallDisplayIcon       = {app}\{#MyAppExeName}
UninstallDisplayName       = {#MyAppName}
Compression                = lzma2/ultra64
SolidCompression           = yes
ArchitecturesInstallIn64BitMode = x64compatible
MinVersion                 = 10.0.17763
PrivilegesRequired         = admin
CloseApplications          = yes
AppId                      = {{E6E4D5A6-8B2C-4A3D-9F1E-7C5D8B3A2F4E}
ChangesEnvironment         = no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; ---- Files to install ----
[Files]
; Main executable and DLLs
Source: "{#BuildDir}\{#MyAppExeName}";                    DestDir: "{app}";     Flags: ignoreversion
Source: "{#BuildDir}\flutter_windows.dll";                 DestDir: "{app}";     Flags: ignoreversion
Source: "{#BuildDir}\privet_ffi.dll";                      DestDir: "{app}";     Flags: ignoreversion
Source: "{#BuildDir}\dartjni.dll";                         DestDir: "{app}";     Flags: ignoreversion
Source: "{#BuildDir}\url_launcher_windows_plugin.dll";     DestDir: "{app}";     Flags: ignoreversion

; AOT and ICU data
Source: "{#BuildDir}\data\app.so";                         DestDir: "{app}\data";      Flags: ignoreversion
Source: "{#BuildDir}\data\icudtl.dat";                     DestDir: "{app}\data";      Flags: ignoreversion

; Flutter assets (recursive)
Source: "{#BuildDir}\data\flutter_assets\*";               DestDir: "{app}\data\flutter_assets"; Flags: ignoreversion recursesubdirs createallsubdirs

; VC++ Redistributable (optional — bundle manually before building)
Source: "{#RedistFile}";                                   DestDir: "{tmp}";     Flags: ignoreversion skipifsourcedoesntexist

; ---- Shortcuts ----
[Icons]
Name: "{autoprograms}\{#MyAppName}";                      Filename: "{app}\{#MyAppExeName}"
Name: "{autoprograms}\Uninstall {#MyAppName}";             Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";                        Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

; ---- Tasks ----
[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"; Flags: checkedonce

; ---- Install VC++ redist before app files (if bundled) ----
[Run]
Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/quiet /norestart"; StatusMsg: "Installing VC++ Redistributable..."; Check: VCRedistNeedsInstall and FileExists(ExpandConstant('{tmp}\vc_redist.x64.exe')); Flags: skipifdoesntexist

; ---- Uninstall ----
[UninstallRun]
; Default file removal is sufficient.

; ---- Code: VC++ Redistributable detection ----
[Code]
function VCRedistNeedsInstall: Boolean;
var
  Version: String;
begin
  if RegQueryStringValue(HKLM,
       'SOFTWARE\Microsoft\VisualStudio\VC\Runtimes\x64',
       'Version', Version) then
  begin
    Result := (CompareText(Version, 'v14') < 0);
  end
  else if RegQueryStringValue(HKLM,
       'SOFTWARE\WOW6432Node\Microsoft\VisualStudio\VC\Runtimes\x64',
       'Version', Version) then
  begin
    Result := (CompareText(Version, 'v14') < 0);
  end
  else
    Result := True;
end;
