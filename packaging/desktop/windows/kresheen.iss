; Inno Setup script for the Windows installer (run through build.py, which passes the /D defines).
; Per-user install: no administrator rights, files under %LOCALAPPDATA%\Programs\Kresheen, data under
; %LOCALAPPDATA%\Kresheen (kept on uninstall).
#ifndef AppVersion
  #error AppVersion is required
#endif

[Setup]
AppId={{6F1C2B9E-6C1F-4C7B-9C3A-5B8E2D4A7F10}
AppName=Kresheen
AppVersion={#AppVersion}
AppPublisher=Pecka Cyber LLC
AppPublisherURL=https://github.com/PeckaCyber/kresheen
DefaultDirName={localappdata}\Programs\Kresheen
DefaultGroupName=Kresheen
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#OutDir}
OutputBaseFilename={#OutName}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
LicenseFile={#AppDir}\LICENSE
UninstallDisplayName=Kresheen

[Files]
Source: "{#AppDir}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\Kresheen"; Filename: "{app}\kresheen.exe"; Comment: "Start Kresheen and open it in the browser"
Name: "{userdesktop}\Kresheen"; Filename: "{app}\kresheen.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Run]
Filename: "{app}\kresheen.exe"; Description: "Start Kresheen now"; Flags: nowait postinstall skipifsilent
