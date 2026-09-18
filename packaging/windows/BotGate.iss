#ifndef AppVersion
#define AppVersion "0.0.0"
#endif

[Setup]
AppId={{7F8D9D9B-2D86-4CC9-B8B1-2D829E5D5B6A}
AppName=Bot Gate
AppVerName=Bot Gate
AppVersion={#AppVersion}
AppPublisher=Bot Gate
DefaultDirName={localappdata}\Programs\BotGate
DefaultGroupName=Bot Gate
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
CloseApplications=yes
RestartApplications=no
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=output
OutputBaseFilename=BotGate-{#AppVersion}-windows-x64-setup
SetupIconFile=staging\bot-gate.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\bot-gate.exe

[Files]
Source: "staging\bot-gate.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\bot-gate.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\config.toml"; DestDir: "{app}"; Flags: ignoreversion onlyifdoesntexist
Source: "staging\frontend\dist\*"; DestDir: "{app}\frontend\dist"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "staging\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Bot Gate"; Filename: "{app}\bot-gate.exe"; IconFilename: "{app}\bot-gate.ico"; WorkingDir: "{app}"
Name: "{commondesktop}\Bot Gate"; Filename: "{app}\bot-gate.exe"; IconFilename: "{app}\bot-gate.ico"; WorkingDir: "{app}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\bot-gate.exe"; Description: "Start Bot Gate"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent
