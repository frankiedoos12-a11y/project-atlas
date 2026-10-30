; Inno Setup recipe for ProjectAtlas-Setup.exe. Run build.ps1, not this directly.
;
; Installs for the current user only (no administrator prompt) into
; %LOCALAPPDATA%\Programs\Project Atlas, with Start menu and desktop shortcuts.
; Settings, history, quarantine and the VirusTotal key live elsewhere and survive
; updates and uninstalling.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6C2E8F4B-7A51-4D4E-9B0E-5A7C1E2D9F31}
AppName=Project Atlas
AppVersion={#AppVersion}
AppVerName=Project Atlas {#AppVersion}
AppPublisher=PugTheSecurity
AppPublisherURL=https://github.com/frankiedoos12-a11y/project-atlas
AppSupportURL=https://github.com/frankiedoos12-a11y/project-atlas/issues
DefaultDirName={localappdata}\Programs\Project Atlas
DefaultGroupName=Project Atlas
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=lowest
OutputDir=dist
OutputBaseFilename=ProjectAtlas-Setup
SetupIconFile=build\atlas.ico
UninstallDisplayIcon={app}\ProjectAtlas.exe
UninstallDisplayName=Project Atlas
LicenseFile=..\LICENSE
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
CloseApplications=force
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "Put Project Atlas on the desktop"
Name: "autostart"; Description: "Start protection when I sign in to Windows (recommended)"
Name: "contextmenu"; Description: "Add ""Scan with Project Atlas"" when I right-click a file"
Name: "browserhelper"; Description: "Let the Atlas browser extension check links"
Name: "service"; Description: "Keep protection running: start Atlas again if it's closed or stopped (asks for administrator approval)"

[Files]
Source: "dist\ProjectAtlas\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; The service's program: `atlas service install` copies it to Program Files.
Source: "dist\ProjectAtlasService\*"; DestDir: "{app}\service"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; Old library files from the previous version.
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{autoprograms}\Project Atlas"; Filename: "{app}\ProjectAtlas.exe"; Comment: "Open the Project Atlas window"
Name: "{autodesktop}\Project Atlas"; Filename: "{app}\ProjectAtlas.exe"; Comment: "Open the Project Atlas window"; Tasks: desktopicon

[Run]
Filename: "{app}\atlas.exe"; Parameters: "autostart on"; Flags: runhidden; Tasks: autostart
Filename: "{app}\atlas.exe"; Parameters: "context-menu on"; Flags: runhidden; Tasks: contextmenu
Filename: "{app}\atlas.exe"; Parameters: "browser-extension on"; Flags: runhidden; Tasks: browserhelper
; Silent updates (from the tray) don't ask for an administrator: the service already installed keeps working.
Filename: "{app}\atlas.exe"; Parameters: "service install"; Verb: "runas"; Flags: shellexec runhidden waituntilterminated; Tasks: service; Check: not WizardSilent
; Updates run silently: start the tray again afterwards.
Filename: "{app}\ProjectAtlas.exe"; Parameters: "-m atlas.tray"; Flags: nowait runasoriginaluser; Tasks: autostart; Check: WizardSilent
Filename: "{app}\ProjectAtlas.exe"; Description: "Open Project Atlas now"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{app}\atlas.exe"; Parameters: "service uninstall"; Verb: "runas"; Flags: shellexec runhidden waituntilterminated; RunOnceId: "RemoveService"; Check: ServiceInstalled
Filename: "{app}\atlas.exe"; Parameters: "autostart off --only-mine"; Flags: runhidden; RunOnceId: "AutostartOff"
Filename: "{app}\atlas.exe"; Parameters: "context-menu off --only-mine"; Flags: runhidden; RunOnceId: "ContextMenuOff"
Filename: "{app}\atlas.exe"; Parameters: "browser-extension off --only-mine"; Flags: runhidden; RunOnceId: "BrowserHelperOff"
Filename: "{cmd}"; Parameters: "/c taskkill /f /im ProjectAtlas.exe"; Flags: runhidden; RunOnceId: "StopAtlas"

[Code]
// While files are replaced, the service mustn't start the tray (it would lock them). It ignores this file
// after 10 minutes, in case it's left behind.
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  ForceDirectories(ExpandConstant('{app}'));
  SaveStringToFile(ExpandConstant('{app}\updating'), 'Project Atlas is being installed', False);
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    DeleteFile(ExpandConstant('{app}\updating'));
end;

function ServiceInstalled: Boolean;
begin
  Result := RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\ProjectAtlas');
end;
