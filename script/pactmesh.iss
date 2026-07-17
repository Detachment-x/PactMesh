; PactMesh offline Windows installer (Inno Setup 6).
; Built in CI (per edition):
;   ISCC.exe //DAppVersion=<ver> //DEdition=<admin|member> \
;            //DSourceDir=<abs stage dir> //DOutDir=<abs out dir> script\pactmesh.iss
; SourceDir/OutDir are passed as ABSOLUTE paths so [Files]/[OutputDir] never
; depend on the script's own location.
;
; Editions share AppId + install dir so the admin package can be installed
; straight over a member install (in-place upgrade) to arm a device for the
; root upgrade -- trust-domain data under %APPDATA%\PactMesh is never touched.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "pactmesh-windows-x86_64"
#endif
#ifndef OutDir
  #define OutDir "."
#endif
#ifndef Edition
  #define Edition "admin"
#endif

#define MyAppName "PactMesh"
#define MyAppPublisher "PactMesh Project"
#define MyAppURL "https://github.com/Detachment-x/PactMesh"
#define MyAppExeName "pactmesh.exe"

[Setup]
AppId={{B9E7F3A2-4C1D-4E8B-9A6F-2D5C8E1A7B40}
AppName={#MyAppName}
AppVersion={#AppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
DefaultDirName={autopf}\PactMesh
DefaultGroupName=PactMesh
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes
PrivilegesRequired=admin
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
OutputDir={#OutDir}
#if Edition == "member"
OutputBaseFilename=pactmesh-member-setup-x86_64
UninstallDisplayName={#MyAppName} (Member)
#else
OutputBaseFilename=pactmesh-setup-x86_64
UninstallDisplayName={#MyAppName}
#endif
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addtopath"; Description: "Add PactMesh to the system PATH"; GroupDescription: "System integration:"
#if Edition == "admin"
Name: "desktopicon"; Description: "Create a desktop shortcut to the PactMesh console"; GroupDescription: "Shortcuts:"
Name: "traystartup"; Description: "Launch the PactMesh tray icon at sign-in"; GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "installservice"; Description: "Run PactMesh as an always-on background service (starts now and at every boot)"; GroupDescription: "Service:"
#endif

[Files]
Source: "{#SourceDir}\pactmesh.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\pactmesh-core.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\*.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\*.sys"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme skipifsourcedoesntexist

[Icons]
#if Edition == "admin"
Name: "{group}\PactMesh Console"; Filename: "{app}\{#MyAppExeName}"; Parameters: "web"; Comment: "Open the PactMesh web console in your browser"
Name: "{group}\PactMesh First-time Setup (advanced)"; Filename: "{app}\{#MyAppExeName}"; Parameters: "quickstart"; Comment: "Optional: create a network from the command line instead of the web console"
#else
Name: "{group}\PactMesh (join & status)"; Filename: "{app}\{#MyAppExeName}"; Parameters: "tui"; Comment: "Join a network and watch peers/status"
#endif
Name: "{group}\Uninstall PactMesh"; Filename: "{uninstallexe}"
#if Edition == "admin"
Name: "{autodesktop}\PactMesh Console"; Filename: "{app}\{#MyAppExeName}"; Parameters: "web"; Tasks: desktopicon
Name: "{userstartup}\PactMesh Tray"; Filename: "{app}\{#MyAppExeName}"; Parameters: "tray"; Tasks: traystartup
#endif

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath('{app}')

[Run]
#if Edition == "admin"
Filename: "{app}\{#MyAppExeName}"; Parameters: "service install --serve"; Flags: runhidden waituntilterminated; Tasks: installservice; StatusMsg: "Registering the always-on PactMesh service..."
Filename: "{app}\{#MyAppExeName}"; Parameters: "service start"; Flags: runhidden waituntilterminated; Tasks: installservice; StatusMsg: "Starting the PactMesh service..."
Filename: "{app}\{#MyAppExeName}"; Parameters: "web"; Description: "Open the PactMesh console now"; Flags: postinstall skipifsilent nowait
#endif

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "service stop"; Flags: runhidden; RunOnceId: "PactMeshSvcStop"
Filename: "{app}\{#MyAppExeName}"; Parameters: "service uninstall"; Flags: runhidden; RunOnceId: "PactMeshSvcUninstall"

[Code]
const
  EnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function NeedsAddPath(Param: string): Boolean;
var
  OrigPath, AppDir: string;
begin
  if not RegQueryStringValue(HKLM, EnvKey, 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  AppDir := ExpandConstant(Param);
  Result := Pos(';' + Uppercase(AppDir) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;

procedure RemoveFromPath(AppDir: string);
var
  OrigPath, NewPath: string;
begin
  if not RegQueryStringValue(HKLM, EnvKey, 'Path', OrigPath) then
    exit;
  NewPath := ';' + OrigPath + ';';
  StringChangeEx(NewPath, ';' + AppDir + ';', ';', True);
  if (Length(NewPath) > 0) and (NewPath[1] = ';') then
    Delete(NewPath, 1, 1);
  if (Length(NewPath) > 0) and (NewPath[Length(NewPath)] = ';') then
    Delete(NewPath, Length(NewPath), 1);
  RegWriteExpandStringValue(HKLM, EnvKey, 'Path', NewPath);
end;

#if Edition == "member"
// Member packages carry no console/governance code. Joining is a CLI step the
// user runs after install; point them at it once the files are in place.
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and (not WizardSilent) then
    MsgBox('PactMesh (member) is installed.' + #13#10 + #13#10 +
           'To join a network:' + #13#10 +
           '  1. Get an invite link from your network administrator.' + #13#10 +
           '  2. Open a new terminal and run:' + #13#10 +
           '       pactmesh trust accept-invite "<invite-link>"' + #13#10 +
           '  3. Bring up the data plane as a background service:' + #13#10 +
           '       pactmesh service install' + #13#10 +
           '       pactmesh service start' + #13#10 + #13#10 +
           'Or run "pactmesh tui" for an interactive join & status console.',
           mbInformation, MB_OK);
end;
#endif

// Trust-domain data lives under <RoamingAppData>\PactMesh. The console runs as
// the signed-in user; the always-on service runs as LocalSystem. Wipe both.
procedure PurgeData();
var
  UserDir, SysDir: string;
begin
  UserDir := ExpandConstant('{userappdata}\PactMesh');
  SysDir := ExpandConstant('{sys}\config\systemprofile\AppData\Roaming\PactMesh');
  if DirExists(UserDir) then
    DelTree(UserDir, True, True, True);
  if DirExists(SysDir) then
    DelTree(SysDir, True, True, True);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RemoveFromPath(ExpandConstant('{app}'));
    if not UninstallSilent then
      if MsgBox('Also delete PactMesh configuration and network data (keys, domains, networks)?'
                + #13#10 + 'This CANNOT be undone.' + #13#10 + #13#10
                + 'Choose No to keep your data for a future reinstall.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        PurgeData();
  end;
end;
