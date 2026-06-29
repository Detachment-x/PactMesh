; PactMesh offline Windows installer (Inno Setup 6).
; Built in CI:
;   ISCC.exe //DAppVersion=<ver> //DSourceDir=<abs stage dir> //DOutDir=<abs out dir> script\pactmesh.iss
; SourceDir/OutDir are passed as ABSOLUTE paths so [Files]/[OutputDir] never
; depend on the script's own location.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "pactmesh-windows-x86_64"
#endif
#ifndef OutDir
  #define OutDir "."
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
OutputBaseFilename=pactmesh-setup-x86_64
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addtopath"; Description: "Add PactMesh to the system PATH"; GroupDescription: "System integration:"
Name: "desktopicon"; Description: "Create a desktop shortcut to the PactMesh console"; GroupDescription: "Shortcuts:"
Name: "traystartup"; Description: "Launch the PactMesh tray icon at sign-in"; GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "installservice"; Description: "Register the background service for boot auto-start (run 'pactmesh quickstart' first)"; GroupDescription: "Service (optional, advanced):"; Flags: unchecked

[Files]
Source: "{#SourceDir}\pactmesh.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\pactmesh-core.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\*.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\*.sys"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme skipifsourcedoesntexist

[Icons]
Name: "{group}\PactMesh Console"; Filename: "{app}\{#MyAppExeName}"; Parameters: "web"; Comment: "Open the PactMesh web console in your browser"
Name: "{group}\PactMesh First-time Setup"; Filename: "{app}\{#MyAppExeName}"; Parameters: "quickstart"; Comment: "Create your network and start the console"
Name: "{group}\Uninstall PactMesh"; Filename: "{uninstallexe}"
Name: "{autodesktop}\PactMesh Console"; Filename: "{app}\{#MyAppExeName}"; Parameters: "web"; Tasks: desktopicon
Name: "{userstartup}\PactMesh Tray"; Filename: "{app}\{#MyAppExeName}"; Parameters: "tray"; Tasks: traystartup

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath('{app}')

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "service install --serve"; Flags: runhidden waituntilterminated; Tasks: installservice; StatusMsg: "Registering PactMesh service..."
Filename: "{app}\{#MyAppExeName}"; Parameters: "quickstart"; Description: "Run first-time setup now (creates your network)"; Flags: postinstall skipifsilent nowait unchecked

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

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
