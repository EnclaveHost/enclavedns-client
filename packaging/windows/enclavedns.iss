; EnclaveDNS client for Windows: the service, the CLI, and enabling it.
; Built by CI: ISCC /DAppVersion=x.y.z packaging\windows\enclavedns.iss
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{6C1E5B9A-3F5D-4E7B-9C1A-2D8E4F0B7A13}
AppName=EnclaveDNS
AppVersion={#AppVersion}
AppPublisher=Enclave Host, Inc.
AppPublisherURL=https://github.com/EnclaveHost/enclavedns-client
AppSupportURL=https://github.com/EnclaveHost/enclavedns-client/issues
DefaultDirName={autopf}\EnclaveDNS
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist
OutputBaseFilename=EnclaveDNS-Setup-{#AppVersion}-x64
LicenseFile=..\..\LICENSE
SetupIconFile=enclavedns.ico
UninstallDisplayIcon={app}\enclavedns.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes

[Tasks]
Name: "enable"; Description: "Use EnclaveDNS for this computer's DNS now, and trust its .eth-only certificate for HTTPS"
Name: "path"; Description: "Add enclavedns to the PATH (for the command line)"

[Files]
Source: "..\..\target\release\enclavedns.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "config.toml"; DestDir: "{commonappdata}\EnclaveDNS"; Flags: onlyifdoesntexist uninsneveruninstall

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: path; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\enclavedns.exe"; Parameters: "service install"; Flags: runhidden waituntilterminated; StatusMsg: "Registering the EnclaveDNS service..."
Filename: "{app}\enclavedns.exe"; Parameters: "service start"; Flags: runhidden waituntilterminated; StatusMsg: "Starting EnclaveDNS..."
Filename: "{app}\enclavedns.exe"; Parameters: "enable"; Flags: runhidden waituntilterminated; Tasks: enable; StatusMsg: "Pointing this computer's DNS at EnclaveDNS..."

[UninstallRun]
Filename: "{app}\enclavedns.exe"; Parameters: "disable"; Flags: runhidden waituntilterminated; RunOnceId: "EnclaveDNSDisable"
Filename: "{app}\enclavedns.exe"; Parameters: "service uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "EnclaveDNSService"

[UninstallDelete]
; the .eth CA (its key included) goes with the program
Type: filesandordirs; Name: "{commonappdata}\EnclaveDNS\state"

[Code]
function NeedsAddPath(Dir: string): Boolean;
var
  Paths: string;
begin
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', Paths) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') = 0;
end;

{ an upgrade replaces enclavedns.exe, which the running service holds open }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop EnclaveDNS', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(1500);
  Result := '';
end;
