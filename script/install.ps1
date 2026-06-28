<#
.SYNOPSIS
    PactMesh Windows installer (x86_64).

.DESCRIPTION
    Downloads a PactMesh release from GitHub, installs pactmesh.exe /
    pactmesh-core.exe and their bundled drivers, and adds the install
    directory to the system PATH. Run `pactmesh quickstart` afterwards.

.PARAMETER Version
    "latest" (default) or a tag such as "v2.6.2".

.PARAMETER InstallDir
    Install directory. Default: "$env:ProgramFiles\PactMesh".

.PARAMETER GhProxy
    Optional GitHub download proxy prefix (e.g. https://ghfast.top/) for
    regions with poor GitHub connectivity.

.EXAMPLE
    .\install.ps1
    .\install.ps1 -Version v2.6.2
    .\install.ps1 -GhProxy https://ghfast.top/
#>
param(
    [Parameter(Position = 0)]
    [ValidatePattern('^(latest|v?\d+\.\d+\.\d+(-[^\s]+)?)$')]
    [string]$Version = 'latest',

    [Parameter(Position = 1)]
    [string]$InstallDir = "$env:ProgramFiles\PactMesh",

    [string]$GhProxy = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$GITHUB_REPO = 'Detachment-x/PactMesh'
$ASSET = 'pactmesh-windows-x86_64.zip'

# ---- Administrator check ----------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Please run this script as Administrator (the daemon needs a TUN device).'
    exit 1
}

# ---- Architecture guard -----------------------------------------------------
$cpuArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
if ($cpuArch -ne 'AMD64') {
    Write-Error "Prebuilt releases cover Windows x86_64 only (detected: $cpuArch). Build from source: https://github.com/$GITHUB_REPO"
    exit 1
}

Write-Host ''
Write-Host '  ===== PactMesh Windows Installer =====' -ForegroundColor Cyan
Write-Host ''

# ---- Resolve download URL ---------------------------------------------------
if ($Version -eq 'latest') {
    $base = "https://github.com/$GITHUB_REPO/releases/latest/download/$ASSET"
}
else {
    $tag = if ($Version -notmatch '^v') { "v$Version" } else { $Version }
    $base = "https://github.com/$GITHUB_REPO/releases/download/$tag/$ASSET"
}
$downloadUrl = if ($GhProxy) { "$($GhProxy.TrimEnd('/'))/$base" } else { $base }

# ---- Download ---------------------------------------------------------------
Write-Host "[1/4] Downloading $ASSET ..." -ForegroundColor Yellow
Write-Host "      $downloadUrl" -ForegroundColor DarkGray
$tempDir = Join-Path $env:TEMP "pactmesh-install-$(Get-Random)"
$zipPath = Join-Path $tempDir $ASSET
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -ErrorAction Stop
}
catch {
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    Write-Error "Download failed: $_`nDownload manually from https://github.com/$GITHUB_REPO/releases"
    exit 1
}

# ---- Extract ----------------------------------------------------------------
Write-Host '[2/4] Extracting...' -ForegroundColor Yellow
$extractDir = Join-Path $tempDir 'extracted'
New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
$exe = Get-ChildItem -Path $extractDir -Filter 'pactmesh.exe' -Recurse | Select-Object -First 1
if (-not $exe) {
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
    Write-Error 'pactmesh.exe not found in the archive.'
    exit 1
}
$binSource = $exe.DirectoryName

# ---- Install ----------------------------------------------------------------
Write-Host "[3/4] Installing to $InstallDir ..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Get-ChildItem -Path $binSource | Copy-Item -Destination $InstallDir -Force
Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
Write-Host "      Installed pactmesh.exe, pactmesh-core.exe and drivers." -ForegroundColor Green

# ---- PATH -------------------------------------------------------------------
Write-Host '[4/4] Updating system PATH...' -ForegroundColor Yellow
$systemPath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
$entries = $systemPath -split ';' | ForEach-Object { $_.TrimEnd('\') }
if ($entries -inotcontains $InstallDir.TrimEnd('\')) {
    [Environment]::SetEnvironmentVariable('PATH', "$systemPath;$InstallDir", 'Machine')
    $env:PATH = "$env:PATH;$InstallDir"
    Write-Host "      Added $InstallDir to system PATH." -ForegroundColor Green
}
else {
    Write-Host "      $InstallDir already on PATH." -ForegroundColor DarkGray
}

Write-Host ''
Write-Host '  [OK] PactMesh installed.' -ForegroundColor Green
Write-Host ''
Write-Host '  Next steps:' -ForegroundColor White
Write-Host '    1. First-run setup (creates your network, opens the web console):' -ForegroundColor White
Write-Host '         pactmesh quickstart' -ForegroundColor Green
Write-Host '       then open the printed http://127.0.0.1:15810/?token=... URL.'
Write-Host '    2. Optional - run the daemon as a Windows service:' -ForegroundColor White
Write-Host '         pactmesh service install ; pactmesh service start' -ForegroundColor Green
Write-Host ''
Write-Host '  NOTE: if PATH was just updated, restart your terminal.' -ForegroundColor DarkYellow
Write-Host "  Docs: https://github.com/$GITHUB_REPO" -ForegroundColor DarkGray
Write-Host ''
