#Requires -RunAsAdministrator
<#
.SYNOPSIS
    HispanShield Antivirus — Manual Installation Script
.DESCRIPTION
    Installs the HispanShield security agent as a Windows Service
    and sets up the dashboard shortcut.
.PARAMETER InstallDir
    Installation directory (default: C:\Program Files\HispanShield)
.PARAMETER DataDir
    Data directory (default: C:\ProgramData\HispanShield)
.PARAMETER Uninstall
    Uninstall HispanShield
.PARAMETER Force
    Force reinstall even if already installed
.EXAMPLE
    .\install.ps1
    .\install.ps1 -Uninstall
    .\install.ps1 -InstallDir "D:\HispanShield" -Force
#>
param(
    [string]$InstallDir = "C:\Program Files\HispanShield",
    [string]$DataDir    = "C:\ProgramData\HispanShield",
    [switch]$Uninstall,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ServiceName = "HispanShieldAgent"
$AgentExe    = Join-Path $InstallDir "bin\hispanshield-agent.exe"
$UIExe       = Join-Path $InstallDir "hispanshield-ui.exe"

function Write-Step  { param($msg) Write-Host "  [*] $msg" -ForegroundColor Cyan }
function Write-OK    { param($msg) Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Error { param($msg) Write-Host "  [-] $msg" -ForegroundColor Red; exit 1 }

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║     HispanShield Antivirus v0.1.0        ║" -ForegroundColor Cyan
Write-Host "  ║     Windows Security Agent Installer     ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Uninstall mode ────────────────────────────────────────────────────────────
if ($Uninstall) {
    Write-Step "Stopping service..."
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue

    Write-Step "Removing service..."
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        sc.exe delete $ServiceName | Out-Null
        Write-OK "Service removed"
    } else {
        Write-Warn "Service not found"
    }

    Write-Step "Removing installation files..."
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue

    Write-Step "Removing shortcuts..."
    Remove-Item "$env:PUBLIC\Desktop\HispanShield Antivirus.lnk" -ErrorAction SilentlyContinue
    Remove-Item "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\HispanShield" -Recurse -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "  [+] HispanShield uninstalled successfully." -ForegroundColor Green
    Write-Host "      Data and logs preserved at: $DataDir" -ForegroundColor Gray
    Write-Host "      Delete manually if no longer needed." -ForegroundColor Gray
    Write-Host ""
    exit 0
}

# ── Pre-checks ────────────────────────────────────────────────────────────────
$scriptDir = Split-Path $MyInvocation.MyCommand.Path
$repoRoot  = Split-Path (Split-Path $scriptDir)
$agentSrc  = Join-Path $repoRoot "target\release\hispanshield-agent.exe"
$uiSrc     = Join-Path $repoRoot "ui\src-tauri\target\release\hispanshield-ui.exe"

if (-not (Test-Path $agentSrc)) {
    Write-Error "Agent binary not found at $agentSrc. Run 'cargo build --release -p hispanshield-agent' first."
}
if (-not (Test-Path $uiSrc)) {
    Write-Warn "UI binary not found. Dashboard shortcut will not be created."
    $uiSrc = $null
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing -and -not $Force) {
    Write-Error "HispanShield is already installed. Use -Force to reinstall or -Uninstall to remove."
}

# ── Create directories ────────────────────────────────────────────────────────
Write-Step "Creating directory structure..."
$dirs = @(
    "$InstallDir\bin",
    "$InstallDir\rules",
    "$InstallDir\feeds",
    "$DataDir\logs",
    "$DataDir\quarantine"
)
foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
Write-OK "Directories created"

# ── Copy files ────────────────────────────────────────────────────────────────
Write-Step "Copying agent binary..."
Copy-Item $agentSrc $AgentExe -Force
Write-OK "Agent installed: $AgentExe"

if ($uiSrc) {
    Write-Step "Copying UI binary..."
    Copy-Item $uiSrc $UIExe -Force
    Write-OK "UI installed: $UIExe"
}

Write-Step "Copying YARA rules and feeds config..."
Copy-Item (Join-Path $repoRoot "rules\hispan\*") "$InstallDir\rules\" -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $repoRoot "feeds\feed_config.json") "$InstallDir\feeds\" -Force -ErrorAction SilentlyContinue
Write-OK "Rules and feeds copied"

# ── Generate IPC token ────────────────────────────────────────────────────────
Write-Step "Generating IPC authentication token..."
$tokenBytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
$token      = [System.Convert]::ToBase64String($tokenBytes)
Set-Content -Path "$DataDir\ipc_token" -Value $token -Encoding ASCII -NoNewline
Write-OK "IPC token generated"

# ── Set permissions on data directory ────────────────────────────────────────
Write-Step "Hardening data directory permissions..."
$acl = Get-Acl $DataDir
$acl.SetAccessRuleProtection($true, $false)

$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$adminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")

$acl.AddAccessRule($systemRule)
$acl.AddAccessRule($adminRule)
Set-Acl $DataDir $acl
Write-OK "Permissions set (SYSTEM + Administrators only)"

# ── Remove existing service if reinstalling ───────────────────────────────────
if ($existing) {
    Write-Step "Removing existing service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep 2
}

# ── Install Windows Service ───────────────────────────────────────────────────
Write-Step "Registering Windows Service..."
New-Service `
    -Name        $ServiceName `
    -DisplayName "HispanShield Security Agent" `
    -Description "Real-time threat protection and network monitoring for HispanShield Antivirus" `
    -BinaryPathName "`"$AgentExe`" run" `
    -StartupType Automatic | Out-Null

Write-Step "Starting service..."
Start-Service -Name $ServiceName
Start-Sleep 3

$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq "Running") {
    Write-OK "Service running (PID: $(Get-Process | Where-Object {$_.Name -eq 'hispanshield-agent'} | Select-Object -ExpandProperty Id -ErrorAction SilentlyContinue))"
} else {
    Write-Warn "Service status: $($svc.Status). Check Event Viewer > Application for details."
}

# ── Create shortcuts ──────────────────────────────────────────────────────────
if ($uiSrc) {
    Write-Step "Creating shortcuts..."
    $shell = New-Object -ComObject WScript.Shell

    $desktopLink = "$env:PUBLIC\Desktop\HispanShield Antivirus.lnk"
    $sc = $shell.CreateShortcut($desktopLink)
    $sc.TargetPath       = $UIExe
    $sc.WorkingDirectory = $InstallDir
    $sc.Description      = "HispanShield Antivirus"
    $sc.Save()

    $startMenuDir = "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\HispanShield"
    New-Item -ItemType Directory -Force -Path $startMenuDir | Out-Null
    $scSM = $shell.CreateShortcut("$startMenuDir\HispanShield Antivirus.lnk")
    $scSM.TargetPath       = $UIExe
    $scSM.WorkingDirectory = $InstallDir
    $scSM.Save()

    Write-OK "Shortcuts created"
}

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║   Installation Complete!                 ║" -ForegroundColor Green
Write-Host "  ║                                          ║" -ForegroundColor Green
Write-Host "  ║   Service:  HispanShieldAgent (Running)  ║" -ForegroundColor Green
Write-Host "  ║   Data dir: $DataDir" -ForegroundColor Green
Write-Host "  ║   Shortcut: Desktop                      ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
