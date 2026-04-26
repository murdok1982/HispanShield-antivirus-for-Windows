#Requires -RunAsAdministrator
<#
.SYNOPSIS
    HispanShield Antivirus — Complete Build Script
.DESCRIPTION
    Builds the agent, dashboard and optionally the MSI installer.
.PARAMETER BuildType
    "release" (default) or "debug"
.PARAMETER SkipAgent
    Skip building the Rust agent
.PARAMETER SkipUI
    Skip building the Tauri UI
.PARAMETER SkipInstaller
    Skip building the MSI installer
#>
param(
    [string]$BuildType    = "release",
    [switch]$SkipAgent,
    [switch]$SkipUI,
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path (Split-Path $MyInvocation.MyCommand.Path)
Set-Location $repoRoot

function Write-Step { Write-Host "`n[BUILD] $args" -ForegroundColor Cyan }
function Write-OK   { Write-Host "[OK]    $args" -ForegroundColor Green }
function Write-Fail { Write-Host "[FAIL]  $args" -ForegroundColor Red; exit 1 }

$startTime = Get-Date
Write-Host ""
Write-Host "  HispanShield Antivirus — Build ($BuildType)" -ForegroundColor Cyan
Write-Host "  Repository: $repoRoot" -ForegroundColor Gray
Write-Host ""

# ── Agent ─────────────────────────────────────────────────────────────────────
if (-not $SkipAgent) {
    Write-Step "Building Rust agent..."
    $cargoArgs = @("build", "-p", "hispanshield-agent")
    if ($BuildType -eq "release") { $cargoArgs += "--release" }

    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) { Write-Fail "cargo build failed" }

    $agentPath = Join-Path $repoRoot "target\$BuildType\hispanshield-agent.exe"
    $agentSize = [math]::Round((Get-Item $agentPath).Length / 1MB, 2)
    Write-OK "Agent: $agentPath ($agentSize MB)"
}

# ── Tests ─────────────────────────────────────────────────────────────────────
Write-Step "Running agent tests..."
& cargo test -p hispanshield-agent
if ($LASTEXITCODE -ne 0) { Write-Fail "Tests failed" }
Write-OK "All tests passed"

# ── UI ────────────────────────────────────────────────────────────────────────
if (-not $SkipUI) {
    Write-Step "Installing Node.js dependencies..."
    Set-Location "$repoRoot\ui"
    & npm ci
    if ($LASTEXITCODE -ne 0) { Write-Fail "npm ci failed" }

    Write-Step "TypeScript check..."
    & npx tsc --noEmit
    if ($LASTEXITCODE -ne 0) { Write-Fail "TypeScript check failed" }

    Write-Step "Building Tauri UI..."
    if ($BuildType -eq "release") {
        & npm run tauri build
    } else {
        Write-Host "  (dev mode — not building bundle, use 'npm run tauri dev' for live reload)"
    }
    if ($LASTEXITCODE -ne 0) { Write-Fail "Tauri build failed" }

    Set-Location $repoRoot
    Write-OK "UI build complete"
}

# ── MSI Installer ────────────────────────────────────────────────────────────
if (-not $SkipInstaller -and $BuildType -eq "release") {
    Write-Step "Building MSI installer (requires WiX Toolset v4)..."
    $wixAvailable = Get-Command "wix" -ErrorAction SilentlyContinue
    if (-not $wixAvailable) {
        Write-Host "  WiX Toolset not found. Skipping MSI build." -ForegroundColor Yellow
        Write-Host "  Install via: dotnet tool install --global wix" -ForegroundColor Gray
    } else {
        New-Item -ItemType Directory -Force -Path "$repoRoot\installer\build" | Out-Null
        & wix build "$repoRoot\installer\wix\hispanshield.wxs" `
            -out "$repoRoot\installer\build\HispanShield-0.1.0.msi"
        if ($LASTEXITCODE -ne 0) { Write-Fail "WiX build failed" }
        Write-OK "MSI: installer\build\HispanShield-0.1.0.msi"
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
$elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
Write-Host ""
Write-Host "  Build completed in ${elapsed}s" -ForegroundColor Green
Write-Host ""
if (-not $SkipAgent) {
    Write-Host "  Agent:   target\$BuildType\hispanshield-agent.exe" -ForegroundColor Gray
}
if (-not $SkipUI -and $BuildType -eq "release") {
    Write-Host "  UI:      ui\src-tauri\target\release\hispanshield-ui.exe" -ForegroundColor Gray
    Write-Host "  Bundle:  ui\src-tauri\target\release\bundle\" -ForegroundColor Gray
}
Write-Host ""
