# ============================================================
# Claude Code / Claude Desktop -- Day-Zero Bootstrap
# Run on any fresh Windows machine (as Administrator).
# Restores all memory, extensions, hooks, and config.
#
# Repo:  https://github.com/Fuzzywumpets/claude-memory
#
# BEFORE RUNNING you need ONE thing: your Doppler service token.
#   https://dashboard.doppler.com
#   Workplace: Fuzzywumpets | Project: fww-shared | Config: prd
#   Project Settings > Service Tokens > Create
# ============================================================

$ErrorActionPreference = "Stop"

function Check-Command([string]$cmd) {
    return [bool](Get-Command $cmd -ErrorAction SilentlyContinue)
}

Write-Host ""
Write-Host "STEP 1 of 3 -- Prerequisites (git, node, doppler)" -ForegroundColor Cyan
$tools = @{ "git" = "Git.Git"; "node" = "OpenJS.NodeJS.LTS"; "doppler" = "Doppler.doppler" }
$needRestart = $false
foreach ($cmd in $tools.Keys) {
    if (Check-Command $cmd) {
        Write-Host "  [OK] $cmd" -ForegroundColor Green
    } else {
        Write-Host "  [..] Installing $cmd via winget..." -ForegroundColor Yellow
        winget install $tools[$cmd] --silent --accept-source-agreements --accept-package-agreements
        $needRestart = $true
    }
}
if ($needRestart) {
    Write-Host ""
    Write-Host "  Tools installed. Close + reopen PowerShell as Administrator, then re-run this script." -ForegroundColor Magenta
    exit 0
}

Write-Host ""
Write-Host "STEP 2 of 3 -- Doppler auth" -ForegroundColor Cyan
$dopplerOk = $false
try { $null = doppler secrets --only-names 2>&1; if ($LASTEXITCODE -eq 0) { $dopplerOk = $true } } catch {}

if ($dopplerOk) {
    Write-Host "  [OK] Doppler already authenticated" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "  Get your token from https://dashboard.doppler.com" -ForegroundColor Yellow
    Write-Host "  Workplace: Fuzzywumpets | Project: fww-shared | Config: prd" -ForegroundColor DarkGray
    Write-Host "  Project Settings > Service Tokens > Create" -ForegroundColor DarkGray
    Write-Host ""
    $secureToken = Read-Host "  Paste Doppler service token (input hidden)" -AsSecureString
    $plainToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken))
    doppler configure set token $plainToken --scope global 2>&1 | Out-Null
    doppler configure set project fww-shared --scope global 2>&1 | Out-Null
    doppler configure set config prd --scope global 2>&1 | Out-Null
    New-Item -ItemType Directory -Force "$env:USERPROFILE\.secrets" | Out-Null
    "DOPPLER_TOKEN=$plainToken" | Set-Content "$env:USERPROFILE\.secrets\doppler.env" -Encoding utf8
    try {
        $null = doppler secrets --only-names 2>&1
        if ($LASTEXITCODE -ne 0) { throw "auth failed" }
        Write-Host "  [OK] Doppler authenticated" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Doppler auth failed -- check your token" -ForegroundColor Red; exit 1
    }
}

Write-Host ""
Write-Host "STEP 3 of 3 -- Fetching and running full restore..." -ForegroundColor Cyan
Write-Host ""
$gh  = doppler secrets get MEMORY_GH_TOKEN --plain
$url = "https://raw.githubusercontent.com/Fuzzywumpets/claude-memory/main/bootstrap/restore-windows.ps1"
$src = (Invoke-WebRequest -Uri $url -Headers @{ Authorization = "token $gh" }).Content
Invoke-Expression $src
