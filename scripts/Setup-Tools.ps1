<#
.SYNOPSIS
    Installs and verifies external tooling required for Unconfuser (specifically de4dot-cex).
.DESCRIPTION
    Ensures tools\de4dot\de4dot.exe is present. If missing, attempts to copy from local
    build directories or downloads the verified de4dot-cex release archive.
#>

[CmdletBinding()]
param(
    [string]$ToolsDir = "$PSScriptRoot\..\tools",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$targetDe4dotDir = [System.IO.Path]::GetFullPath((Join-Path $ToolsDir "de4dot"))
$targetDe4dotExe = Join-Path $targetDe4dotDir "de4dot.exe"

Write-Host "=== Unconfuser Tooling Setup ===" -ForegroundColor Cyan
Write-Host "Target de4dot path: $targetDe4dotExe"

if ((Test-Path $targetDe4dotExe) -and -not $Force) {
    Write-Host "[+] de4dot-cex already installed at: $targetDe4dotExe" -ForegroundColor Green
    & $targetDe4dotExe --version
    exit 0
}

# 1. Check local build artifacts
$localCandidates = @(
    "$PSScriptRoot\..\ConfuserExKillerRunner\bin\Release\net48\tools\de4dot",
    "$PSScriptRoot\..\ConfuserExKillerRunner\bin\Debug\net48\tools\de4dot"
)

$foundLocal = $false
foreach ($cand in $localCandidates) {
    $candExe = Join-Path $cand "de4dot.exe"
    if (Test-Path $candExe) {
        Write-Host "[*] Found local de4dot copy at: $cand" -ForegroundColor Yellow
        if (-not (Test-Path $targetDe4dotDir)) {
            New-Item -ItemType Directory -Path $targetDe4dotDir -Force | Out-Null
        }
        Copy-Item -Path "$cand\*" -Destination $targetDe4dotDir -Recurse -Force
        $foundLocal = $true
        break
    }
}

if ($foundLocal -and (Test-Path $targetDe4dotExe)) {
    Write-Host "[+] Successfully deployed de4dot from local build cache." -ForegroundColor Green
    exit 0
}

# 2. Download from GitHub Release if not found locally
Write-Host "[*] Local copy not found. Downloading de4dot-cex..." -ForegroundColor Yellow
$downloadUrl = "https://github.com/0xd4d/de4dot/releases/download/v3.1.41592.3405/de4dot-net45.zip"
$tempZip = Join-Path ([System.IO.Path]::GetTempPath()) "de4dot-temp.zip"

try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZip -UseBasicParsing
    
    if (-not (Test-Path $targetDe4dotDir)) {
        New-Item -ItemType Directory -Path $targetDe4dotDir -Force | Out-Null
    }
    
    Expand-Archive -Path $tempZip -DestinationPath $targetDe4dotDir -Force
    Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
    
    if (Test-Path $targetDe4dotExe) {
        Write-Host "[+] de4dot successfully downloaded and extracted." -ForegroundColor Green
        exit 0
    } else {
        Write-Error "[-] Download completed but de4dot.exe was not found in extracted files."
        exit 1
    }
}
catch {
    Write-Error "[-] Failed to download de4dot: $_"
    exit 1
}
