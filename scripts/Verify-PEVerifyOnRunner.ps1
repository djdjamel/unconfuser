<#
.SYNOPSIS
    Discovers PEVerify.exe on Windows runner, displays path and version, executes /IL and /MD verification, and archives logs.
.PARAMETER Target
    Path to the .NET Framework assembly to verify (defaults to net48 BenignSample).
.PARAMETER LogPath
    Path where verification log will be saved.
#>
param(
    [string]$Target = "benchmarks\BenignSample\bin\Release\net48\BenignSample.exe",
    [string]$LogPath = "benchmarks\peverify_runner_verification.log"
)

$ErrorActionPreference = "Stop"

$logDir = [System.IO.Path]::GetDirectoryName($LogPath)
if ($logDir -and !(Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$logContent = [System.Collections.Generic.List[string]]::new()
function LogMsg([string]$msg) {
    Write-Host $msg
    $logContent.Add($msg)
}

LogMsg "=== Unconfuser Official PEVerify Runner Verification ==="
LogMsg "Date: $([System.DateTime]::UtcNow.ToString('o'))"
LogMsg "Operating System: $((Get-CimInstance Win32_OperatingSystem).Caption) ($((Get-CimInstance Win32_OperatingSystem).Version))"
LogMsg "Target assembly: $Target"

if (!(Test-Path $Target)) {
    LogMsg "ERROR: Target assembly '$Target' not found."
    $logContent | Out-File -FilePath $LogPath -Encoding utf8
    exit 1
}

# 1. Search for PEVerify.exe
$searchPaths = @(
    "C:\Program Files (x86)\Microsoft SDKs\Windows",
    "C:\Program Files\Microsoft SDKs\Windows"
)

$peverify = $null
foreach ($basePath in $searchPaths) {
    if (Test-Path $basePath) {
        $found = Get-ChildItem -Path $basePath -Filter "PEVerify.exe" -Recurse -ErrorAction SilentlyContinue |
            Sort-Object { $_.FullName -like "*x64*" } -Descending |
            Select-Object -First 1
        if ($found) {
            $peverify = $found.FullName
            break
        }
    }
}

if (!$peverify) {
    $fromPath = Get-Command "PEVerify.exe" -ErrorAction SilentlyContinue
    if ($fromPath) {
        $peverify = $fromPath.Source
    }
}

if (!$peverify -or !(Test-Path $peverify)) {
    LogMsg "STATUS: VERIFICATION_NOT_EXECUTED"
    LogMsg "ERROR: PEVerify.exe was not found on this runner."
    LogMsg "Search paths inspected: $($searchPaths -join ', ')"
    $logContent | Out-File -FilePath $LogPath -Encoding utf8
    exit 1
}

# 2. Display Path, Version, and verify existence
LogMsg "PEVerify Path: $peverify"
$versionInfo = (Get-Item $peverify).VersionInfo
LogMsg "PEVerify FileVersion: $($versionInfo.FileVersion)"
LogMsg "PEVerify ProductVersion: $($versionInfo.ProductVersion)"
LogMsg "PEVerify Exists: $(Test-Path $peverify)"

# 3. Execute /IL and /MD on target
LogMsg "`n--- Executing PEVerify /IL /MD ---"
$procInfo = New-Object System.Diagnostics.ProcessStartInfo
$procInfo.FileName = $peverify
$procInfo.Arguments = "/IL /MD `"$Target`""
$procInfo.RedirectStandardOutput = $true
$procInfo.RedirectStandardError = $true
$procInfo.UseShellExecute = $false
$procInfo.CreateNoWindow = $true

$proc = [System.Diagnostics.Process]::Start($procInfo)
$stdout = $proc.StandardOutput.ReadToEnd()
$stderr = $proc.StandardError.ReadToEnd()
$proc.WaitForExit()
$exitCode = $proc.ExitCode

LogMsg $stdout
if ($stderr) {
    LogMsg "STDERR: $stderr"
}
LogMsg "PEVerify Exit Code: $exitCode"

if ($exitCode -eq 0) {
    LogMsg "STATUS: PEVERIFY_EXECUTED_PASSED"
    LogMsg "Verification completed successfully: zero IL and MD errors detected."
} else {
    LogMsg "STATUS: PEVERIFY_EXECUTED_FAILED"
    LogMsg "ERROR: PEVerify reported violations (exit code $exitCode)."
}

$logContent | Out-File -FilePath $LogPath -Encoding utf8

if ($exitCode -ne 0) {
    exit $exitCode
}
