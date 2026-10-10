# EdgeSentinel - Health and Database Verification Script for Windows
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

$PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = Join-Path (Split-Path -Parent $ProjectRoot) ".venv\Scripts\python.exe"
}
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

Push-Location $ProjectRoot
try {
    Write-Host "=== System & Engine Health Check ===" -ForegroundColor Cyan
    & $PythonExe src/edgesentinel/cli.py status

    Write-Host ""
    Write-Host "=== Database Integrity & Storage Metrics ===" -ForegroundColor Cyan
    & $PythonExe src/edgesentinel/cli.py db-check
}
finally {
    Pop-Location
}
