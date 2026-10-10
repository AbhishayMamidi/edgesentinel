# EdgeSentinel - Comprehensive Test Suite Runner for Windows
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " EdgeSentinel - Running Test Suite & QA Checks" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = Join-Path (Split-Path -Parent $ProjectRoot) ".venv\Scripts\python.exe"
}
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

Push-Location $ProjectRoot
try {
    Write-Host "[1/2] Running Pytest across all unit and integration tests..." -ForegroundColor Green
    & $PythonExe -m pytest -v

    Write-Host ""
    Write-Host "[2/2] Running CLI configuration check..." -ForegroundColor Green
    & $PythonExe src/edgesentinel/cli.py config-check

    Write-Host ""
    Write-Host "[+] All quality assurance and validation checks passed!" -ForegroundColor Green
}
finally {
    Pop-Location
}
