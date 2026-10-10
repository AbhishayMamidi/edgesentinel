# EdgeSentinel - Local Windows Development Launcher
param (
    [int]$Port = 8080,
    [string]$HostAddr = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " EdgeSentinel - Windows Local Development Runner" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Locate Python environment
$PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = Join-Path (Split-Path -Parent $ProjectRoot) ".venv\Scripts\python.exe"
}
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

Write-Host "[+] Using Python: $PythonExe" -ForegroundColor Green
Write-Host "[+] Launching Dashboard on http://${HostAddr}:${Port}" -ForegroundColor Green
Write-Host "[*] Press Ctrl+C to terminate." -ForegroundColor Yellow

& $PythonExe "$ProjectRoot\src\edgesentinel\cli.py" dashboard --port $Port --host $HostAddr
