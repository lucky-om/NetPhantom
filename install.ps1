# NetPhantom v3.1.3 Automated PowerShell Installer
# Run: iwr -useb https://netphantom.luckyverse.tech/install.ps1 | iex

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$setupUrl = "https://github.com/lucky-om/NetPhantom/raw/main/website/NetPhantom_Setup.exe"
$tempDir = [System.IO.Path]::GetTempPath()
$setupExe = Join-Path $tempDir "NetPhantom_Setup.exe"

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   NetPhantom v3.1.3 — Automated Windows Setup Installer  " -ForegroundColor Cyan
Write-Host "   Publisher: Luckyverse Security                        " -ForegroundColor DarkCyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/3] Downloading NetPhantom_Setup.exe..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $setupUrl -OutFile $setupExe -UseBasicParsing

Write-Host "[2/3] Verifying and unblocking binary security tags..." -ForegroundColor Yellow
if (Test-Path $setupExe) {
    Unblock-File -Path $setupExe -ErrorAction SilentlyContinue
    $motw = "$setupExe:Zone.Identifier"
    if (Test-Path $motw) {
        Remove-Item $motw -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "[3/3] Launching NetPhantom Setup Wizard with Administrator privileges..." -ForegroundColor Green
Write-Host ""

Start-Process -FilePath $setupExe -Verb RunAs
