# ==============================================================================
# KSP CLI -- Global One-Liner Installer for Windows PowerShell
# ==============================================================================
# Usage:
#   irm https://raw.githubusercontent.com/Kush2272/ksp/main/install.ps1 | iex
# ==============================================================================

$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host "  ==                KSP CLI INSTALLER                   ==" -ForegroundColor Cyan
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host "  Kush Secure Protocol -- CLI v0.1.0 Installer" -ForegroundColor White
Write-Host "  Experimental Secure Application Protocol" -ForegroundColor DarkGray
Write-Host ""

$InstallDir = "$env:USERPROFILE\.ksp\bin"
if (-not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Check if cargo is installed on system
$CargoExists = Get-Command cargo -ErrorAction SilentlyContinue

if ($CargoExists) {
    Write-Host "  [+] Cargo (Rust) detected on system." -ForegroundColor Green
    Write-Host "  [+] Compiling and installing latest KSP CLI globally via Cargo..." -ForegroundColor Yellow
    
    if (Test-Path "crates\ksp-cli\Cargo.toml") {
        cargo install --path crates/ksp-cli --force --locked
    } else {
        cargo install --git https://github.com/Kush2272/ksp.git ksp-cli --force --locked
    }
} else {
    Write-Host "  [!] Cargo not detected. Checking for pre-compiled Windows executable release..." -ForegroundColor Yellow
    $BinUrl = "https://github.com/Kush2272/ksp/releases/latest/download/ksp.exe"
    $DestPath = "$InstallDir\ksp.exe"

    try {
        Write-Host "  [+] Downloading $BinUrl to $DestPath..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $BinUrl -OutFile $DestPath -UseBasicParsing
    } catch {
        Write-Host ""
        Write-Host "  [X] Could not download pre-built release binary yet." -ForegroundColor Red
        Write-Host "      Please install Rust via https://rustup.rs and run:" -ForegroundColor Yellow
        Write-Host "        cargo install --git https://github.com/Kush2272/ksp.git ksp-cli" -ForegroundColor White
        Write-Host ""
        exit 1
    }

    # Add to User PATH if not present
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        Write-Host "  [+] Adding $InstallDir to User PATH environment variable..." -ForegroundColor Yellow
        [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
        $env:PATH = "$env:PATH;$InstallDir"
    }
}

Write-Host ""
Write-Host "  [OK] KSP CLI successfully installed and ready!" -ForegroundColor Green
Write-Host "  [i] Open a new terminal and type ksp or ksp --help to get started." -ForegroundColor Cyan
Write-Host ""
