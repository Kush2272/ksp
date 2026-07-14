# ==============================================================================
# KSP CLI -- Global One-Liner Uninstaller for Windows PowerShell
# ==============================================================================
# Usage:
#   irm https://raw.githubusercontent.com/Kush2272/ksp/main/uninstall.ps1 | iex
# ==============================================================================

$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host "  ==               KSP CLI UNINSTALLER                  ==" -ForegroundColor Cyan
Write-Host "  ========================================================" -ForegroundColor Cyan
Write-Host "  Removing Kush Secure Protocol CLI from your system..." -ForegroundColor White
Write-Host ""

# 1. Try cargo uninstall if cargo is available
$CargoExists = Get-Command cargo -ErrorAction SilentlyContinue
if ($CargoExists) {
    Write-Host "  [+] Checking for Cargo installation of ksp-cli..." -ForegroundColor Yellow
    cargo uninstall ksp-cli 2>$null | Out-Null
}

# 2. Remove binary from standard paths
$BinPaths = @(
    "$env:USERPROFILE\.cargo\bin\ksp.exe",
    "$env:USERPROFILE\.ksp\bin\ksp.exe"
)

foreach ($Path in $BinPaths) {
    if (Test-Path $Path) {
        try {
            Write-Host "  [+] Deleting binary at $Path..." -ForegroundColor Yellow
            Remove-Item -Force $Path -ErrorAction Stop
        } catch {
            Write-Host "  [!] Could not delete $Path (File might be in use or open in terminal)." -ForegroundColor Red
            Write-Host "      Please close any open terminals running ksp and delete manually." -ForegroundColor DarkGray
        }
    }
}

# 3. Remove user configuration and cache (~/.ksp)
$ConfigDir = "$env:USERPROFILE\.ksp"
if (Test-Path $ConfigDir) {
    Write-Host "  [+] Removing KSP configuration directory ($ConfigDir)..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $ConfigDir -ErrorAction SilentlyContinue
}

# 4. Clean User PATH environment variable
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$InstallDir = "$env:USERPROFILE\.ksp\bin"
if ($UserPath -like "*$InstallDir*") {
    Write-Host "  [+] Cleaning $InstallDir from User PATH environment variable..." -ForegroundColor Yellow
    $CleanPath = ($UserPath.Split(';') | Where-Object { $_ -ne $InstallDir -and $_ -ne "" }) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $CleanPath, "User")
}

Write-Host ""
Write-Host "  [OK] KSP CLI has been completely uninstalled from your system!" -ForegroundColor Green
Write-Host ""
