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

$Failed = $false
foreach ($Path in $BinPaths) {
    if (Test-Path $Path) {
        try {
            Write-Host "  [+] Deleting binary at $Path..." -ForegroundColor Yellow
            Remove-Item -Force $Path -ErrorAction Stop
        } catch {
            Write-Host "  [!] Could not delete $Path because it is locked by Windows (os error 5 - Access Denied)." -ForegroundColor Red
            Write-Host "      This happens when ksp.exe is actively running or open in a terminal window." -ForegroundColor Yellow
            
            $Response = Read-Host "  [?] Schedule background task to automatically delete ksp.exe 2 seconds after you close your terminal? (Y/n)"
            if ($Response -eq '' -or $Response -like 'Y*' -or $Response -like 'y*') {
                Start-Process cmd -ArgumentList "/C timeout /t 2 /nobreak >nul & del /f /q `"$Path`" 2>nul & cargo uninstall ksp-cli 2>nul" -WindowStyle Hidden
                Write-Host "      [✔] Scheduled background self-cleanup for $Path!" -ForegroundColor Green
            } else {
                Write-Host "      Please close any open terminals running ksp and delete manually." -ForegroundColor DarkGray
                $Failed = $true
            }
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
if ($Failed) {
    Write-Host "  [!] KSP CLI configuration uninstalled, but ksp.exe could not be deleted because it is currently running or locked." -ForegroundColor Yellow
    Write-Host "      Please close the terminal running ksp and run: cargo uninstall ksp-cli" -ForegroundColor White
} else {
    Write-Host "  [OK] KSP CLI has been completely uninstalled from your system!" -ForegroundColor Green
}
Write-Host ""
Write-Host "  To reinstall KSP CLI anytime in the future, run:" -ForegroundColor Cyan
Write-Host "    irm https://raw.githubusercontent.com/Kush2272/ksp/main/install.ps1 | iex" -ForegroundColor White
Write-Host "    # Or via Cargo: cargo install --git https://github.com/Kush2272/ksp.git ksp-cli --force" -ForegroundColor DarkGray
Write-Host ""
