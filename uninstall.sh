#!/bin/sh
# ==============================================================================
# KSP CLI -- Global One-Liner Uninstaller for Linux & macOS
# ==============================================================================
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Kush2272/ksp/main/uninstall.sh | sh
# ==============================================================================

set -e

printf "\n\033[36m  ========================================================\033[0m\n"
printf "\033[36m  ==               KSP CLI UNINSTALLER                  ==\033[0m\n"
printf "\033[36m  ========================================================\033[0m\n"
printf "\033[1m  Removing Kush Secure Protocol CLI from your system...\033[0m\n\n"

if command -v cargo >/dev/null 2>&1; then
    printf "\033[33m  [+] Checking for Cargo installation of ksp-cli...\033[0m\n"
    cargo uninstall ksp-cli 2>/dev/null || true
fi

BINS="$HOME/.cargo/bin/ksp $HOME/.ksp/bin/ksp /usr/local/bin/ksp /usr/bin/ksp"
for BIN in $BINS; do
    if [ -f "$BIN" ]; then
        printf "\033[33m  [+] Deleting binary at %s...\033[0m\n" "$BIN"
        rm -f "$BIN" 2>/dev/null || sudo rm -f "$BIN" 2>/dev/null || true
    fi
done

CONFIG_DIR="$HOME/.ksp"
if [ -d "$CONFIG_DIR" ]; then
    printf "\033[33m  [+] Removing KSP configuration directory (%s)...\033[0m\n" "$CONFIG_DIR"
    rm -rf "$CONFIG_DIR"
fi

printf "\n\033[32m  [OK] KSP CLI has been completely uninstalled from your system!\033[0m\n\n"
