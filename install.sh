#!/bin/sh
# ==============================================================================
# KSP CLI — Global One-Liner Installer for Linux & macOS
# ==============================================================================
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Kush2272/ksp/main/install.sh | sh
# ==============================================================================

set -e

printf "\n"
printf "\033[36m  ██╗  ██╗███████╗██████╗ \033[0m\n"
printf "\033[36m  ██║ ██╔╝██╔════╝██╔══██╗\033[0m\n"
printf "\033[36m  █████╔╝ ███████╗██████╔╝\033[0m\n"
printf "\033[36m  ██╔═██╗ ╚════██║██╔═══╝ \033[0m\n"
printf "\033[36m  ██║  ██╗███████║██║     \033[0m\n"
printf "\033[36m  ╚═╝  ╚═╝╚══════╝╚═╝     \033[0m\n"
printf "\n\033[1m  Kush Secure Protocol — CLI v0.1.0 Installer\033[0m\n"
printf "\033[2m  Experimental Secure Application Protocol\033[0m\n\n"

INSTALL_DIR="$HOME/.ksp/bin"
mkdir -p "$INSTALL_DIR"

if command -v cargo >/dev/null 2>&1; then
    printf "\033[32m  [+] Cargo (Rust) detected on system.\033[0m\n"
    printf "\033[33m  [+] Compiling and installing latest KSP CLI globally via Cargo...\033[0m\n"
    if [ -f "crates/ksp-cli/Cargo.toml" ]; then
        cargo install --path crates/ksp-cli --force --locked
    else
        cargo install --git https://github.com/Kush2272/ksp.git ksp-cli --force --locked
    fi
else
    printf "\033[33m  [!] Cargo not detected. Checking for pre-compiled release binary...\033[0m\n"
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    if [ "$OS" = "darwin" ]; then
        TAR_NAME="ksp-darwin-${ARCH}.tar.gz"
    else
        TAR_NAME="ksp-linux-${ARCH}.tar.gz"
    fi

    BIN_URL="https://github.com/Kush2272/ksp/releases/latest/download/${TAR_NAME}"
    TMP_DIR=$(mktemp -d)
    
    if curl -fsSL "$BIN_URL" -o "$TMP_DIR/ksp.tar.gz" 2>/dev/null; then
        tar -xzf "$TMP_DIR/ksp.tar.gz" -C "$INSTALL_DIR"
        chmod +x "$INSTALL_DIR/ksp"
        rm -rf "$TMP_DIR"
    else
        printf "\n\033[31m  [✘] Could not download pre-built release binary (${TAR_NAME}).\033[0m\n"
        printf "\033[33m      Please install Rust via https://rustup.rs and run:\033[0m\n"
        printf "        cargo install --git https://github.com/Kush2272/ksp.git ksp-cli\n\n"
        rm -rf "$TMP_DIR"
        exit 1
    fi

    # Add to PATH recommendation
    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *)
            printf "\033[33m  [+] Add %s to your PATH by running:\033[0m\n" "$INSTALL_DIR"
            printf "        export PATH=\"\$PATH:%s\"\n" "$INSTALL_DIR"
            ;;
    esac
fi

printf "\n\033[32m  ✔ KSP CLI successfully installed and ready!\033[0m\n"
printf "\033[36m  💡 Open a terminal and type 'ksp' or 'ksp --help' to get started.\033[0m\n\n"
