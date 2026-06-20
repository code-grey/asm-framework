#!/bin/bash

# ASM Framework Setup Script
# This script installs all required dependencies for the ASM Framework.

set -e

echo "[*] Starting ASM Framework Dependency Installation..."

# 1. Update and install basic system requirements
echo "[*] Installing system dependencies (nmap, amass, exploitdb, jq)..."
sudo apt-get update
sudo apt-get install -y nmap amass exploitdb jq libpcap-dev

# 2. Check if Go is installed
if ! command -v go &> /dev/null
then
    echo "[!] Go is not installed. Please install Go (1.20+) first."
    exit 1
fi

echo "[*] Go is installed. Proceeding with Go tools..."

# Setup Go environment variables if not already set
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# 3. Install Go-based tools
echo "[*] Installing Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "[*] Installing Httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "[*] Installing Gau..."
go install github.com/lc/gau/v2/cmd/gau@latest

echo "[*] Installing Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest


echo "[*] Installing Dalfox (for future fuzzing mode)..."
go install github.com/hahwul/dalfox/v2@latest


# 5. Symlink Go binaries to /usr/local/bin for global access (requires sudo)
echo "[*] Symlinking Go binaries to /usr/local/bin..."
sudo cp $GOPATH/bin/subfinder /usr/local/bin/ || true
sudo cp $GOPATH/bin/httpx /usr/local/bin/ || true
sudo cp $GOPATH/bin/gau /usr/local/bin/ || true
sudo cp $GOPATH/bin/nuclei /usr/local/bin/ || true
sudo cp $GOPATH/bin/puredns /usr/local/bin/ || true
sudo cp $GOPATH/bin/dalfox /usr/local/bin/ || true

echo "[*] Updating Nuclei templates..."
nuclei -update-templates

echo "[*] Updating SearchSploit (ExploitDB)..."
searchsploit -u

echo "[+] Installation complete! You can now run the ASM framework."
