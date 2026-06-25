# Attack Surface Management (ASM) Framework

A modular, orchestration-driven framework written in Go for automated attack surface discovery, network mapping, and vulnerability intelligence. This project integrates multiple industry-standard security tools into a unified, high-performance pipeline.

## Project Architecture

The framework is built using a highly modular Go architecture (`cmd/` and `pkg/` structure) and operates sequentially through a funnel-based pipeline:

1.  **Subdomain Enumeration**: Discovers potential targets using `subfinder` and `amass`.
2.  **DNS Resolution**: Filters out dead or parked domains using `puredns` to preserve downstream scan time.
3.  **Port Scanning**: Identifies open ports and services on live targets using `nmap`.
4.  **Web Context Probing**: Connects to open web ports using `httpx` to extract page titles, HTTP status codes, and technology fingerprinting (Frameworks, CMS, Web Servers).
5.  **Endpoint Discovery**: Scrapes historical and hidden URLs from live websites using `gau`.
6.  **Vulnerability Intelligence**: 
    - Executes high-speed vulnerability templates against live targets using `nuclei`.
    - Maps discovered service versions to known CVEs using `searchsploit` (ExploitDB).

### Code Modularity
- **`cmd/asm/`**: The main entry point for the application.
- **`pkg/orchestrator/`**: Manages the execution pipeline, concurrent worker pools, and context propagation.
- **`pkg/runner/`**: Contains modular Go wrappers for all external tools (Nmap, Amass, Httpx, etc.), ensuring uniform execution.
- **`pkg/storage/`**: Handles local persistence using SQLite, automatically managing schema migrations and data deduplication.
- **`pkg/logger/`**: A centralized, structured logging package built on Go's native `log/slog` for clean error handling and debugging.
- **`pkg/tui/`**: An interactive terminal user interface for exploring the database.

All gathered intelligence is deduplicated in memory and permanently persisted to a local SQLite database (`asm.db`).

## Assumptions

*   The tool is executed in a Unix-like environment (Linux/macOS) with root or sudo privileges available for certain `nmap` packet operations if required.
*   The host machine has an active, unfiltered outbound internet connection.
*   The required external binaries (listed below) are installed and available in the system `$PATH`.
*   You have explicit permission to scan the target domains.

## Prerequisites & Installation

The framework relies on several external security tools. We provide a `setup.sh` script to automate the installation of all dependencies on Kali Linux / Ubuntu systems.

1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd asm-framework
   ```

2. Run the automated setup script to install all dependencies (`nmap`, `amass`, `subfinder`, `httpx`, `gau`, `nuclei`, `exploitdb`, `puredns`):
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. Compile the Go binary:
   ```bash
   go mod tidy
   go build -ldflags="-s -w" -trimpath -o asm ./cmd/asm/main.go
   ```

## Usage

### Basic Scan (Fast)
Executes passive subdomain enumeration, DNS filtration, and probes the top 100 most common ports.

```bash
./asm -d example.com
```

### Deep Scan (Thorough)
Activates deep enumeration mode. Amass performs active TLS/DNS scraping, Subfinder uses premium sources, and Nmap runs a full 65k port sweep with Service Versioning (`-sV`) and Vulnerability Scripting (`--script vuln`).

```bash
./asm -d example.com -deep
```

*Note: Deep scans can take significantly longer depending on the target's size.*

### Interactive Database Viewer (TUI)
The framework includes a built-in Terminal User Interface (TUI) to interactively browse historical scan data, subdomains, open ports, web services, and vulnerabilities.

```bash
./asm -tui
```

**TUI Navigation:**
*   `Up/Down`: Select items.
*   `Right/Enter`: Step into a target or subdomain to view deeper details.
*   `Left/Esc/Backspace`: Step backwards out of a pane.
*   `q` or `Ctrl+C`: Quit the application safely.

### Machine-Readable Output (JSON)
Output the run's "delta" (only newly discovered assets) as a structured JSON object, ideal for integrating with SIEMs.

```bash
./asm -d example.com -json > delta.json
```

### On-Demand Offline Reporting
Generate a timestamped, interactive HTML dashboard and JSON report in the `internal-docs/reports/` directory directly from the existing database context, without triggering a new network scan.

```bash
./asm -d example.com -report-only
```

## Database Schema

The core persistence layer is a SQLite database (`asm.db`). 
*   `subdomains`: Unique discovered subdomains, root domains, and DNS resolution status.
*   `ports`: Port numbers, service protocols, versions, and state (linked to subdomains).
*   `web_services`: HTTP context including URL, Title, Tech Stack, and Status Codes.
*   `endpoints`: Deep URL paths and parameters.
*   `vulnerabilities`: Identified CVEs, ExploitDB matches, and severity details.
*   `scans`: Metadata tracking execution time and status of runner tools.
