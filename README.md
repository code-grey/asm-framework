# Attack Surface Management (ASM) Framework

A modular, orchestration-driven framework written in Go for automated attack surface discovery, network mapping, and vulnerability context gathering.

## Architecture

The framework operates sequentially through a funnel-based architecture, progressively narrowing targets to ensure speed and accuracy:

1.  **Subdomain Enumeration**: Discovers potential targets using `subfinder` and `amass`.
2.  **DNS Resolution**: Filters out dead or parked domains using `puredns` to preserve downstream scan time.
3.  **Port Scanning**: Identifies open ports and services on live targets using `nmap`.
4.  **Web Context Probing**: Connects to open web ports using `httpx` to extract page titles, HTTP status codes, and underlying technology stacks.
5.  **Endpoint Discovery**: Scrapes historical and hidden URLs from live websites using `gau`.

All gathered intelligence is deduplicated in memory and permanently persisted to a local SQLite database (`asm.db`).

## Assumptions

*   The tool is executed in a Unix-like environment (Linux/macOS) with root or sudo privileges available for certain `nmap` packet operations if required.
*   The host machine has an active, unfiltered outbound internet connection.
*   The required external binaries (listed below) are installed and available in the system `$PATH`.
*   You have explicit permission to scan the target domains.

## Prerequisites

The framework is an orchestrator; it does not replace the security tools. You must have the following installed on your system:

*   **Go** (1.20+)
*   **Nmap**
*   **Subfinder** (`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`)
*   **Amass** (v4.x installed natively, not via broken shell wrappers)
*   **Massdns** (Required dependency for puredns)
*   **Puredns** (`go install github.com/d3mondev/puredns/v2@latest`)
*   **Httpx** (`go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`)
*   **Gau** (`go install github.com/lc/gau/v2/cmd/gau@latest`)

Ensure all tools, especially those installed via `go install`, are accessible globally (e.g., symlinked to `/usr/local/bin/`).

## Installation

Clone the repository and compile the Go binary:

```bash
git clone <repository_url>
cd asm-framework
go mod tidy
go build -ldflags="-s -w" -trimpath -o asm ./cmd/asm
```

## Usage

### Basic Scan (Fast)

Executes passive subdomain enumeration and probes the top 100 most common ports.

```bash
./asm -d example.com
```

### Deep Scan (Thorough)

Activates deep enumeration mode. Amass will perform active TLS and DNS scraping, Subfinder will use all available premium sources, and Nmap will perform a full 65,535 port sweep with Service Versioning (`-sV`) and Vulnerability Scripting (`--script vuln`).

```bash
./asm -d example.com -deep
```

*Note: Deep scans can take significantly longer (from minutes to hours) depending on the target's size and network firewall configurations.*

### Interactive Database Viewer (TUI)

The framework includes a built-in Terminal User Interface (TUI) to interactively browse your historical scan data, subdomains, open ports, and software versions without writing SQL queries.

```bash
./asm -tui
```

**TUI Navigation:**
*   `Up/Down`: Select items.
*   `Right/Enter`: Step into a target or subdomain to view deeper details.
*   `Left/Esc/Backspace`: Step backwards out of a pane.
*   `q` or `Ctrl+C`: Quit the application safely.

### Machine-Readable Output (JSON)

For integration with external pipelines, SIEMs, or local LLMs, you can output the run's "delta" (only newly discovered assets) as a structured JSON object.

```bash
./asm -d example.com -json > delta.json
```

## Database Schema

The core persistence layer is a SQLite database (`asm.db`). It automatically manages schema migrations. 

*   `subdomains`: Stores all unique, discovered subdomains and root domains.
*   `ports`: Stores port numbers, service protocols, service versions, and state, linked to `subdomains`.
*   `web_services`: Stores HTTP context (URL, Title, Tech Stack, Status), linked to `ports`.
*   `endpoints`: Stores deep URL paths and parameters, linked to `subdomains`.

## Future Roadmap

Please refer to the `plans.md` file for the upcoming integrations, including Nuclei vulnerability scanning, Report Generation, and Threat Intelligence RSS matching.
