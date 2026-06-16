# Developer Log - June 16, 2026

## Objective
Build a modular, highly performant Attack Surface Management (ASM) framework in Go from scratch. The framework must orchestrate external security tools, deduplicate findings, and persistently store state in a SQLite database to enable differential "delta" reporting for SIEM and local LLM ingestion.

## Implementation Steps & Milestones

### 1. Initial Architecture & Storage Layer
- Created a robust SQLite schema capable of tracking `subdomains` and `ports`.
- Implemented the `Storage` interface in `pkg/storage/storage.go` to enforce modularity.
- Implemented `SQLiteStorage` with automated table creation and graceful migrations, explicitly handling in-database deduplication via `UNIQUE` constraints and returning a boolean (`isNew`) to track the attack surface delta.

### 2. Core Runner Interfaces & Tool Integration (Phase 1)
- Defined the `SubdomainRunner` and `PortScanner` interfaces.
- Implemented wrappers for `Subfinder` and `Amass` via `os/exec`.
- **Debugging Amass:** Discovered that the native Kali/Debian `/usr/bin/amass` executable is a broken shell script relying on missing `libpostal_data`. Bypassed the wrapper by pointing the executor directly to `/usr/lib/amass/amass`.
- Implemented the `Nmap` runner. Addressed a critical data-mapping bug where Nmap outputted Reverse DNS names instead of target subdomains, causing database insertion failures. Fixed by forcing the parser to map ports strictly to the provided input target.

### 3. Orchestrator Pipeline & Concurrency
- Developed `pkg/orchestrator/pipeline.go` to tie the tools together.
- Implemented a strict **Worker Pool** pattern for Nmap scanning. Instead of spawning an unbounded number of goroutines (which risks file descriptor exhaustion), constrained concurrent port scanning to exactly 10 workers using buffered channels (`jobs` and `results`).
- Introduced Context (`context.Context`) propagation throughout the entire pipeline. Replaced standard `cmd.Run()` with `exec.CommandContext()` to enable OS-level `SIGKILL` execution.
- Wired `os.Signal` in `cmd/asm/main.go` to intercept `SIGINT` (Ctrl+C), gracefully killing child processes while preserving and saving all gathered data up to the point of cancellation.

### 4. Deep Mode & Terminal UI (TUI)
- Upgraded the database schema to support a `version` column in the ports table.
- Implemented a `-deep` flag that:
  - Switches Amass to `-active` mode (DNS brute-forcing, TLS cert scraping).
  - Switches Subfinder to `-all` mode.
  - Switches Nmap to `-p- -sV --script vuln` (Full 65k port sweep, service versioning, and NSE vulnerability scanning).
- Integrated `tview` and `tcell` to build a 3-pane interactive database viewer (`./asm -tui`).
- **TUI Debugging:** Fixed a freeze issue by implementing a global application input capture for `Ctrl+C` and `q`. Rewrote list navigation logic to allow fluid stepping inward (Domains -> Subdomains -> Ports) and backward (Esc/Left Arrow).
- Implemented an asynchronous ASCII spinner during long-running tasks to prevent the illusion of a frozen CLI.

### 5. Pipeline Expansion (Phase 2 Integrations)
- Expanded the pipeline into a precise funnel: `Enumeration -> Filtration -> Port Scanning -> Web Probing -> Endpoint Scraping`.
- **System Preparation:** Installed external Go tools to the local environment:
  - `go install github.com/d3mondev/puredns/v2@latest`
  - `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`
  - `go install github.com/lc/gau/v2/cmd/gau@latest`
  - Moved installed binaries to `/usr/local/bin/` to ensure global accessibility.
- Wrote Go wrappers for `puredns`, `httpx`, and `gau`.
- Updated SQLite schema to include `web_services` (titles, tech stacks, status codes) and `endpoints` (historical URLs).
- Updated the pipeline to sequentially execute these tools, passing outputs between them (e.g., extracting HTTP/HTTPS ports from Nmap results and piping them directly to `httpx`).
- Modified `os/exec` commands to include `SysProcAttr = &syscall.SysProcAttr{Setpgid: true}` and `Stdin = nil`. This isolates child processes into distinct process groups, permanently fixing a bug where crashed network tools corrupted the user's terminal by disabling local echo (`stty -echo`).

## Next Steps (Tomorrow)
- Implement Phase 3: `Nuclei` vulnerability scanner integration.
- Map `httpx` output directly into the `Nuclei` runner for surgical, high-speed vulnerability template execution.
