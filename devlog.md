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

## 2026-06-18: Vulnerability Pipeline Fixes and ExploitDB Integration
- **Fixed Nuclei Mapping:** Discovered that Nuclei findings were being dropped because they didn't exactly match the base URL from httpx. Implemented prefix-based mapping to correctly associate vulnerabilities with ports even when found on sub-paths.
- **Integrated ExploitDB:** Added a new runner for `searchsploit`. It now automatically queries ExploitDB for every service version discovered by Nmap and stores matching exploits in the database.
- **Implemented Scan Status Tracking:** Added a `scans` table to the SQLite database. The orchestrator now records the start time, end time, and status of every tool execution.
- **TUI Enhancements:** Updated the interactive TUI to include a "Scan Progress" pane, allowing users to see which tools have finished running for a target domain.
- **Amass Robustness:** Added a fallback for Amass to use the standard `amass` command if the direct binary path in `/usr/lib/amass/amass` is missing.

## 2026-06-18: Nuclei Hang Fix (Timeouts)
- **Implemented Timeouts:** Added a 15-minute `context.WithTimeout` wrap for the Nuclei runner. This resolves the issue where Nuclei could hang indefinitely during template evaluation or network deadlocks, taking down the whole pipeline with it.
- **Nuclei Safety Flags:** Added `-disable-update-check` to prevent interactive prompts or network hangs before scans even start.

## 2026-06-18: UX Enhancements and Configuration Roadmap
- **Nmap Fast Mode Fix:** Added `-sV` to the default (Fast) Nmap scan. Previously, only the Deep mode grabbed service banners, which meant ExploitDB would find nothing by default. Now it functions correctly across all modes.
- **Nuclei Spinner:** Added an active terminal spinner to the Nuclei runner. Because Nuclei can take several minutes to run, the lack of visual feedback made the framework appear hung. The active spinner reassures the user that the background process is still alive.
- **Roadmap Update:** Documented the planned move towards a `config.yaml` setup in Phase 4. This will eventually remove hardcoded tool arguments from the Go binaries, allowing for environment-specific customization without recompilation.

## 2026-06-18: Core Framework Optimizations (Phase 4)
- **Database Upserts:** Rewrote all SQLite `INSERT` operations (subdomains, ports, web services, endpoints, vulnerabilities) to use `ON CONFLICT DO UPDATE/NOTHING` (upserts). Also added performance pragmas (`WAL`, `cache_size`, `temp_store = MEMORY`). This dramatically reduces disk I/O and speeds up database operations by several orders of magnitude.
- **Streaming Output (Memory Efficiency):** Refactored all runner tools (Subfinder, Amass, Httpx, Gau, Puredns, Nuclei) to use `bufio.Scanner` and `cmd.StdoutPipe()`. Previously, entire tool outputs were buffered in RAM (using `bytes.Buffer`), causing massive memory spikes during large scans. The framework now processes output streams line-by-line with a near-zero memory footprint.
- **Timeouts:** Enforced a universal `context.WithTimeout` across all external tools to guarantee the pipeline will never zombie or hang indefinitely due to third-party rate limits or deadlocks.
- **DNS Filtering (Pipeline Pruning):** Integrated `puredns` into the orchestrator immediately after subdomain enumeration. Dead subdomains (NXDOMAIN) are now instantly dropped, meaning Nmap and subsequent tools only waste time scanning responsive infrastructure.
- **Gau Worker Pool:** Converted the sequential `gau` endpoint scraper into a concurrent Goroutine worker pool, drastically speeding up URL discovery across multiple live web services.
