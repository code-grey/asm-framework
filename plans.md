# ASM Framework Roadmap

## Phase 1: Core Engine (✅ Completed)
- [x] Storage Layer: SQLite schema for Subdomains and Ports.
- [x] Runner Interfaces: Generic execution interfaces.
- [x] Tool Integrations: Subfinder, Amass, Nmap.
- [x] Orchestrator: Pipeline execution, in-memory deduplication, and database diffing.
- [x] Graceful Shutdowns: Context cancellation and OS signal handling.
- [x] Deep Mode (`-deep`): Service version extraction and active DNS scanning.
- [x] Terminal UI (`-tui`): 3-pane interactive database viewer.

## Phase 2: Pipeline Expansion & Context (⏳ Up Next)
- [ ] **DNS Resolution (`puredns`)**:
  - Filter out dead subdomains before they reach Nmap to massively speed up the pipeline.
- [ ] **Web Probing & Tech Fingerprinting (`httpx`)**:
  - Scan open ports to extract Web Page Titles, HTTP Status Codes, and Tech Stacks.
  - Update SQLite schema to store web context.
- [ ] **Endpoint Discovery (`gau`)**:
  - Extract historical and hidden URLs for discovered live websites.

## Phase 3: Vulnerability & Reporting (✅ Completed)
- [x] **Nuclei Integration**: 
  - Automatically scan live `httpx` targets for known CVEs.
  - Improved result mapping to handle sub-paths via prefix matching.
- [x] **ExploitDB Integration**:
  - Integrated `searchsploit` for service-version based exploit lookup.
- [x] **Scan Progress Tracking**:
  - Added persistence for tool execution status (running/completed/failed).
  - Updated TUI with a live-ish "Scan Progress" pane.
- [ ] **Report Generator**:
  - Build a module to query the database and export a comprehensive report (PDF/Markdown/HTML) detailing assets, versions, and discovered vulnerabilities.

## Phase 5: Active Fuzzing & DAST (Future)
- [ ] **Proxy & Anonymization Routing**:
  - Implement proxy support (`HTTP`/`SOCKS5`) across all fuzzing runners.
  - Integrate with `proxychains` or a rotating proxy pool (e.g., `proxy-list`) to prevent IP blacklisting during aggressive scans.
- [ ] **Fuzzing Mode (`-fuzz`)**:
  - Introduce an aggressive attack mode, separate from `-deep`, to actively exploit discovered parameters.
- [ ] **Parameter Discovery via `arjun` / `x8`**:
  - Actively brute-force hidden or undocumented parameters (e.g., `?debug=true`, `?admin=1`) before fuzzing.
- [ ] **Cross-Site Scripting (XSS) via `Dalfox`**:
  - Automatically parse `gau` output for parameterized URLs and pipe them into Dalfox for XSS discovery.
- [ ] **SQL Injection (SQLi) via `SQLMap` or `Ghauri`**:
  - Automate SQLi payload delivery against discovered parameters.
- [ ] **Directory & API Brute-Forcing via `ffuf` / `feroxbuster`**:
  - Actively brute-force hidden directories, API endpoints, and configuration files (e.g., `.git`, `.env`) on live `httpx` targets.
- [ ] **Server-Side Request Forgery (SSRF) via `Interactsh` / `ParamSpider`**:
  - Inject OAST (Out-of-Band) callbacks into hidden parameters to catch blind SSRF and RCE.
- [ ] **Subdomain Takeover Detection**:
  - Integrate `subjack` to identify dangling CNAME records pointing to unclaimed cloud services (AWS, GitHub, Heroku).
- [ ] **JavaScript Analysis & Secret Extraction**:
  - Download discovered `.js` files and scan with `trufflehog` or `gitleaks` to find hardcoded API keys and credentials.
- [ ] **CORS Misconfiguration Scanning**:
  - Identify overly permissive Cross-Origin Resource Sharing policies.

## Phase 6: Defensive Posture & Compliance (Blue Team)
- [ ] **Continuous Diffing & Alerting**:
  - Compare current scan results against the previous database state. Trigger immediate alerts (Slack/Telegram) when *new* open ports, subdomains, or vulnerabilities appear.
- [ ] **WAF & CDN Profiling via `wafw00f`**:
  - Automatically detect if external assets are properly protected by WAFs (Cloudflare, Akamai, Imperva) and flag unprotected critical infrastructure.
- [ ] **Vulnerability Prioritization (CISA KEV & EPSS)**:
  - Cross-reference discovered CVEs against the CISA Known Exploited Vulnerabilities catalog and the Exploit Prediction Scoring System (EPSS) to prioritize what developers must patch first.
- [ ] **Technology Drift & EOL Detection**:
  - Track the `TechStack` (via `httpx`/`wappalyzer`) over time. Alert when a server is running End-of-Life (EOL) software (e.g., PHP 5.6, IIS 6.0) or when an unauthorized tech stack is deployed.
- [ ] **Visual Network Mapping (Graph Database)**:
  - Export data to Neo4j or BloodHound-style graphs to visualize relationships between domains, IP blocks, ASNs, and cloud providers.
- [ ] **Data Leakage & Public Exposure Monitoring**:
  - Scan public code repositories (GitHub/GitLab API) and Pastebin for leaked credentials matching the company's domain or IP space.
- [ ] **Cloud Asset Unification (CSPM)**:
  - Connect to AWS/GCP/Azure APIs (read-only) to map unmanaged cloud assets against the discovered external attack surface (Shadow IT detection).
- [ ] **SSL/TLS & Infrastructure Health**:
  - Integrate `testssl.sh` to grade cipher suites, detect expiring certificates, and flag vulnerable protocols (e.g., TLS 1.0).
- [ ] **Remediation Tracking (Ticketing System Integration)**:
  - Bi-directional sync with Jira/Jira Service Desk to automatically open tickets for critical vulnerabilities and mark them as resolved when a subsequent scan shows them patched.

## Phase 7: Framework Restructure (Core + Plugin Architecture)
- [ ] **The Go-Native Core (Single Binary)**:
  - Refactor baseline ASM runners to import external tools as Go libraries (e.g., `subfinder`, `httpx`, `nuclei`, `naabu`) rather than executing via `os/exec`.
  - Goal: The core framework functions as a frictionless, standalone single binary with zero external dependencies for 90% of reconnaissance tasks.
- [ ] **Nmap Replacement (Hybrid `naabu` + `zgrab2`)**:
  - Replace the C-based `nmap` with `naabu` (a pure Go port scanner) for ultra-fast asynchronous port sweeping.
  - Implement a Go-native banner grabbing fallback (e.g., `zgrab2` or custom dialers) on discovered open ports to retain exact service versioning for ExploitDB.
- [ ] **The Exploitation Plugins (Opt-In Expansion)**:
  - For advanced DAST tools written in other languages (e.g., `sqlmap` in Python, `wpscan` in Ruby), design a plugin system where the Go core orchestrates external execution.
  - The Go binary gracefully checks for host dependencies or leverages Docker containers to execute these complex, multi-language tools without bloating the core binary.

## Phase 8: Automation & Intelligence (Future)
- [ ] **Interactive TUI Dashboard**:
  - Evolve the `cmd/asm/main.go` entry point to support an interactive terminal application (using `tview` or `bubbletea`) for managing scans, configuring modules, and reviewing findings, while retaining headless CLI flag support.
- [ ] **Configuration Management (`config.yaml`)**:
  - Migrate hardcoded tool arguments (e.g., Nmap timing, Nuclei flags) into a centralized configuration file.
  - Allow users to override defaults without recompiling the framework.
- [ ] **Telegram Bot / Web UI**:
  - Create a new entry point (`cmd/bot/main.go`).
  - Enable asynchronous scan triggers via chat commands.
- [ ] **ThreatFeed Integration (Contextual Matching)**:
  - Ingest RSS feeds from `s.ee/threatfeed` (and other CTI sources).
  - Automatically scrape the destination URLs to retrieve the full article text.
  - Parse full feed text (using local LLMs like Ollama) to extract software names, versions, and CVEs.
  - Cross-reference against local ASM SQLite database to trigger immediate alerts on Zero-Day matches.
- [ ] **Hardware Acceleration (Auto-Scaling Workers)**:
  - Dynamically read available system CPU cores and RAM (`runtime.NumCPU()`, `gopsutil`).
  - Auto-scale the Goroutine worker pools (for `gau`, `nmap`, etc.) to saturate available hardware (e.g., spawning 100 workers on a 32-core server vs. 5 on a Raspberry Pi).

## Phase 9: Context-Aware Kali Tooling (Future)
- [ ] **Asynchronous Port Sweeping (`masscan` -> `nmap`)**:
  - Use `masscan` for rapid internet-scale port discovery, piping only the open ports to `nmap -sV` for deep banner grabbing.
- [ ] **Conditional CMS Exploitation (`wpscan` / `joomscan`)**:
  - Automatically trigger specialized scanners when `httpx` identifies specific technologies (e.g., WordPress, Joomla).
- [ ] **Corporate Infrastructure Mapping (`enum4linux` / `smbmap`)**:
  - Automatically trigger SMB and LDAP enumeration when ports 139 or 445 are discovered.
- [ ] **OSINT & Wetware Mapping (`theHarvester`)**:
  - Scrape employee emails and names from search engines to feed into Data Leakage monitors.
- [ ] **Deep Cryptographic Auditing (`sslscan`)**:
  - Run comprehensive TLS/SSL checks on all discovered port 443 services.
- [ ] **Legacy Misconfiguration Scanning (`nikto`)**:
  - Deploy `nikto` alongside Nuclei to catch legacy CGI and default administrative file exposures.
- [ ] **Advanced DNS OSINT (`dnsenum`)**:
  - Attempt Zone Transfers (AXFR) and map target ASNs at the beginning of the pipeline.

## Phase 10: Enterprise & Commercial Viability (SaaS Platform)
- [ ] **Distributed Agent Architecture**:
  - Run the ASM binary in `--agent` mode, connecting via WebSocket to a central orchestrator. Allows scanning internal VPCs, LANs, and external scopes simultaneously.
- [ ] **Multi-Tenancy & RBAC (Role-Based Access Control)**:
  - Update database schemas to support `tenant_id` for Managed Security Service Providers (MSSPs) to isolate client data.
- [ ] **API-First & SIEM Integration**:
  - Build a REST/GraphQL API for dashboard consumption.
  - Native webhooks to push findings into Splunk, Microsoft Sentinel, and DataDog via standard STIX/TAXII formats.
- [ ] **Compliance Mapping (SOC2, PCI-DSS, ISO27001)**:
  - Report generator that translates technical CVEs into compliance violations (e.g., "TLS 1.0 violates PCI-DSS 4.1").
- [ ] **Enterprise Secrets Vault**:
  - Native integration with HashiCorp Vault or AWS KMS to securely pull configuration API keys at runtime instead of relying on local YAML files.
- [ ] **Sandbox Execution (`code-grey/silo`)**:
  - Isolate custom scanning modules and fuzzers within unprivileged container runtimes to prevent malicious templates from compromising the host framework.

## Phase 11: Agentic API & Autonomous Red Teaming
- [ ] **LLM Tool Integration (The "Sensory Engine")**:
  - Expose the SQLite database and execution runners via a structured local API specifically formatted for LLM function calling (OpenAI Function Calling / LangChain Tools).
- [ ] **Agentic Orchestration (Dynamic Fuzzing)**:
  - Replace static pipelines with an LLM-driven decision engine. The LLM reviews the ASM data (e.g., "Found a login page on port 8080") and dynamically selects the next specialized tool (e.g., "Deploy Hydra against that endpoint").
- [ ] **Local-First AI Integration**:
  - Ensure the agentic orchestration can run entirely offline using local models (Ollama, vLLM) to guarantee zero data leakage of sensitive corporate infrastructure maps to external cloud APIs.
