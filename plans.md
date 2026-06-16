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

## Phase 3: Vulnerability & Reporting
- [ ] **Nuclei Integration**: 
  - Create `pkg/runner/nuclei.go`.
  - Automatically scan live `httpx` targets for known CVEs.
  - Update SQLite schema to store vulnerabilities.
- [ ] **Report Generator**:
  - Build a module to query the database and export a comprehensive report (PDF/Markdown/HTML) detailing assets, versions, and discovered vulnerabilities.

## Phase 4: Automation & Intelligence (Future)
- [ ] **Telegram Bot / Web UI**:
  - Create a new entry point (`cmd/bot/main.go`).
  - Enable asynchronous scan triggers via chat commands.
- [ ] **ThreatFeed Integration (Contextual Matching)**:
  - Ingest RSS feeds from `s.ee/threatfeed`.
  - Parse feed text (using Ollama) to extract software names/CVEs.
  - Cross-reference against local ASM SQLite database.
  - Trigger immediate alerts on matches.
