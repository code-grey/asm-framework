package orchestrator

import (
	"encoding/json"
	"context"
	"fmt"
	"asm-framework/pkg/logger"
	"strings"
	"sync"
	"time"

	"asm-framework/pkg/runner"
	"asm-framework/pkg/storage"
)

type ResultSummary struct {
	Target            string
	TotalSubdomains   int
	NewSubdomains     []string
	DeadSubdomains    int
	LiveSubdomains    int
	TotalPorts        int
	NewPorts          []runner.PortResult
	TotalWebServices  int
	NewWebServices    []storage.WebService
	TotalEndpoints    int
	NewEndpoints      []storage.Endpoint
	TotalVulnerabilities int
}

type Pipeline struct {
	storage          storage.Storage
	subdomainRunners []runner.SubdomainRunner
	dnsResolver      *runner.Puredns
	portScanners     []runner.PortScanner
	webProber        *runner.Httpx
	endpointScraper  *runner.Gau
	nucleiScanner    *runner.Nuclei
	exploitScanner   *runner.ExploitDB
	nvdRunner        *runner.NVD
	workerCount      int
}

func NewPipeline(s storage.Storage) *Pipeline {
	return &Pipeline{
		storage:     s,
		workerCount: 10,
	}
}

func (p *Pipeline) AddSubdomainRunner(r runner.SubdomainRunner) {
	p.subdomainRunners = append(p.subdomainRunners, r)
}

func (p *Pipeline) SetDNSResolver(r *runner.Puredns) {
	p.dnsResolver = r
}

func (p *Pipeline) AddPortScanner(r runner.PortScanner) {
	p.portScanners = append(p.portScanners, r)
}

func (p *Pipeline) SetNVDRunner(r *runner.NVD) {
	p.nvdRunner = r
}

func (p *Pipeline) SetWebProber(r *runner.Httpx) {
	p.webProber = r
}

func (p *Pipeline) SetEndpointScraper(r *runner.Gau) {
	p.endpointScraper = r
}

func (p *Pipeline) SetNucleiScanner(r *runner.Nuclei) {
	p.nucleiScanner = r
}

func (p *Pipeline) SetExploitScanner(r *runner.ExploitDB) {
	p.exploitScanner = r
}


func (p *Pipeline) Run(ctx context.Context, target string, deep bool) (*ResultSummary, error) {
	summary := &ResultSummary{
		Target:        target,
		NewSubdomains: make([]string, 0),
		NewPorts:      make([]runner.PortResult, 0),
	}

	var wg sync.WaitGroup
	subdomainCh := make(chan string, 1000)

	mode := "Fast"
	if deep {
		mode = "Deep"
	}
	fmt.Printf("[*] Starting %s subdomain enumeration for %s\n", mode, target)
	for _, r := range p.subdomainRunners {
		wg.Add(1)
		go func(runner runner.SubdomainRunner) {
			defer wg.Done()
			
			// Check context before starting
			if ctx.Err() != nil {
				return
			}
			
			p.storage.UpdateScanStatus(target, runner.Name(), "running")
			fmt.Printf("    - Running %s...\n", runner.Name())
			subs, err := runner.Run(ctx, target, deep)
			if err != nil {
				logger.Errorf("    [!] Error running %s: %v\n", runner.Name(), err)
				p.storage.UpdateScanStatus(target, runner.Name(), "failed")
				return
			}
			p.storage.UpdateScanStatus(target, runner.Name(), "completed")
			fmt.Printf("    [+] %s completed (%d subdomains)\n", runner.Name(), len(subs))
			for _, sub := range subs {
				select {
				case <-ctx.Done():
					return
				case subdomainCh <- sub:
				}
			}
		}(r)
	}

	go func() {
		wg.Wait()
		close(subdomainCh)
	}()

	uniqueSubs := make(map[string]bool)
	uniqueSubs[target] = true

	// Spinner animation for subdomain enumeration
	spinCtx, stopSpinner := context.WithCancel(context.Background())
	go func() {
		chars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		for {
			select {
			case <-spinCtx.Done():
				fmt.Print("\r\033[K") // Clear line
				return
			default:
				fmt.Printf("\r    %s Waiting for enumeration to complete...", chars[i])
				i = (i + 1) % len(chars)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	// Read from channel, respect context cancellation
	readLoop:
	for {
		select {
		case <-ctx.Done():
			stopSpinner()
			fmt.Println("\n[!] Pipeline cancelled during subdomain enumeration.")
			return summary, ctx.Err()
		case sub, ok := <-subdomainCh:
			if !ok {
				break readLoop
			}
			uniqueSubs[sub] = true
		}
	}
	stopSpinner()

	summary.TotalSubdomains = len(uniqueSubs)
	fmt.Printf("\r[*] Discovered %d unique subdomains\n", len(uniqueSubs))

	var rawSubs []string
	for sub := range uniqueSubs {
		rawSubs = append(rawSubs, sub)
	}

	// 1. Insert ALL discovered subdomains into the database BEFORE filtering.
	// This ensures even dead subdomains are tracked for takeover detection and temporal analysis.
	subdomainIDMap := make(map[string]int64)
	for _, sub := range rawSubs {
		subDB, isNew, err := p.storage.AddSubdomain(sub)
		if err != nil {
			logger.Errorf("[!] Error saving subdomain %s: %v\n", sub, err)
			continue
		}
		subdomainIDMap[sub] = subDB.ID
		if isNew {
			summary.NewSubdomains = append(summary.NewSubdomains, sub)
		}
	}

	// 2. DNS Resolution Filtering — update alive/dead status in the database.
	// Only live subdomains proceed to port scanning; dead ones stay in the DB with is_alive=false.
	targetsToScan := make([]string, 0, len(uniqueSubs))

	if p.dnsResolver != nil {
		fmt.Printf("[*] Filtering dead subdomains with puredns...\n")
		p.storage.UpdateScanStatus(target, "puredns", "running")
		liveSubs, err := p.dnsResolver.Run(ctx, rawSubs)
		if err != nil {
			logger.Errorf("[!] Error running puredns: %v\n", err)
			p.storage.UpdateScanStatus(target, "puredns", "failed")
			// fallback to all if dns fails — mark everything alive
			targetsToScan = rawSubs
		} else {
			p.storage.UpdateScanStatus(target, "puredns", "completed")
			targetsToScan = liveSubs

			// Compute the dead set (rawSubs minus liveSubs)
			liveSet := make(map[string]bool, len(liveSubs))
			for _, s := range liveSubs {
				liveSet[s] = true
			}
			var deadSubs []string
			for _, s := range rawSubs {
				if !liveSet[s] {
					deadSubs = append(deadSubs, s)
				}
			}

			// Batch update alive/dead status in the database
			if err := p.storage.UpdateSubdomainAliveStatus(liveSubs, deadSubs); err != nil {
				logger.Errorf("[!] Error updating subdomain alive status: %v\n", err)
			}

			summary.DeadSubdomains = len(deadSubs)
			summary.LiveSubdomains = len(liveSubs)
			fmt.Printf("    [+] puredns: %d live, %d dead subdomains\n", len(liveSubs), len(deadSubs))
		}
	} else {
		targetsToScan = rawSubs
		summary.LiveSubdomains = len(rawSubs)
	}

	if len(p.portScanners) > 0 && len(targetsToScan) > 0 {
		fmt.Printf("[*] Starting %s port scanning for %d targets using %d workers\n", mode, len(targetsToScan), p.workerCount)
		p.storage.UpdateScanStatus(target, "nmap", "running")
		
		jobs := make(chan string, len(targetsToScan))
		results := make(chan []runner.PortResult, len(targetsToScan)*5)
		
		var portWg sync.WaitGroup
		var scannedCount int
		var countMut sync.Mutex

		for w := 1; w <= p.workerCount; w++ {
			portWg.Add(1)
			go func(workerID int) {
				defer portWg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case t, ok := <-jobs:
						if !ok {
							return
						}
						scanner := p.portScanners[0] 
						res, err := scanner.Run(ctx, []string{t}, deep)
						if err != nil {
							if ctx.Err() == nil {
								// logger.Errorf overwrites spinner line, but for CLI it's acceptable error output
								logger.Errorf("\r    [!] Worker %d error on %s: %v\n", workerID, t, err)
							}
							continue
						}
						
						countMut.Lock()
						scannedCount++
						countMut.Unlock()

						select {
						case <-ctx.Done():
							return
						case results <- res:
						}
					}
				}
			}(w)
		}

		// Feed jobs
		go func() {
			for _, t := range targetsToScan {
				select {
				case <-ctx.Done():
					break
				case jobs <- t:
				}
			}
			close(jobs)
		}()

		go func() {
			portWg.Wait()
			close(results)
		}()

		// Spinner for port scanning
		spinCtx2, stopSpinner2 := context.WithCancel(context.Background())
		go func() {
			chars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			i := 0
			total := len(targetsToScan)
			for {
				select {
				case <-spinCtx2.Done():
					fmt.Print("\r\033[K")
					return
				default:
					countMut.Lock()
					c := scannedCount
					countMut.Unlock()
					fmt.Printf("\r    %s Scanning [%d/%d] targets...", chars[i], c, total)
					i = (i + 1) % len(chars)
					time.Sleep(100 * time.Millisecond)
				}
			}
		}()

		var allPorts []runner.PortResult
		
		portReadLoop:
		for {
			select {
			case <-ctx.Done():
				stopSpinner2()
				fmt.Println("\n[!] Pipeline cancelled during port scanning.")
				p.storage.UpdateScanStatus(target, "nmap", "failed")
				return summary, ctx.Err()
			case resBatch, ok := <-results:
				if !ok {
					break portReadLoop
				}
				allPorts = append(allPorts, resBatch...)
			}
		}
		stopSpinner2()
		p.storage.UpdateScanStatus(target, "nmap", "completed")

		summary.TotalPorts = len(allPorts)

		var webTargets []string
		portIDMap := make(map[string]int64) // maps URL to Port ID

		for _, res := range allPorts {
			subID, exists := subdomainIDMap[res.Target]
			if !exists {
				continue
			}
			
			portDB, isNew, err := p.storage.AddPort(subID, res.Number, res.Service, res.Version, res.State)
			if err != nil {
				logger.Errorf("\r[!] Error saving port %d on %s: %v\n", res.Number, res.Target, err)
				continue
			}
			if isNew {
				summary.NewPorts = append(summary.NewPorts, res)
			}

			// 2.5 ExploitDB Lookup (if version is present)
			if p.exploitScanner != nil && res.Version != "" {
				p.storage.UpdateScanStatus(target, "exploitdb", "running")
				exploits, err := p.exploitScanner.Run(ctx, res.Version)
				if err == nil && len(exploits) > 0 {
					for _, exp := range exploits {
						cve := ""
						cvss := 0.0
						severity := "HIGH" // Default for exploitdb

						// Parse first CVE from Codes
						if exp.Codes != "" {
							parts := strings.Split(exp.Codes, ";")
							for _, pCode := range parts {
								if strings.HasPrefix(strings.ToUpper(pCode), "CVE-") {
									cve = pCode
									break
								}
							}
						}

						// Fetch CVSS if we have a CVE and NVD runner is attached
						if cve != "" && p.nvdRunner != nil {
							nvdRes := p.nvdRunner.FetchCVSS(cve)
							if nvdRes.CVSS > 0 {
								cvss = nvdRes.CVSS
								severity = nvdRes.Severity
							}
						}

						_, _, _ = p.storage.AddVulnerability(portDB.ID, "exploitdb", exp.Title, severity, cve, cvss, exp.Path)
						summary.TotalVulnerabilities++
					}
				}
				p.storage.UpdateScanStatus(target, "exploitdb", "completed")
			}

			// Collect web targets for httpx (HTTP/HTTPS)
			if strings.Contains(res.Service, "http") || res.Number == 80 || res.Number == 443 || res.Number == 8080 || res.Number == 8443 {
				scheme := "http://"
				if strings.Contains(res.Service, "https") || res.Number == 443 || res.Number == 8443 {
					scheme = "https://"
				}
				url := fmt.Sprintf("%s%s:%d", scheme, res.Target, res.Number)
				webTargets = append(webTargets, url)
				portIDMap[url] = portDB.ID
			}
		}

		// 3. Web Probing (httpx)
		var liveWebServices []string // URLs for GAU to scan
		if p.webProber != nil && len(webTargets) > 0 {
			fmt.Printf("[*] Probing %d web services with httpx...\n", len(webTargets))
			p.storage.UpdateScanStatus(target, "httpx", "running")
			httpxResults, err := p.webProber.Run(ctx, webTargets)
			if err == nil {
				summary.TotalWebServices = len(httpxResults)
				for _, ws := range httpxResults {
					portID, ok := portIDMap[ws.URL]
					if !ok {
						continue // fallback
					}
					
					// Convert tech slice and metadata to structured JSON
					type StructuredTech struct {
						WebServer    string   `json:"web_server,omitempty"`
						CDN          string   `json:"cdn,omitempty"`
						Technologies []string `json:"technologies,omitempty"`
					}
					
					techObj := StructuredTech{
						WebServer:    ws.WebServer,
						CDN:          ws.CDNName,
						Technologies: ws.Tech,
					}
					
					techBytes, _ := json.Marshal(techObj)
					techStr := string(techBytes)

					wsDB, isNew, err := p.storage.AddWebService(portID, ws.URL, ws.Title, ws.StatusCode, techStr)
					if err != nil {
						logger.Errorf("[!] Error saving web service %s: %v\n", ws.URL, err)
						continue
					}
					if isNew {
						summary.NewWebServices = append(summary.NewWebServices, wsDB)
					}
					liveWebServices = append(liveWebServices, ws.URL)
				}
				p.storage.UpdateScanStatus(target, "httpx", "completed")
			} else {
				p.storage.UpdateScanStatus(target, "httpx", "failed")
			}
			fmt.Printf("    [+] httpx probing completed\n")
		}

		// 4. Endpoint Scraping (gau)
		if p.endpointScraper != nil && len(liveWebServices) > 0 && deep {
			fmt.Printf("[*] Deep Scraping endpoints for %d live websites with gau using %d workers...\n", len(liveWebServices), p.workerCount)
			p.storage.UpdateScanStatus(target, "gau", "running")
			
			gauJobs := make(chan string, len(liveWebServices))
			var gauWg sync.WaitGroup

			// Mutex to protect summary fields and DB writes inside the worker
			var gauMut sync.Mutex

			for w := 1; w <= p.workerCount; w++ {
				gauWg.Add(1)
				go func() {
					defer gauWg.Done()
					for targetURL := range gauJobs {
						if ctx.Err() != nil {
							return
						}
						
						// Naive extraction: https://sub.domain.com:443 -> sub.domain.com
						hostPart := strings.TrimPrefix(targetURL, "http://")
						hostPart = strings.TrimPrefix(hostPart, "https://")
						if idx := strings.Index(hostPart, ":"); idx != -1 {
							hostPart = hostPart[:idx]
						}
						
						subID, exists := subdomainIDMap[hostPart]
						if !exists {
							continue
						}

						urls, err := p.endpointScraper.Run(ctx, targetURL)
						if err == nil {
							gauMut.Lock()
							summary.TotalEndpoints += len(urls)
							for _, u := range urls {
								epDB, isNew, err := p.storage.AddEndpoint(subID, u)
								if err == nil && isNew {
									summary.NewEndpoints = append(summary.NewEndpoints, epDB)
								}
							}
							gauMut.Unlock()
						}
					}
				}()
			}

			// Feed gau jobs
			for _, targetURL := range liveWebServices {
				gauJobs <- targetURL
			}
			close(gauJobs)

			// Spinner for gau
			spinCtxGau, stopGauSpinner := context.WithCancel(context.Background())
			go func() {
				chars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
				i := 0
				for {
					select {
					case <-spinCtxGau.Done():
						fmt.Print("\r\033[K")
						return
					default:
						fmt.Printf("\r    %s Scraping endpoints...", chars[i])
						i = (i + 1) % len(chars)
						time.Sleep(100 * time.Millisecond)
					}
				}
			}()

			gauWg.Wait()
			stopGauSpinner()

			p.storage.UpdateScanStatus(target, "gau", "completed")
			fmt.Printf("    [+] gau scraping completed\n")
		}

		// 5. Vulnerability Scanning (nuclei)
		if p.nucleiScanner != nil && len(liveWebServices) > 0 {
			p.storage.UpdateScanStatus(target, "nuclei", "running")
			
			// Nuclei Spinner
			spinCtx3, stopSpinner3 := context.WithCancel(context.Background())
			go func() {
				chars := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
				i := 0
				for {
					select {
					case <-spinCtx3.Done():
						fmt.Print("\r\033[K")
						return
					default:
						fmt.Printf("\r    %s Scanning %d live services with nuclei...", chars[i], len(liveWebServices))
						i = (i + 1) % len(chars)
						time.Sleep(100 * time.Millisecond)
					}
				}
			}()

			nucleiResults, err := p.nucleiScanner.Run(ctx, liveWebServices)
			stopSpinner3() // Stop spinner before printing next line
			
			if err == nil {
				for _, vuln := range nucleiResults {
					// Find portID
					// matchedAt is like https://sub.domain.com:443/login.php
					// portIDMap keys are like https://sub.domain.com:443
					
					var portID int64
					found := false
					
					// Prefix matching to handle sub-paths
					for url, pid := range portIDMap {
						if strings.HasPrefix(vuln.MatchedAt, url) {
							portID = pid
							found = true
							break
						}
					}

					if !found {
						continue 
					}
					
					cve := ""
					if len(vuln.Info.Classification.CVEID) > 0 {
						cve = vuln.Info.Classification.CVEID[0]
					}
					cvss := vuln.Info.Classification.CVSSScore
					
					_, _, err := p.storage.AddVulnerability(portID, vuln.TemplateID, vuln.Info.Name, vuln.Info.Severity, cve, cvss, vuln.MatchedAt)
					if err != nil {
						logger.Errorf("[!] Error saving vulnerability %s: %v\n", vuln.TemplateID, err)
					} else {
						summary.TotalVulnerabilities++
					}
				}
				p.storage.UpdateScanStatus(target, "nuclei", "completed")
			} else {
				p.storage.UpdateScanStatus(target, "nuclei", "failed")
			}
			fmt.Printf("    [+] nuclei scanning completed (%d findings)\n", summary.TotalVulnerabilities)
		}

	}

	return summary, nil
}
