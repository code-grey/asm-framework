package orchestrator

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"asm-framework/pkg/runner"
	"asm-framework/pkg/storage"
)

type ResultSummary struct {
	Target            string
	TotalSubdomains   int
	NewSubdomains     []string
	TotalPorts        int
	NewPorts          []runner.PortResult
}

type Pipeline struct {
	storage          storage.Storage
	subdomainRunners []runner.SubdomainRunner
	portScanners     []runner.PortScanner
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

func (p *Pipeline) AddPortScanner(r runner.PortScanner) {
	p.portScanners = append(p.portScanners, r)
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
			
			fmt.Printf("    - Running %s...\n", runner.Name())
			subs, err := runner.Run(ctx, target, deep)
			if err != nil {
				log.Printf("    [!] Error running %s: %v\n", runner.Name(), err)
				return
			}
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

	targetsToScan := make([]string, 0, len(uniqueSubs))
	subdomainIDMap := make(map[string]int64)

	for sub := range uniqueSubs {
		subDB, isNew, err := p.storage.AddSubdomain(sub)
		if err != nil {
			log.Printf("[!] Error saving subdomain %s: %v\n", sub, err)
			continue
		}
		subdomainIDMap[sub] = subDB.ID
		targetsToScan = append(targetsToScan, sub)
		if isNew {
			summary.NewSubdomains = append(summary.NewSubdomains, sub)
		}
	}

	if len(p.portScanners) > 0 && len(targetsToScan) > 0 {
		fmt.Printf("[*] Starting %s port scanning for %d targets using %d workers\n", mode, len(targetsToScan), p.workerCount)
		
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
								// log.Printf overwrites spinner line, but for CLI it's acceptable error output
								log.Printf("\r    [!] Worker %d error on %s: %v\n", workerID, t, err)
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
				return summary, ctx.Err()
			case resBatch, ok := <-results:
				if !ok {
					break portReadLoop
				}
				allPorts = append(allPorts, resBatch...)
			}
		}
		stopSpinner2()

		summary.TotalPorts = len(allPorts)

		for _, res := range allPorts {
			subID, exists := subdomainIDMap[res.Target]
			if !exists {
				continue
			}
			
			_, isNew, err := p.storage.AddPort(subID, res.Number, res.Service, res.Version, res.State)
			if err != nil {
				log.Printf("\r[!] Error saving port %d on %s: %v\n", res.Number, res.Target, err)
				continue
			}
			if isNew {
				summary.NewPorts = append(summary.NewPorts, res)
			}
		}
	}

	return summary, nil
}
