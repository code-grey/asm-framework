package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"asm-framework/pkg/logger"
	"asm-framework/pkg/orchestrator"
	"asm-framework/pkg/report"
	"asm-framework/pkg/runner"
	"asm-framework/pkg/storage"
	"asm-framework/pkg/tui"
)

func main() {
	domain := flag.String("d", "", "Target domain to scan (e.g. example.com)")
	dbPath := flag.String("db", "asm.db", "Path to SQLite database")
	jsonOut := flag.Bool("json", false, "Output results in JSON format")
	runTui := flag.Bool("tui", false, "Launch the interactive TUI viewer for the database")
	deepMode := flag.Bool("deep", false, "Run in deep mode (Amass active, Subfinder all sources, Nmap full ports + versioning)")
	reportOnly := flag.Bool("report-only", false, "Generate report from existing DB data without scanning")
	flag.Parse()

	logger.InitLogger(*deepMode, *jsonOut)

	// Sanitize domain input
	if *domain != "" {
		cleaned := strings.TrimSpace(*domain)
		cleaned = strings.TrimPrefix(cleaned, "http://")
		cleaned = strings.TrimPrefix(cleaned, "https://")
		cleaned = strings.TrimRight(cleaned, "/")
		*domain = cleaned
	}

	// Handle TUI mode (no domain required)
	if *runTui {
		store, err := storage.NewSQLiteStorage(*dbPath)
		if err != nil {
			logger.Fatalf("Failed to initialize database: %v", err)
		}
		defer store.Close()

		if err := store.Init(); err != nil {
			logger.Fatalf("Failed to initialize database schema: %v", err)
		}

		if err := tui.RunTUI(store); err != nil {
			logger.Fatalf("TUI Error: %v", err)
		}
		return
	}

	if *domain == "" {
		fmt.Println("Error: Target domain (-d) or -tui flag is required")
		flag.Usage()
		os.Exit(1)
	}

	// Setup Context with Signal Handling for Graceful Shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\n[!] Termination signal received. Gracefully shutting down...")
		cancel()
	}()

	if dir := filepath.Dir(*dbPath); dir != "." {
		os.MkdirAll(dir, 0755)
	}

	store, err := storage.NewSQLiteStorage(*dbPath)
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}
	defer store.Close()

	if err := store.Init(); err != nil {
		logger.Fatalf("Failed to initialize database schema: %v", err)
	}

	if *reportOnly {
		fmt.Printf("========================================\n")
		fmt.Printf("ASM Framework Report Generator\n")
		fmt.Printf("Generating offline report for: %s\n", *domain)
		fmt.Printf("========================================\n")
		
		reportDir := "internal-docs/reports"
		os.MkdirAll(reportDir, 0755)
		timestamp := time.Now().Format("20060102_150405")
		baseFilename := fmt.Sprintf("%s/report_%s_%s", reportDir, *domain, timestamp)
		
		if err := report.Generate(store, baseFilename, *domain); err != nil {
			logger.Fatalf("Failed to generate report: %v", err)
		}
		os.Exit(0)
	}

	pipeline := orchestrator.NewPipeline(store)
	pipeline.AddSubdomainRunner(runner.NewSubfinder())
	pipeline.AddSubdomainRunner(runner.NewAmass())
	pipeline.SetDNSResolver(runner.NewPuredns())
	pipeline.AddPortScanner(runner.NewNmap())
	pipeline.SetWebProber(runner.NewHttpx())
	pipeline.SetEndpointScraper(runner.NewGau())
	pipeline.SetNucleiScanner(runner.NewNuclei())
	pipeline.SetExploitScanner(runner.NewExploitDB())
	pipeline.SetNVDRunner(runner.NewNVD())

	if !*jsonOut {
		fmt.Printf("========================================\n")
		fmt.Printf("ASM Framework run for: %s\n", *domain)
		fmt.Printf("Database: %s\n", *dbPath)
		fmt.Printf("========================================\n")
	}

	summary, err := pipeline.Run(ctx, *domain, *deepMode)
	if err != nil && err != context.Canceled {
		logger.Fatalf("Pipeline failed: %v", err)
	}

	// Print Results even if partially completed due to cancellation
	if *jsonOut {
		b, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			logger.Fatalf("Failed to serialize output to JSON: %v", err)
		}
		fmt.Println(string(b))
	} else {
		fmt.Printf("\n================ SUMMARY ================\n")
		fmt.Printf("Total Subdomains Discovered: %d\n", summary.TotalSubdomains)
		if summary.LiveSubdomains > 0 || summary.DeadSubdomains > 0 {
			fmt.Printf("  Live (DNS Resolved):      %d\n", summary.LiveSubdomains)
			fmt.Printf("  Dead (NXDOMAIN):          %d\n", summary.DeadSubdomains)
		}
		fmt.Printf("New Subdomains Added:        %d\n", len(summary.NewSubdomains))
		if len(summary.NewSubdomains) > 0 {
			for _, sub := range summary.NewSubdomains {
				fmt.Printf("  + %s\n", sub)
			}
		}

		fmt.Printf("\nTotal Open Ports Found:      %d\n", summary.TotalPorts)
		fmt.Printf("New Open Ports Added:        %d\n", len(summary.NewPorts))
		if len(summary.NewPorts) > 0 {
			for _, port := range summary.NewPorts {
				fmt.Printf("  + %s:%d [%s]\n", port.Target, port.Number, port.Service)
			}
		}
		fmt.Printf("\nTotal Vulnerabilities Found: %d\n", summary.TotalVulnerabilities)
		fmt.Printf("=========================================\n")

		if err == context.Canceled {
			fmt.Println("\nRun partially completed due to cancellation. Database updated with gathered data.")
		} else {
			fmt.Println("\nRun complete! Database updated.")
		}

		// Generate the final comprehensive reports
		reportDir := "internal-docs/reports"
		os.MkdirAll(reportDir, 0755)
		timestamp := time.Now().Format("20060102_150405")
		baseFilename := fmt.Sprintf("%s/report_%s_%s", reportDir, *domain, timestamp)
		
		if err := report.Generate(store, baseFilename, *domain); err != nil {
			logger.Errorf("Failed to generate report: %v", err)
		}
	}
}
