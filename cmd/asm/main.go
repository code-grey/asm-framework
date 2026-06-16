package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"asm-framework/pkg/orchestrator"
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
	flag.Parse()

	// Handle TUI mode (no domain required)
	if *runTui {
		store, err := storage.NewSQLiteStorage(*dbPath)
		if err != nil {
			log.Fatalf("Failed to initialize database: %v", err)
		}
		defer store.Close()

		if err := store.Init(); err != nil {
			log.Fatalf("Failed to initialize database schema: %v", err)
		}

		if err := tui.RunTUI(store); err != nil {
			log.Fatalf("TUI Error: %v", err)
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
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer store.Close()

	if err := store.Init(); err != nil {
		log.Fatalf("Failed to initialize database schema: %v", err)
	}

	pipeline := orchestrator.NewPipeline(store)
	pipeline.AddSubdomainRunner(runner.NewSubfinder())
	pipeline.AddSubdomainRunner(runner.NewAmass())
	pipeline.AddPortScanner(runner.NewNmap())

	if !*jsonOut {
		fmt.Printf("========================================\n")
		fmt.Printf("ASM Framework run for: %s\n", *domain)
		fmt.Printf("Database: %s\n", *dbPath)
		fmt.Printf("========================================\n")
	}

	summary, err := pipeline.Run(ctx, *domain, *deepMode)
	if err != nil && err != context.Canceled {
		log.Fatalf("Pipeline failed: %v", err)
	}

	// Print Results even if partially completed due to cancellation
	if *jsonOut {
		b, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			log.Fatalf("Failed to serialize output to JSON: %v", err)
		}
		fmt.Println(string(b))
	} else {
		fmt.Printf("\n================ SUMMARY ================\n")
		fmt.Printf("Total Subdomains Discovered: %d\n", summary.TotalSubdomains)
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
		fmt.Printf("=========================================\n")
		
		if err == context.Canceled {
			fmt.Println("\nRun partially completed due to cancellation. Database updated with gathered data.")
		} else {
			fmt.Println("\nRun complete! Database updated.")
		}
	}
}
