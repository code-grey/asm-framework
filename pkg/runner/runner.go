package runner

import "context"

// SubdomainRunner defines an interface for tools that discover subdomains.
type SubdomainRunner interface {
	Run(ctx context.Context, target string, deep bool) ([]string, error)
	Name() string
}

// PortResult represents an open port discovered on a specific target.
type PortResult struct {
	Target  string // The IP or domain that was scanned
	Number  int
	Service string
	Version string // The exact software version running on the port
	State   string
}

// PortScanner defines an interface for tools that discover open ports.
type PortScanner interface {
	Run(ctx context.Context, targets []string, deep bool) ([]PortResult, error)
	Name() string
}
