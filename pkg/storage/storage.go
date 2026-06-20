package storage

import "time"

// Subdomain represents a discovered subdomain.
type Subdomain struct {
	ID           int64     `json:"id"`
	Domain       string    `json:"domain"`
	IsAlive      bool      `json:"is_alive"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Port represents an open port on a subdomain.
type Port struct {
	ID           int64     `json:"id"`
	SubdomainID  int64     `json:"subdomain_id"`
	Number       int       `json:"number"`
	Service      string    `json:"service"`
	Version      string    `json:"version"`
	State        string    `json:"state"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// WebService represents HTTP context gathered by httpx
type WebService struct {
	ID           int64     `json:"id"`
	PortID       int64     `json:"port_id"`
	URL          string    `json:"url"`
	Title        string    `json:"title"`
	StatusCode   int       `json:"status_code"`
	TechStack    string    `json:"tech_stack"` // Comma separated or JSON
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Endpoint represents a deep URL gathered by gau
type Endpoint struct {
	ID           int64     `json:"id"`
	SubdomainID  int64     `json:"subdomain_id"`
	URL          string    `json:"url"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Vulnerability represents a vulnerability found by Nuclei
type Vulnerability struct {
	ID           int64     `json:"id"`
	PortID       int64     `json:"port_id"`
	TemplateID   string    `json:"template_id"`
	Name         string    `json:"name"`
	Severity     string    `json:"severity"`
	MatchedAt    string    `json:"matched_at"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Scan represents a tool execution status
type Scan struct {
	ID         int64      `json:"id"`
	Target     string     `json:"target"`
	Tool       string     `json:"tool"`
	Status     string     `json:"status"` // "running", "completed", "failed"
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

// Storage defines the interface for data persistence.
type Storage interface {
	Init() error
	Close() error
	AddSubdomain(domain string) (Subdomain, bool, error) // Returns Subdomain, isNew, error
	UpdateSubdomainAliveStatus(alive []string, dead []string) error
	AddPort(subdomainID int64, number int, service, version, state string) (Port, bool, error)
	AddWebService(portID int64, url, title string, statusCode int, techStack string) (WebService, bool, error)
	AddEndpoint(subdomainID int64, url string) (Endpoint, bool, error)
	AddVulnerability(portID int64, templateID, name, severity, matchedAt string) (Vulnerability, bool, error)
	GetSubdomains() ([]Subdomain, error)
	GetPorts(subdomainID int64) ([]Port, error)
	GetWebServices(portID int64) ([]WebService, error)
	GetEndpoints(subdomainID int64) ([]Endpoint, error)
	GetVulnerabilities(portID int64) ([]Vulnerability, error)

	// Scan tracking
	UpdateScanStatus(target, tool, status string) error
	GetScans(target string) ([]Scan, error)
}

