package storage

import "time"

// Subdomain represents a discovered subdomain.
type Subdomain struct {
	ID           int64     `json:"id"`
	Domain       string    `json:"domain"`
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

// Storage defines the interface for data persistence.
type Storage interface {
	Init() error
	Close() error
	AddSubdomain(domain string) (Subdomain, bool, error) // Returns Subdomain, isNew, error
	AddPort(subdomainID int64, number int, service, version, state string) (Port, bool, error)
	GetSubdomains() ([]Subdomain, error)
	GetPorts(subdomainID int64) ([]Port, error)
}
