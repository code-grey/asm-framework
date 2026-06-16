package storage

import (
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteStorage struct {
	db *sql.DB
}

func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	return &SQLiteStorage{db: db}, nil
}

func (s *SQLiteStorage) Init() error {
	schema := `
	CREATE TABLE IF NOT EXISTS subdomains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT UNIQUE NOT NULL,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS ports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		subdomain_id INTEGER NOT NULL,
		number INTEGER NOT NULL,
		service TEXT,
		version TEXT DEFAULT '',
		state TEXT,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(subdomain_id) REFERENCES subdomains(id),
		UNIQUE(subdomain_id, number)
	);
	`
	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	// Graceful migration for existing databases
	_, _ = s.db.Exec("ALTER TABLE ports ADD COLUMN version TEXT DEFAULT ''")

	return nil
}

func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

func (s *SQLiteStorage) AddSubdomain(domain string) (Subdomain, bool, error) {
	var sub Subdomain
	var isNew bool

	// Check if exists
	err := s.db.QueryRow("SELECT id, domain, discovered_at FROM subdomains WHERE domain = ?", domain).
		Scan(&sub.ID, &sub.Domain, &sub.DiscoveredAt)

	if err == sql.ErrNoRows {
		// Insert
		res, err := s.db.Exec("INSERT INTO subdomains (domain, discovered_at) VALUES (?, ?)", domain, time.Now())
		if err != nil {
			return sub, false, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return sub, false, err
		}
		sub.ID = id
		sub.Domain = domain
		sub.DiscoveredAt = time.Now()
		isNew = true
	} else if err != nil {
		return sub, false, err
	}

	return sub, isNew, nil
}

func (s *SQLiteStorage) AddPort(subdomainID int64, number int, service, version, state string) (Port, bool, error) {
	var port Port
	var isNew bool

	err := s.db.QueryRow("SELECT id, subdomain_id, number, service, version, state, discovered_at FROM ports WHERE subdomain_id = ? AND number = ?", subdomainID, number).
		Scan(&port.ID, &port.SubdomainID, &port.Number, &port.Service, &port.Version, &port.State, &port.DiscoveredAt)

	if err == sql.ErrNoRows {
		res, err := s.db.Exec("INSERT INTO ports (subdomain_id, number, service, version, state, discovered_at) VALUES (?, ?, ?, ?, ?, ?)",
			subdomainID, number, service, version, state, time.Now())
		if err != nil {
			return port, false, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return port, false, err
		}
		port.ID = id
		port.SubdomainID = subdomainID
		port.Number = number
		port.Service = service
		port.Version = version
		port.State = state
		port.DiscoveredAt = time.Now()
		isNew = true
	} else if err != nil {
		// If port exists but version is new/updated, we could update it here. For now, simple insert/ignore.
		// Let's update version if the existing one is empty
		if port.Version == "" && version != "" {
			_, _ = s.db.Exec("UPDATE ports SET version = ?, service = ? WHERE id = ?", version, service, port.ID)
			port.Version = version
			port.Service = service
		}
		return port, false, err
	}

	return port, isNew, nil
}

func (s *SQLiteStorage) GetSubdomains() ([]Subdomain, error) {
	rows, err := s.db.Query("SELECT id, domain, discovered_at FROM subdomains")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subdomains []Subdomain
	for rows.Next() {
		var sub Subdomain
		if err := rows.Scan(&sub.ID, &sub.Domain, &sub.DiscoveredAt); err != nil {
			return nil, err
		}
		subdomains = append(subdomains, sub)
	}
	return subdomains, nil
}

func (s *SQLiteStorage) GetPorts(subdomainID int64) ([]Port, error) {
	rows, err := s.db.Query("SELECT id, subdomain_id, number, service, version, state, discovered_at FROM ports WHERE subdomain_id = ?", subdomainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []Port
	for rows.Next() {
		var port Port
		if err := rows.Scan(&port.ID, &port.SubdomainID, &port.Number, &port.Service, &port.Version, &port.State, &port.DiscoveredAt); err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, nil
}
