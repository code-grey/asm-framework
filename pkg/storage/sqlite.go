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

	CREATE TABLE IF NOT EXISTS web_services (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		port_id INTEGER NOT NULL,
		url TEXT UNIQUE NOT NULL,
		title TEXT,
		status_code INTEGER,
		tech_stack TEXT,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(port_id) REFERENCES ports(id)
	);

	CREATE TABLE IF NOT EXISTS endpoints (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		subdomain_id INTEGER NOT NULL,
		url TEXT UNIQUE NOT NULL,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
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

func (s *SQLiteStorage) AddWebService(portID int64, url, title string, statusCode int, techStack string) (WebService, bool, error) {
	var ws WebService
	var isNew bool

	err := s.db.QueryRow("SELECT id, port_id, url, title, status_code, tech_stack, discovered_at FROM web_services WHERE url = ?", url).
		Scan(&ws.ID, &ws.PortID, &ws.URL, &ws.Title, &ws.StatusCode, &ws.TechStack, &ws.DiscoveredAt)

	if err == sql.ErrNoRows {
		res, err := s.db.Exec("INSERT INTO web_services (port_id, url, title, status_code, tech_stack, discovered_at) VALUES (?, ?, ?, ?, ?, ?)",
			portID, url, title, statusCode, techStack, time.Now())
		if err != nil {
			return ws, false, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return ws, false, err
		}
		ws.ID = id
		ws.PortID = portID
		ws.URL = url
		ws.Title = title
		ws.StatusCode = statusCode
		ws.TechStack = techStack
		ws.DiscoveredAt = time.Now()
		isNew = true
	} else if err != nil {
		return ws, false, err
	} else {
		// Update title/status/tech if it already existed but might have changed
		_, _ = s.db.Exec("UPDATE web_services SET title = ?, status_code = ?, tech_stack = ? WHERE id = ?", title, statusCode, techStack, ws.ID)
	}

	return ws, isNew, nil
}

func (s *SQLiteStorage) AddEndpoint(subdomainID int64, url string) (Endpoint, bool, error) {
	var ep Endpoint
	var isNew bool

	err := s.db.QueryRow("SELECT id, subdomain_id, url, discovered_at FROM endpoints WHERE url = ?", url).
		Scan(&ep.ID, &ep.SubdomainID, &ep.URL, &ep.DiscoveredAt)

	if err == sql.ErrNoRows {
		res, err := s.db.Exec("INSERT INTO endpoints (subdomain_id, url, discovered_at) VALUES (?, ?, ?)",
			subdomainID, url, time.Now())
		if err != nil {
			return ep, false, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return ep, false, err
		}
		ep.ID = id
		ep.SubdomainID = subdomainID
		ep.URL = url
		ep.DiscoveredAt = time.Now()
		isNew = true
	} else if err != nil {
		return ep, false, err
	}

	return ep, isNew, nil
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

func (s *SQLiteStorage) GetWebServices(portID int64) ([]WebService, error) {
	rows, err := s.db.Query("SELECT id, port_id, url, title, status_code, tech_stack, discovered_at FROM web_services WHERE port_id = ?", portID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var wss []WebService
	for rows.Next() {
		var ws WebService
		if err := rows.Scan(&ws.ID, &ws.PortID, &ws.URL, &ws.Title, &ws.StatusCode, &ws.TechStack, &ws.DiscoveredAt); err != nil {
			return nil, err
		}
		wss = append(wss, ws)
	}
	return wss, nil
}

func (s *SQLiteStorage) GetEndpoints(subdomainID int64) ([]Endpoint, error) {
	rows, err := s.db.Query("SELECT id, subdomain_id, url, discovered_at FROM endpoints WHERE subdomain_id = ?", subdomainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var eps []Endpoint
	for rows.Next() {
		var ep Endpoint
		if err := rows.Scan(&ep.ID, &ep.SubdomainID, &ep.URL, &ep.DiscoveredAt); err != nil {
			return nil, err
		}
		eps = append(eps, ep)
	}
	return eps, nil
}
