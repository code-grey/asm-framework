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
	// Enable performance pragmas
	_, _ = s.db.Exec(`
		PRAGMA journal_mode = WAL;
		PRAGMA synchronous = NORMAL;
		PRAGMA cache_size = -64000;
		PRAGMA temp_store = MEMORY;
	`)

	schema := `
	CREATE TABLE IF NOT EXISTS subdomains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT UNIQUE NOT NULL,
		is_alive INTEGER NOT NULL DEFAULT 1,
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

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		port_id INTEGER NOT NULL,
		template_id TEXT NOT NULL,
		name TEXT NOT NULL,
		severity TEXT NOT NULL,
		matched_at TEXT NOT NULL,
		discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(port_id) REFERENCES ports(id),
		UNIQUE(port_id, template_id, matched_at)
	);

	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		tool TEXT NOT NULL,
		status TEXT NOT NULL,
		started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		finished_at DATETIME,
		UNIQUE(target, tool)
	);
	`
	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	// Graceful migration for existing databases
	_, _ = s.db.Exec("ALTER TABLE ports ADD COLUMN version TEXT DEFAULT ''")
	_, _ = s.db.Exec("ALTER TABLE subdomains ADD COLUMN is_alive INTEGER NOT NULL DEFAULT 1")

	return nil
}

func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

func (s *SQLiteStorage) AddSubdomain(domain string) (Subdomain, bool, error) {
	var sub Subdomain
	var isNew bool

	// Upsert query — new subdomains default to is_alive=1 (optimistic)
	_, err := s.db.Exec(`
		INSERT INTO subdomains (domain, discovered_at) VALUES (?, ?)
		ON CONFLICT(domain) DO NOTHING
	`, domain, time.Now())
	
	if err != nil {
		return sub, false, err
	}

	err = s.db.QueryRow("SELECT id, domain, is_alive, discovered_at FROM subdomains WHERE domain = ?", domain).
		Scan(&sub.ID, &sub.Domain, &sub.IsAlive, &sub.DiscoveredAt)
		
	// If the discovered_at time is very close to now, it's newly inserted
	if time.Since(sub.DiscoveredAt) < time.Second {
		isNew = true
	}

	return sub, isNew, err
}

func (s *SQLiteStorage) UpdateSubdomainAliveStatus(alive []string, dead []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmtAlive, err := tx.Prepare("UPDATE subdomains SET is_alive = 1 WHERE domain = ?")
	if err != nil {
		return err
	}
	defer stmtAlive.Close()

	for _, d := range alive {
		if _, err := stmtAlive.Exec(d); err != nil {
			return err
		}
	}

	stmtDead, err := tx.Prepare("UPDATE subdomains SET is_alive = 0 WHERE domain = ?")
	if err != nil {
		return err
	}
	defer stmtDead.Close()

	for _, d := range dead {
		if _, err := stmtDead.Exec(d); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *SQLiteStorage) AddPort(subdomainID int64, number int, service, version, state string) (Port, bool, error) {
	var port Port
	var isNew bool

	_, err := s.db.Exec(`
		INSERT INTO ports (subdomain_id, number, service, version, state, discovered_at) 
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(subdomain_id, number) DO UPDATE SET 
		version = excluded.version,
		service = excluded.service,
		state = excluded.state
	`, subdomainID, number, service, version, state, time.Now())
	
	if err != nil {
		return port, false, err
	}

	err = s.db.QueryRow("SELECT id, subdomain_id, number, service, version, state, discovered_at FROM ports WHERE subdomain_id = ? AND number = ?", subdomainID, number).
		Scan(&port.ID, &port.SubdomainID, &port.Number, &port.Service, &port.Version, &port.State, &port.DiscoveredAt)

	if err == nil && time.Since(port.DiscoveredAt) < time.Second {
		isNew = true
	}

	return port, isNew, err
}

func (s *SQLiteStorage) AddWebService(portID int64, url, title string, statusCode int, techStack string) (WebService, bool, error) {
	var ws WebService
	var isNew bool

	_, err := s.db.Exec(`
		INSERT INTO web_services (port_id, url, title, status_code, tech_stack, discovered_at) 
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(url) DO UPDATE SET 
		title = excluded.title,
		status_code = excluded.status_code,
		tech_stack = excluded.tech_stack
	`, portID, url, title, statusCode, techStack, time.Now())

	if err != nil {
		return ws, false, err
	}

	err = s.db.QueryRow("SELECT id, port_id, url, title, status_code, tech_stack, discovered_at FROM web_services WHERE url = ?", url).
		Scan(&ws.ID, &ws.PortID, &ws.URL, &ws.Title, &ws.StatusCode, &ws.TechStack, &ws.DiscoveredAt)

	if err == nil && time.Since(ws.DiscoveredAt) < time.Second {
		isNew = true
	}

	return ws, isNew, err
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

func (s *SQLiteStorage) AddVulnerability(portID int64, templateID, name, severity, matchedAt string) (Vulnerability, bool, error) {
	var vuln Vulnerability
	var isNew bool

	_, err := s.db.Exec(`
		INSERT INTO vulnerabilities (port_id, template_id, name, severity, matched_at, discovered_at) 
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(port_id, template_id, matched_at) DO NOTHING
	`, portID, templateID, name, severity, matchedAt, time.Now())

	if err != nil {
		return vuln, false, err
	}

	err = s.db.QueryRow("SELECT id, port_id, template_id, name, severity, matched_at, discovered_at FROM vulnerabilities WHERE port_id = ? AND template_id = ? AND matched_at = ?", portID, templateID, matchedAt).
		Scan(&vuln.ID, &vuln.PortID, &vuln.TemplateID, &vuln.Name, &vuln.Severity, &vuln.MatchedAt, &vuln.DiscoveredAt)

	if err == nil && time.Since(vuln.DiscoveredAt) < time.Second {
		isNew = true
	}

	return vuln, isNew, err
}

func (s *SQLiteStorage) GetSubdomains() ([]Subdomain, error) {
	rows, err := s.db.Query("SELECT id, domain, is_alive, discovered_at FROM subdomains")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subdomains []Subdomain
	for rows.Next() {
		var sub Subdomain
		if err := rows.Scan(&sub.ID, &sub.Domain, &sub.IsAlive, &sub.DiscoveredAt); err != nil {
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

func (s *SQLiteStorage) GetVulnerabilities(portID int64) ([]Vulnerability, error) {
	rows, err := s.db.Query("SELECT id, port_id, template_id, name, severity, matched_at, discovered_at FROM vulnerabilities WHERE port_id = ?", portID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []Vulnerability
	for rows.Next() {
		var vuln Vulnerability
		if err := rows.Scan(&vuln.ID, &vuln.PortID, &vuln.TemplateID, &vuln.Name, &vuln.Severity, &vuln.MatchedAt, &vuln.DiscoveredAt); err != nil {
			return nil, err
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

func (s *SQLiteStorage) UpdateScanStatus(target, tool, status string) error {
	var finishedAt interface{}
	if status == "completed" || status == "failed" {
		finishedAt = time.Now()
	} else {
		finishedAt = nil
	}

	_, err := s.db.Exec(`
		INSERT INTO scans (target, tool, status, started_at, finished_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(target, tool) DO UPDATE SET
		status = excluded.status,
		finished_at = excluded.finished_at
	`, target, tool, status, time.Now(), finishedAt)
	return err
}

func (s *SQLiteStorage) GetScans(target string) ([]Scan, error) {
	rows, err := s.db.Query("SELECT id, target, tool, status, started_at, finished_at FROM scans WHERE target = ?", target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []Scan
	for rows.Next() {
		var scan Scan
		var finishedAt sql.NullTime
		if err := rows.Scan(&scan.ID, &scan.Target, &scan.Tool, &scan.Status, &scan.StartedAt, &finishedAt); err != nil {
			return nil, err
		}
		if finishedAt.Valid {
			scan.FinishedAt = &finishedAt.Time
		}
		scans = append(scans, scan)
	}
	return scans, nil
}

