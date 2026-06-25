package runner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"asm-framework/pkg/logger"
)

type NVDResult struct {
	CVE      string
	CVSS     float64
	Severity string
}

type NVD struct {
	cache map[string]NVDResult
	mu    sync.Mutex
}

func NewNVD() *NVD {
	return &NVD{
		cache: make(map[string]NVDResult),
	}
}

func (n *NVD) Name() string {
	return "nvd"
}

// FetchCVSS retrieves CVSS score and severity for a given CVE ID.
func (n *NVD) FetchCVSS(cveID string) NVDResult {
	n.mu.Lock()
	if res, exists := n.cache[cveID]; exists {
		n.mu.Unlock()
		return res
	}
	n.mu.Unlock()

	// Rate limit protection for NVD (5 req / 30 sec without API key)
	// We will just do a simple sleep to prevent spamming
	time.Sleep(6 * time.Second)

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		logger.Errorf("[NVD] Failed to fetch %s: %v", cveID, err)
		return NVDResult{CVE: cveID, CVSS: 0.0, Severity: "UNKNOWN"}
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		logger.Errorf("[NVD] Bad status %d for %s", resp.StatusCode, cveID)
		return NVDResult{CVE: cveID, CVSS: 0.0, Severity: "UNKNOWN"}
	}

	var data struct {
		Vulnerabilities []struct {
			CVE struct {
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CvssMetricV30 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
					CvssMetricV2 []struct {
						CvssData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
						BaseSeverity string `json:"baseSeverity"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		logger.Errorf("[NVD] Failed to decode %s: %v", cveID, err)
		return NVDResult{CVE: cveID, CVSS: 0.0, Severity: "UNKNOWN"}
	}

	if len(data.Vulnerabilities) == 0 {
		return NVDResult{CVE: cveID, CVSS: 0.0, Severity: "UNKNOWN"}
	}

	metrics := data.Vulnerabilities[0].CVE.Metrics
	res := NVDResult{CVE: cveID}

	if len(metrics.CvssMetricV31) > 0 {
		res.CVSS = metrics.CvssMetricV31[0].CvssData.BaseScore
		res.Severity = strings.ToUpper(metrics.CvssMetricV31[0].CvssData.BaseSeverity)
	} else if len(metrics.CvssMetricV30) > 0 {
		res.CVSS = metrics.CvssMetricV30[0].CvssData.BaseScore
		res.Severity = strings.ToUpper(metrics.CvssMetricV30[0].CvssData.BaseSeverity)
	} else if len(metrics.CvssMetricV2) > 0 {
		res.CVSS = metrics.CvssMetricV2[0].CvssData.BaseScore
		res.Severity = strings.ToUpper(metrics.CvssMetricV2[0].BaseSeverity)
	} else {
		res.Severity = "UNKNOWN"
	}

	n.mu.Lock()
	n.cache[cveID] = res
	n.mu.Unlock()

	return res
}
