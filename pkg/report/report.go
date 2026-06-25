package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"asm-framework/pkg/logger"
	"asm-framework/pkg/storage"
)

// FullReport represents the complete structured export of the ASM database
type FullReport struct {
	GeneratedAt   time.Time       `json:"generated_at"`
	RiskSummary   RiskSummary     `json:"risk_summary"`
	Assets        []AssetReport   `json:"assets"`
}

type RiskSummary struct {
	TotalAssets         int `json:"total_assets"`
	TotalLiveAssets     int `json:"total_live_assets"`
	TotalOpenPorts      int `json:"total_open_ports"`
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	CriticalVulns       int `json:"critical_vulns"`
	HighVulns           int `json:"high_vulns"`
	MediumVulns         int `json:"medium_vulns"`
	LowVulns            int `json:"low_vulns"`
}

type AssetReport struct {
	Domain       string                `json:"domain"`
	IsAlive      bool                  `json:"is_alive"`
	Ports        []PortReport          `json:"ports,omitempty"`
	Endpoints    []storage.Endpoint    `json:"endpoints,omitempty"`
}

type PortReport struct {
	Number          int                     `json:"number"`
	Service         string                  `json:"service"`
	Version         string                  `json:"version,omitempty"`
	State           string                  `json:"state"`
	WebService      *storage.WebService     `json:"web_service,omitempty"`
	Vulnerabilities []storage.Vulnerability `json:"vulnerabilities,omitempty"`
}

// Generate generates both JSON and HTML reports from the storage layer.
func Generate(store storage.Storage, baseFilename string, targetDomain string) error {
	logger.Infof("[*] Generating comprehensive scan reports...")

	allSubs, err := store.GetSubdomains()
	if err != nil {
		return fmt.Errorf("failed to get subdomains: %w", err)
	}

	var subs []storage.Subdomain
	for _, sub := range allSubs {
		// Only include the exact target domain or its subdomains.
		// If targetDomain is empty, include all.
		if sub.Domain == targetDomain || strings.HasSuffix(sub.Domain, "."+targetDomain) || targetDomain == "" {
			subs = append(subs, sub)
		}
	}

	report := FullReport{
		GeneratedAt: time.Now(),
		Assets:      make([]AssetReport, 0, len(subs)),
	}

	for _, sub := range subs {
		asset := AssetReport{
			Domain:  sub.Domain,
			IsAlive: sub.IsAlive,
		}

		report.RiskSummary.TotalAssets++
		if sub.IsAlive {
			report.RiskSummary.TotalLiveAssets++
		}

		// Endpoints
		eps, _ := store.GetEndpoints(sub.ID)
		asset.Endpoints = eps

		// Ports
		ports, _ := store.GetPorts(sub.ID)
		for _, p := range ports {
			report.RiskSummary.TotalOpenPorts++

			portRep := PortReport{
				Number:  p.Number,
				Service: p.Service,
				Version: p.Version,
				State:   p.State,
			}

			// Web Service
			wss, _ := store.GetWebServices(p.ID)
			if len(wss) > 0 {
				portRep.WebService = &wss[0]
			}

			// Vulnerabilities
			vulns, _ := store.GetVulnerabilities(p.ID)
			portRep.Vulnerabilities = vulns
			
			for _, v := range vulns {
				report.RiskSummary.TotalVulnerabilities++
				switch strings.ToUpper(v.Severity) {
				case "CRITICAL":
					report.RiskSummary.CriticalVulns++
				case "HIGH":
					report.RiskSummary.HighVulns++
				case "MEDIUM":
					report.RiskSummary.MediumVulns++
				case "LOW", "INFO":
					report.RiskSummary.LowVulns++
				}
			}

			asset.Ports = append(asset.Ports, portRep)
		}

		report.Assets = append(report.Assets, asset)
	}

	// 1. Generate JSON
	jsonPath := baseFilename + ".json"
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON report: %w", err)
	}
	if err := os.WriteFile(jsonPath, b, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}
	logger.Infof("    [+] Saved structured JSON report to %s", jsonPath)

	// 2. Generate HTML
	htmlPath := baseFilename + ".html"
	if err := generateHTML(report, htmlPath, targetDomain); err != nil {
		return fmt.Errorf("failed to write HTML report: %w", err)
	}
	logger.Infof("    [+] Saved clean HTML report to %s", htmlPath)

	return nil
}

type topVuln struct {
	Name     string
	Severity string
	CVSS     float64
	URL      string
}

func generateHTML(r FullReport, filepath string, targetDomain string) error {
	var sb strings.Builder

	// Collect top vulnerabilities
	var allVulns []topVuln
	for _, a := range r.Assets {
		for _, p := range a.Ports {
			for _, v := range p.Vulnerabilities {
				url := a.Domain + ":" + fmt.Sprint(p.Number)
				if p.WebService != nil {
					url = p.WebService.URL
				}
				allVulns = append(allVulns, topVuln{
					Name:     v.Name,
					Severity: v.Severity,
					CVSS:     v.CVSS,
					URL:      url,
				})
			}
		}
	}
	
	sort.Slice(allVulns, func(i, j int) bool {
		return allVulns[i].CVSS > allVulns[j].CVSS
	})

	// Header & CSS
	sb.WriteString(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>ASM Report - ` + targetDomain + `</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
	body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f7f6; color: #333; line-height: 1.6; margin: 0; padding: 20px; }
	h1, h2, h3 { color: #2c3e50; }
	.container { max-width: 1200px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
	.summary { display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }
	.summary-box { flex: 1; min-width: 150px; background: #ecf0f1; padding: 20px; border-radius: 8px; text-align: center; }
	.summary-box h3 { margin: 0; font-size: 2rem; color: #2980b9; }
	.summary-box span { font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; color: #7f8c8d; }
	.critical { color: #c0392b !important; }
	.high { color: #e67e22 !important; }
	.asset { border: 1px solid #ddd; border-radius: 8px; margin-bottom: 20px; padding: 20px; background: #fafafa; }
	.asset h2 { margin-top: 0; display: flex; align-items: center; gap: 10px; }
	.status { font-size: 0.8rem; padding: 3px 8px; border-radius: 12px; color: #fff; }
	.alive { background: #27ae60; }
	.dead { background: #95a5a6; }
	table { width: 100%; border-collapse: collapse; margin-top: 15px; background: #fff; }
	th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
	th { background-color: #f8f9fa; color: #34495e; font-weight: 600; }
	.vuln-badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: #fff; margin-right: 5px; }
	.badge-CRITICAL { background: #c0392b; }
	.badge-HIGH { background: #e67e22; }
	.badge-MEDIUM { background: #f1c40f; color: #333; }
	.badge-LOW { background: #3498db; }
	.badge-UNKNOWN { background: #95a5a6; }
	.collapsible { cursor: pointer; user-select: none; padding: 10px; margin: -10px -10px 10px -10px; border-radius: 6px; transition: background-color 0.2s; }
	.collapsible:hover { background-color: #eee; }
	.collapsible:after { content: '\002B'; color: #777; font-weight: bold; float: right; margin-left: 5px; }
	.collapsible.active:after { content: "\2212"; }
	.dashboard { display: flex; gap: 30px; margin-bottom: 30px; }
	.chart-container { flex: 1; min-width: 300px; max-width: 400px; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
	.top-vulns { flex: 2; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
</style>
</head>
<body>
<div class="container">
	<h1>Attack Surface Report: ` + targetDomain + `</h1>
	<p>Generated at: ` + r.GeneratedAt.Format(time.RFC1123) + `</p>

	<div class="summary">
		<div class="summary-box"><h3>` + fmt.Sprint(r.RiskSummary.TotalLiveAssets) + `</h3><span>Live Assets</span></div>
		<div class="summary-box"><h3>` + fmt.Sprint(r.RiskSummary.TotalOpenPorts) + `</h3><span>Open Ports</span></div>
		<div class="summary-box"><h3 class="critical">` + fmt.Sprint(r.RiskSummary.CriticalVulns) + `</h3><span>Critical Vulns</span></div>
		<div class="summary-box"><h3 class="high">` + fmt.Sprint(r.RiskSummary.HighVulns) + `</h3><span>High Vulns</span></div>
		<div class="summary-box"><h3>` + fmt.Sprint(r.RiskSummary.TotalVulnerabilities) + `</h3><span>Total Vulns</span></div>
	</div>

	<div class="dashboard">
		<div class="chart-container">
			<h2 style="text-align: center; margin-top:0;">Vulnerability Severity</h2>
			<canvas id="vulnChart"></canvas>
		</div>
		<div class="top-vulns">
			<h2 style="margin-top:0;">Top Vulnerabilities</h2>
			<table>
				<tr><th>Severity</th><th>Name</th><th>Asset</th></tr>`)

	for i, v := range allVulns {
		if i >= 5 {
			break
		}
		badgeClass := "badge-" + strings.ToUpper(v.Severity)
		sb.WriteString(fmt.Sprintf(`<tr><td><span class="vuln-badge %s">%s (%.1f)</span></td><td>%s</td><td>%s</td></tr>`, badgeClass, v.Severity, v.CVSS, v.Name, v.URL))
	}
	if len(allVulns) == 0 {
		sb.WriteString(`<tr><td colspan="3">No vulnerabilities found.</td></tr>`)
	}
	sb.WriteString(`</table>
		</div>
	</div>

	<h2>Discovered Assets</h2>
`)

	// Sort assets to put live ones first
	sort.Slice(r.Assets, func(i, j int) bool {
		return r.Assets[i].IsAlive && !r.Assets[j].IsAlive
	})

	for _, a := range r.Assets {
		statusClass, statusText := "dead", "Offline"
		if a.IsAlive {
			statusClass, statusText = "alive", "Live"
		}

		sb.WriteString(fmt.Sprintf(`
	<div class="asset">
		<h2 class="collapsible">%s <span class="status %s">%s</span></h2>
		<div class="content">`, a.Domain, statusClass, statusText))

		if len(a.Ports) > 0 {
			sb.WriteString(`
		<table>
			<tr>
				<th>Port</th>
				<th>Service/Version</th>
				<th>Web Context (Tech Detected)</th>
				<th>Vulnerabilities</th>
			</tr>`)

			for _, p := range a.Ports {
				svc := p.Service
				if p.Version != "" {
					svc += " (" + p.Version + ")"
				}

				webCtx := "-"
				if p.WebService != nil {
					webCtx = fmt.Sprintf("<strong>%s</strong> [%d]<br><i>%s</i>", p.WebService.URL, p.WebService.StatusCode, p.WebService.TechStack)
				}

				vulnHtml := "-"
				if len(p.Vulnerabilities) > 0 {
					var vLines []string
					for _, v := range p.Vulnerabilities {
						badgeClass := "badge-" + strings.ToUpper(v.Severity)
						cvssText := ""
						if v.CVSS > 0 {
							cvssText = fmt.Sprintf(" (CVSS: %.1f)", v.CVSS)
						}
						vLines = append(vLines, fmt.Sprintf(`<span class="vuln-badge %s">%s</span> %s%s`, badgeClass, v.Severity, v.Name, cvssText))
					}
					vulnHtml = strings.Join(vLines, "<br>")
				}

				sb.WriteString(fmt.Sprintf(`
			<tr>
				<td><strong>%d</strong></td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
			</tr>`, p.Number, svc, webCtx, vulnHtml))
			}
			sb.WriteString(`</table>`)
		} else if a.IsAlive {
			sb.WriteString(`<p>No open ports discovered.</p>`)
		}

		sb.WriteString(`</div>
	</div>`)
	}

	sb.WriteString(`
</div>
<script>
var coll = document.getElementsByClassName("collapsible");
for (var i = 0; i < coll.length; i++) {
  coll[i].addEventListener("click", function() {
    this.classList.toggle("active");
    var content = this.nextElementSibling;
    if (content.style.display === "block") {
      content.style.display = "none";
    } else {
      content.style.display = "block";
    }
  });
}

// Chart.js Donut Chart
var ctx = document.getElementById('vulnChart').getContext('2d');
var vulnChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ['Critical', 'High', 'Medium', 'Low/Info'],
        datasets: [{
            data: [` + fmt.Sprint(r.RiskSummary.CriticalVulns) + `, ` + fmt.Sprint(r.RiskSummary.HighVulns) + `, ` + fmt.Sprint(r.RiskSummary.MediumVulns) + `, ` + fmt.Sprint(r.RiskSummary.LowVulns) + `],
            backgroundColor: ['#c0392b', '#e67e22', '#f1c40f', '#3498db'],
            borderWidth: 0
        }]
    },
    options: {
        responsive: true,
        cutout: '70%',
        plugins: {
            legend: { position: 'bottom' }
        }
    }
});
</script>
</body>
</html>`)

	return os.WriteFile(filepath, []byte(sb.String()), 0644)
}
