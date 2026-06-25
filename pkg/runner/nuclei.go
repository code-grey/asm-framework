package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type NucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Classification struct {
			CVEID     []string `json:"cve-id"`
			CVSSScore float64  `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
	MatchedAt string `json:"matched-at"`
}

type Nuclei struct{}

func NewNuclei() *Nuclei {
	return &Nuclei{}
}

func (n *Nuclei) Name() string {
	return "nuclei"
}

func (n *Nuclei) Run(ctx context.Context, targets []string) ([]NucleiResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "nuclei", "-silent", "-jsonl", "-severity", "critical,high,medium,low", "-disable-update-check", "-ni")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n"))
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var results []NucleiResult
	scanner := bufio.NewScanner(stdout)
	// Nuclei outputs lines that are sometimes very large, handle buffer sizing if needed
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed == "" {
			continue
		}
		var res NucleiResult
		if err := json.Unmarshal([]byte(trimmed), &res); err == nil {
			results = append(results, res)
		}
	}

	_ = cmd.Wait()

	return results, nil
}
