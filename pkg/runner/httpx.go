package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"syscall"
)

type HttpxResult struct {
	URL        string   `json:"url"`
	Host       string   `json:"host"`
	Port       string   `json:"port"`
	Title      string   `json:"title"`
	StatusCode int      `json:"status_code"`
	Tech       []string `json:"tech"`
}

type Httpx struct{}

func NewHttpx() *Httpx {
	return &Httpx{}
}

func (h *Httpx) Name() string {
	return "httpx"
}

func (h *Httpx) Run(ctx context.Context, targets []string) ([]HttpxResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// Output as JSON to easily extract Title and Tech stacks
	cmd := exec.CommandContext(ctx, "httpx", "-silent", "-json", "-tech-detect", "-title", "-status-code")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n"))
	
	var out bytes.Buffer
	cmd.Stdout = &out

	_ = cmd.Run() // ignore exit status

	var results []HttpxResult
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		
		var res HttpxResult
		if err := json.Unmarshal([]byte(trimmed), &res); err == nil {
			results = append(results, res)
		}
	}

	return results, nil
}
