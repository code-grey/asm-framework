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

	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "httpx", "-silent", "-json", "-tech-detect", "-title", "-status-code")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n"))
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var results []HttpxResult
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed == "" {
			continue
		}
		var res HttpxResult
		if err := json.Unmarshal([]byte(trimmed), &res); err == nil {
			results = append(results, res)
		}
	}

	_ = cmd.Wait()

	return results, nil
}
