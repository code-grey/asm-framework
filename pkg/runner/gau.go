package runner

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type Gau struct{}

func NewGau() *Gau {
	return &Gau{}
}

func (g *Gau) Name() string {
	return "gau"
}

func (g *Gau) Run(ctx context.Context, target string) ([]string, error) {
	// Create a sub-context with a 3-minute timeout to prevent hanging on slow archive APIs
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "gau", target, "--threads", "5")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = nil
	
	var out bytes.Buffer
	cmd.Stdout = &out

	_ = cmd.Run()

	var urls []string
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			urls = append(urls, trimmed)
		}
	}

	return urls, nil
}
