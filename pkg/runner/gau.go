package runner

import (
	"bufio"
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
	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "gau", target, "--threads", "5")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var urls []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed != "" {
			urls = append(urls, trimmed)
		}
	}

	_ = cmd.Wait()

	return urls, nil
}
