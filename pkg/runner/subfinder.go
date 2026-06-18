package runner

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type Subfinder struct{}

func NewSubfinder() *Subfinder {
	return &Subfinder{}
}

func (s *Subfinder) Name() string {
	return "subfinder"
}

func (s *Subfinder) Run(ctx context.Context, target string, deep bool) ([]string, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	args := []string{"-d", target, "-silent"}
	if deep {
		args = append(args, "-all") // Use all sources in deep mode
	}
	cmd := exec.CommandContext(timeoutCtx, "subfinder", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var subdomains []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed != "" {
			subdomains = append(subdomains, trimmed)
		}
	}

	_ = cmd.Wait()

	return subdomains, nil
}
