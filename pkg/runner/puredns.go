package runner

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type Puredns struct{}

func NewPuredns() *Puredns {
	return &Puredns{}
}

func (p *Puredns) Name() string {
	return "puredns"
}

func (p *Puredns) Run(ctx context.Context, targets []string) ([]string, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "puredns", "resolve", "-q")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n"))
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var live []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed != "" {
			live = append(live, trimmed)
		}
	}

	_ = cmd.Wait()

	return live, nil
}
