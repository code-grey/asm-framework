package runner

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"syscall"
)

// Puredns filters a list of subdomains and returns only those that resolve to live IPs.
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

	// We pass the targets via Stdin
	cmd := exec.CommandContext(ctx, "puredns", "resolve", "-q")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	
	cmd.Stdin = strings.NewReader(strings.Join(targets, "\n"))
	
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		// puredns might exit 1 if some domains fail to resolve, which is fine.
		// We only care about the stdout
	}

	var live []string
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			live = append(live, trimmed)
		}
	}

	return live, nil
}
