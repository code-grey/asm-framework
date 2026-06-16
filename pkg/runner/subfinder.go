package runner

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"syscall"
)

type Subfinder struct{}

func NewSubfinder() *Subfinder {
	return &Subfinder{}
}

func (s *Subfinder) Name() string {
	return "subfinder"
}

func (s *Subfinder) Run(ctx context.Context, target string, deep bool) ([]string, error) {
	args := []string{"-d", target, "-silent"}
	if deep {
		args = append(args, "-all") // Use all sources in deep mode
	}
	cmd := exec.CommandContext(ctx, "subfinder", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = nil
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	var subdomains []string
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			subdomains = append(subdomains, trimmed)
		}
	}

	return subdomains, nil
}
