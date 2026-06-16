package runner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

type Amass struct{}

func NewAmass() *Amass {
	return &Amass{}
}

func (a *Amass) Name() string {
	return "amass"
}

func (a *Amass) Run(ctx context.Context, target string, deep bool) ([]string, error) {
	args := []string{"enum", "-d", target, "-nocolor"}
	if deep {
		args = append(args, "-active") // Active enumeration, pulls TLS certs, queries live infrastructure
	} else {
		args = append(args, "-passive") // Passive mode for speed
	}

	// Bypassing the broken /usr/bin/amass wrapper on Debian/Kali and calling the binary directly
	cmd := exec.CommandContext(ctx, "/usr/lib/amass/amass", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = nil
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("amass failed: %w, stderr: %s", err, strings.TrimSpace(stderr.String()))
	}

	var subdomains []string
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Amass output can be messy, rudimentary filter for subdomains
		if trimmed != "" && strings.HasSuffix(trimmed, target) && !strings.Contains(trimmed, " ") {
			subdomains = append(subdomains, trimmed)
		}
	}

	return subdomains, nil
}
