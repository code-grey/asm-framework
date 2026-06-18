package runner

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type Amass struct{}

func NewAmass() *Amass {
	return &Amass{}
}

func (a *Amass) Name() string {
	return "amass"
}

func (a *Amass) Run(ctx context.Context, target string, deep bool) ([]string, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	args := []string{"enum", "-d", target, "-nocolor"}
	if deep {
		args = append(args, "-active") // Active enumeration, pulls TLS certs, queries live infrastructure
	} else {
		args = append(args, "-passive") // Passive mode for speed
	}

	binPath := "amass"
	if _, err := exec.LookPath("/usr/lib/amass/amass"); err == nil {
		binPath = "/usr/lib/amass/amass"
	}

	cmd := exec.CommandContext(timeoutCtx, binPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("amass start failed: %w", err)
	}

	var subdomains []string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed != "" && strings.HasSuffix(trimmed, target) && !strings.Contains(trimmed, " ") {
			subdomains = append(subdomains, trimmed)
		}
	}

	_ = cmd.Wait()

	return subdomains, nil
}
