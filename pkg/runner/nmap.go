package runner

import (
	"bytes"
	"context"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

type Nmap struct{}

func NewNmap() *Nmap {
	return &Nmap{}
}

func (n *Nmap) Name() string {
	return "nmap"
}

func (n *Nmap) Run(ctx context.Context, targets []string, deep bool) ([]PortResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// Fast vs Deep configuration
	var args []string
	if deep {
		args = []string{"-T4", "-p-", "-sV", "--open", "-oG", "-"}
	} else {
		args = []string{"-T4", "-F", "--open", "-oG", "-"}
	}
	args = append(args, targets...)

	cmd := exec.CommandContext(ctx, "nmap", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdin = nil
	var out bytes.Buffer
	cmd.Stdout = &out

	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	var results []PortResult
	lines := strings.Split(out.String(), "\n")
	
	for _, line := range lines {
		if strings.HasPrefix(line, "Host:") && strings.Contains(line, "Ports:") {
			parts := strings.Split(line, "\t")
			if len(parts) < 2 {
				continue
			}

			// Extract target (either IP or hostname in parenthesis)
			hostPart := strings.TrimPrefix(parts[0], "Host: ")
			hostTokens := strings.SplitN(hostPart, " ()", 2)
			var target string
			if strings.Contains(hostPart, "(") {
				start := strings.Index(hostPart, "(")
				end := strings.Index(hostPart, ")")
				if start != -1 && end != -1 && end > start {
					target = hostPart[start+1 : end]
				}
			}
			
			if target == "" && len(hostTokens) > 0 {
				target = strings.TrimSpace(hostTokens[0])
			}

			// Nmap often prints the Reverse DNS name instead of the target we gave it.
			if len(targets) == 1 {
				target = targets[0]
			}

			// Extract ports
			portsPart := strings.TrimPrefix(parts[1], "Ports: ")
			portsList := strings.Split(portsPart, ", ")
			
			for _, portStr := range portsList {
				portTokens := strings.Split(portStr, "/")
				if len(portTokens) >= 5 && portTokens[1] == "open" {
					num, _ := strconv.Atoi(portTokens[0])
					service := portTokens[4]
					var version string
					if len(portTokens) >= 7 {
						version = portTokens[6] // In -oG output, version info is the 7th element separated by /
					}
					
					results = append(results, PortResult{
						Target:  target,
						Number:  num,
						State:   "open",
						Service: service,
						Version: version,
					})
				}
			}
		}
	}

	return results, nil
}
