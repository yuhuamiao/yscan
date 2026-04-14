package vuln

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golandproject/yscan/internal/model"
)

type nucleiJSONLine struct {
	TemplateID string `json:"template-id"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Timestamp  string `json:"timestamp"`
	Info       struct {
		Name        string      `json:"name"`
		Severity    string      `json:"severity"`
		Description string      `json:"description"`
		Tags        interface{} `json:"tags"`
	} `json:"info"`
}

func RunNucleiForOpenPorts(ctx context.Context, ip string, openPorts []model.ScanResult) ([]model.NucleiFinding, error) {
	nucleiPath, err := DetectNucleiBinary()
	if err != nil {
		return nil, err
	}

	targets := buildTargets(ip, openPorts)
	if len(targets) == 0 {
		return nil, nil
	}

	tmp, err := os.CreateTemp("", "yscan-nuclei-targets-*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	for _, t := range targets {
		if _, err := tmp.WriteString(t + "\n"); err != nil {
			return nil, err
		}
	}

	if err := tmp.Sync(); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, nucleiPath, "-jsonl", "-silent", "-l", tmp.Name())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var findings []model.NucleiFinding
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var row nucleiJSONLine
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}

		targetIP, targetPort := parseTarget(row.Host, row.MatchedAt)
		if targetIP == "" {
			targetIP = ip
		}

		tags := normalizeTags(row.Info.Tags)
		scanTime := row.Timestamp
		if scanTime == "" {
			scanTime = time.Now().UTC().Format(time.RFC3339)
		}

		findings = append(findings, model.NucleiFinding{
			TemplateID:  row.TemplateID,
			VulnType:    row.Type,
			Name:        row.Info.Name,
			Severity:    row.Info.Severity,
			Description: row.Info.Description,
			Host:        row.Host,
			MatchedAt:   row.MatchedAt,
			Target:      firstNonEmpty(row.MatchedAt, row.Host),
			TargetIP:    targetIP,
			TargetPort:  targetPort,
			ScanTime:    scanTime,
			Evidence:    line,
			Tags:        tags,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	stderrBytes, _ := io.ReadAll(io.LimitReader(stderr, 32768))
	if err := cmd.Wait(); err != nil {
		msg := strings.TrimSpace(string(stderrBytes))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("nuclei execution failed: %s", msg)
	}

	return findings, nil
}

func DetectNucleiBinary() (string, error) {
	for _, name := range nucleiBinaryNames() {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}

	for _, p := range nucleiFallbackPaths() {
		if p == "" {
			continue
		}
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}

	return "", fmt.Errorf("nuclei not found in PATH or GOPATH/bin")
}

func nucleiBinaryNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"nuclei.exe", "nuclei"}
	}
	return []string{"nuclei"}
}

func nucleiFallbackPaths() []string {
	var out []string

	gobin := strings.TrimSpace(os.Getenv("GOBIN"))
	if gobin != "" {
		for _, name := range nucleiBinaryNames() {
			out = append(out, filepath.Join(gobin, name))
		}
	}

	gopath := strings.TrimSpace(os.Getenv("GOPATH"))
	if gopath != "" {
		for _, name := range nucleiBinaryNames() {
			out = append(out, filepath.Join(gopath, "bin", name))
		}
	}

	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		for _, name := range nucleiBinaryNames() {
			out = append(out, filepath.Join(home, "go", "bin", name))
		}
	}

	return out
}

func buildTargets(ip string, openPorts []model.ScanResult) []string {
	seen := make(map[string]struct{})
	var targets []string

	for _, r := range openPorts {
		if !r.Open {
			continue
		}
		_, portStr, err := net.SplitHostPort(r.Address)
		if err != nil {
			continue
		}
		t := net.JoinHostPort(ip, portStr)
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		targets = append(targets, t)
	}
	return targets
}

func parseTarget(hostField, matchedAt string) (string, int) {
	if ip, port, ok := parseHostPort(hostField); ok {
		return ip, port
	}
	if ip, port, ok := parseHostPort(matchedAt); ok {
		return ip, port
	}
	return "", 0
}

func parseHostPort(raw string) (string, int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, false
	}

	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "", 0, false
		}
		host := u.Hostname()
		port := 0
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		} else if strings.EqualFold(u.Scheme, "https") {
			port = 443
		} else if strings.EqualFold(u.Scheme, "http") {
			port = 80
		}
		if net.ParseIP(host) == nil {
			return "", 0, false
		}
		return host, port, true
	}

	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		if net.ParseIP(raw) != nil {
			return raw, 0, true
		}
		return "", 0, false
	}
	port, _ := strconv.Atoi(portStr)
	if net.ParseIP(host) == nil {
		return "", 0, false
	}
	return host, port, true
}

func normalizeTags(v interface{}) string {
	switch t := v.(type) {
	case []interface{}:
		var out []string
		for _, x := range t {
			out = append(out, fmt.Sprint(x))
		}
		return strings.Join(out, ",")
	case string:
		return t
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
