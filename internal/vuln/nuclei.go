package vuln

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/planner"
)

const maxNucleiStderrBytes = 32 * 1024

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

var (
	detectNucleiBinary     = DetectNucleiBinary
	resolveNucleiTemplates = ResolveNucleiTemplatesPath
	newNucleiCommand       = exec.CommandContext
)

func RunNucleiForOpenPorts(ctx context.Context, ip string, openPorts []model.ScanResult, templatesPath string) ([]model.NucleiFinding, error) {
	return RunNucleiForOpenPortsWithTags(ctx, ip, openPorts, templatesPath, nil)
}

// RunNucleiForOpenPortsWithTags restricts Nuclei to a set of template tags
// when tags are supplied. An empty tag set keeps the legacy full-template mode.
func RunNucleiForOpenPortsWithTags(ctx context.Context, ip string, openPorts []model.ScanResult, templatesPath string, tags []string) ([]model.NucleiFinding, error) {
	return runNucleiForOpenPorts(ctx, ip, openPorts, templatesPath, tags, nil)
}

// RunNucleiForOpenPortsWithTemplatePaths runs only reviewed relative template
// paths under the configured root.
func RunNucleiForOpenPortsWithTemplatePaths(ctx context.Context, ip string, openPorts []model.ScanResult, templatesPath string, paths []string) ([]model.NucleiFinding, error) {
	return runNucleiForOpenPorts(ctx, ip, openPorts, templatesPath, nil, paths)
}

func runNucleiForOpenPorts(ctx context.Context, ip string, openPorts []model.ScanResult, templatesPath string, tags, paths []string) ([]model.NucleiFinding, error) {
	nucleiPath, err := detectNucleiBinary()
	if err != nil {
		return nil, err
	}

	resolvedTemplates, err := resolveNucleiTemplates(templatesPath)
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

	args := buildNucleiArgs(tmp.Name(), resolvedTemplates, tags)
	if len(paths) > 0 {
		args = []string{"-jsonl", "-silent", "-l", tmp.Name(), "-exclude-tags", strings.Join(planner.DefaultExcludedTemplateTags(), ",")}
		for _, path := range paths {
			args = append(args, "-t", filepath.Join(resolvedTemplates, path))
		}
	}

	cmd := newNucleiCommand(ctx, nucleiPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	stdoutDone := make(chan nucleiStdoutResult, 1)
	go func() {
		findings, err := parseNucleiJSONL(stdout, ip)
		stdoutDone <- nucleiStdoutResult{findings: findings, err: err}
	}()

	stderrOutput := &boundedOutput{limit: maxNucleiStderrBytes}
	stderrDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(stderrOutput, stderr)
		stderrDone <- err
	}()

	stdoutResult := <-stdoutDone
	stderrErr := <-stderrDone
	waitErr := cmd.Wait()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if stdoutResult.err != nil {
		return nil, stdoutResult.err
	}
	if stderrErr != nil {
		return nil, stderrErr
	}
	if waitErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		msg := strings.TrimSpace(stderrOutput.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		return nil, fmt.Errorf("nuclei execution failed: %s", msg)
	}

	return stdoutResult.findings, nil
}

type nucleiStdoutResult struct {
	findings []model.NucleiFinding
	err      error
}

func parseNucleiJSONL(reader io.Reader, ip string) ([]model.NucleiFinding, error) {
	findings := make([]model.NucleiFinding, 0)
	scanner := bufio.NewScanner(reader)
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
	return findings, nil
}

type boundedOutput struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (output *boundedOutput) Write(data []byte) (int, error) {
	remaining := output.limit - output.buffer.Len()
	if remaining <= 0 {
		output.truncated = true
		return len(data), nil
	}
	if len(data) > remaining {
		_, _ = output.buffer.Write(data[:remaining])
		output.truncated = true
		return len(data), nil
	}
	_, _ = output.buffer.Write(data)
	return len(data), nil
}

func (output *boundedOutput) String() string {
	if !output.truncated {
		return output.buffer.String()
	}
	return output.buffer.String() + "\n[stderr truncated]"
}

func buildNucleiArgs(targetFile, templatesPath string, tags []string) []string {
	args := []string{"-jsonl", "-silent", "-l", targetFile, "-exclude-tags", strings.Join(planner.DefaultExcludedTemplateTags(), ",")}
	if templatesPath != "" {
		args = append(args, "-t", templatesPath)
	}
	if normalizedTags := normalizeTagList(tags); len(normalizedTags) > 0 {
		args = append(args, "-tags", strings.Join(normalizedTags, ","))
	}
	return args
}

func normalizeTagList(tags []string) []string {
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(strings.ToLower(tag))
		if tag == "" {
			continue
		}
		seen[tag] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for tag := range seen {
		result = append(result, tag)
	}
	sort.Strings(result)
	return result
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

func ResolveNucleiTemplatesPath(input string) (string, error) {
	if p := strings.TrimSpace(input); p != "" {
		return validateNucleiTemplatesPath(p)
	}

	for _, p := range nucleiTemplatesFallbackPaths() {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if resolved, err := validateNucleiTemplatesPath(p); err == nil {
			return resolved, nil
		}
	}

	return "", errors.New("nuclei templates not found, please specify --templates <path>")
}

func nucleiBinaryNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"nuclei.exe", "nuclei"}
	}
	return []string{"nuclei"}
}

func nucleiTemplatesFallbackPaths() []string {
	var out []string

	if env := strings.TrimSpace(os.Getenv("NUCLEI_TEMPLATES")); env != "" {
		out = append(out, env)
	}

	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		out = append(out,
			filepath.Join(home, "nuclei-templates"),
			filepath.Join(home, ".local", "nuclei-templates"),
			filepath.Join(home, ".config", "nuclei", "templates"),
		)
	}

	if cwd, err := os.Getwd(); err == nil && strings.TrimSpace(cwd) != "" {
		out = append(out,
			filepath.Join(cwd, "nuclei-templates"),
			filepath.Join(cwd, "templates", "nuclei"),
		)
	}

	return out
}

func validateNucleiTemplatesPath(input string) (string, error) {
	resolved := strings.TrimSpace(input)
	if resolved == "" {
		return "", fmt.Errorf("empty nuclei templates path")
	}

	abs, err := filepath.Abs(resolved)
	if err == nil {
		resolved = abs
	}

	fi, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("nuclei templates path not found: %s", resolved)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("nuclei templates path is not a directory: %s", resolved)
	}

	return resolved, nil
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
