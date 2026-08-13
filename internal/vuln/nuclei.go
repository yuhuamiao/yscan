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
	"sync"
	"time"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/planner"
)

const maxNucleiStderrBytes = 32 * 1024

var (
	ErrNoTemplates              = errors.New("no usable nuclei templates")
	ErrNucleiMissing            = errors.New("nuclei executable missing")
	ErrTemplateDirectoryMissing = errors.New("nuclei template directory missing")
	ErrTemplateMissing          = errors.New("nuclei template missing")
)

var configuredNucleiBinary struct {
	sync.RWMutex
	path string
}

func ConfigureNucleiBinary(path string) {
	configuredNucleiBinary.Lock()
	configuredNucleiBinary.path = strings.TrimSpace(path)
	configuredNucleiBinary.Unlock()
}

// NucleiExecutionResult separates process startup and actual template
// execution from findings and errors. Callers must not infer coverage from an
// empty finding list or a final process error.
type NucleiExecutionResult struct {
	Findings []model.NucleiFinding
	Started  bool
	Executed bool
	Err      error
}

type nucleiJSONLine struct {
	TemplateID string `json:"template-id"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	Port       string `json:"port"`
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
	result := ExecuteNucleiForOpenPortsWithTags(ctx, ip, openPorts, templatesPath, tags)
	return result.Findings, result.Err
}

func ExecuteNucleiForOpenPortsWithTags(ctx context.Context, ip string, openPorts []model.ScanResult, templatesPath string, tags []string) NucleiExecutionResult {
	resolvedTemplates, err := resolveNucleiTemplates(templatesPath)
	if err != nil {
		return NucleiExecutionResult{Err: err}
	}
	return executeNucleiForOpenPortsWithTemplatePaths(ctx, ip, openPorts, []string{resolvedTemplates}, tags)
}

// RunNucleiForOpenPortsWithTemplatePaths executes only the supplied reviewed
// local template files. Callers are responsible for content pinning.
func RunNucleiForOpenPortsWithTemplatePaths(ctx context.Context, ip string, openPorts []model.ScanResult, templatePaths []string) ([]model.NucleiFinding, error) {
	result := ExecuteNucleiForOpenPortsWithTemplatePaths(ctx, ip, openPorts, templatePaths)
	return result.Findings, result.Err
}

func ExecuteNucleiForOpenPortsWithTemplatePaths(ctx context.Context, ip string, openPorts []model.ScanResult, templatePaths []string) NucleiExecutionResult {
	paths := make([]string, 0, len(templatePaths))
	for _, path := range templatePaths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return NucleiExecutionResult{Err: err}
		}
		info, err := os.Stat(absolute)
		if err != nil || info.IsDir() {
			return NucleiExecutionResult{Err: fmt.Errorf("%w: reviewed template is not a file: %s", ErrTemplateMissing, path)}
		}
		paths = append(paths, absolute)
	}
	return executeNucleiForOpenPortsWithTemplatePaths(ctx, ip, openPorts, paths, nil)
}

func runNucleiForOpenPortsWithTemplatePaths(ctx context.Context, ip string, openPorts []model.ScanResult, templatePaths []string, tags []string) ([]model.NucleiFinding, error) {
	result := executeNucleiForOpenPortsWithTemplatePaths(ctx, ip, openPorts, templatePaths, tags)
	return result.Findings, result.Err
}

func executeNucleiForOpenPortsWithTemplatePaths(ctx context.Context, ip string, openPorts []model.ScanResult, templatePaths []string, tags []string) NucleiExecutionResult {
	nucleiPath, err := detectNucleiBinary()
	if err != nil {
		return NucleiExecutionResult{Err: err}
	}

	targets := buildTargets(ip, openPorts)
	if len(targets) == 0 {
		return NucleiExecutionResult{}
	}

	tmp, err := os.CreateTemp("", "yscan-nuclei-targets-*.txt")
	if err != nil {
		return NucleiExecutionResult{Err: err}
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	for _, t := range targets {
		if _, err := tmp.WriteString(t + "\n"); err != nil {
			return NucleiExecutionResult{Err: err}
		}
	}

	if err := tmp.Sync(); err != nil {
		return NucleiExecutionResult{Err: err}
	}

	args := buildNucleiArgs(tmp.Name(), templatePaths, tags)

	cmd := newNucleiCommand(ctx, nucleiPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return NucleiExecutionResult{Err: err}
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return NucleiExecutionResult{Err: err}
	}

	if err := cmd.Start(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return NucleiExecutionResult{Err: ctxErr}
		}
		return NucleiExecutionResult{Err: err}
	}
	result := NucleiExecutionResult{Started: true}

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
	result.Findings = stdoutResult.findings
	if ctxErr := ctx.Err(); ctxErr != nil {
		result.Executed = true
		result.Err = ctxErr
		return result
	}
	if stdoutResult.err != nil {
		result.Executed = true
		result.Err = stdoutResult.err
		return result
	}
	if stderrErr != nil {
		result.Executed = true
		result.Err = stderrErr
		return result
	}
	if waitErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			result.Executed = true
			result.Err = ctxErr
			return result
		}
		msg := strings.TrimSpace(stderrOutput.String())
		if strings.Contains(strings.ToLower(msg), "no templates provided for scan") {
			result.Err = ErrNoTemplates
			return result
		}
		if msg == "" {
			msg = waitErr.Error()
		}
		result.Executed = true
		result.Err = fmt.Errorf("nuclei execution failed: %s", msg)
		return result
	}

	result.Executed = true
	return result
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

		targetIP, targetPort := parseTarget(row.Host, row.MatchedAt, row.Port)
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
		return findings, err
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

func buildNucleiArgs(targetFile string, templatePaths []string, tags []string) []string {
	args := []string{
		"-jsonl", "-silent", "-ni", "-dr", "-rate-limit", "25", "-concurrency", "5",
		"-l", targetFile, "-exclude-tags", strings.Join(planner.DefaultExcludedTemplateTags(), ","),
	}
	for _, templatePath := range templatePaths {
		if strings.TrimSpace(templatePath) != "" {
			args = append(args, "-t", templatePath)
		}
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
	configuredNucleiBinary.RLock()
	configured := configuredNucleiBinary.path
	configuredNucleiBinary.RUnlock()
	if configured != "" && configured != "nuclei" {
		if strings.ContainsRune(configured, filepath.Separator) || filepath.IsAbs(configured) {
			info, err := os.Stat(configured)
			if err != nil || info.IsDir() || info.Mode()&0111 == 0 {
				return "", fmt.Errorf("%w: configured path is not executable: %s", ErrNucleiMissing, configured)
			}
			absolute, err := filepath.Abs(configured)
			if err != nil {
				return "", err
			}
			return absolute, nil
		}
		if path, err := exec.LookPath(configured); err == nil {
			return path, nil
		}
		return "", fmt.Errorf("%w: configured executable %q was not found", ErrNucleiMissing, configured)
	}
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

	return "", fmt.Errorf("%w: not found in PATH or GOPATH/bin", ErrNucleiMissing)
}

func ResolveNucleiTemplatesPath(input string) (string, error) {
	if p := strings.TrimSpace(input); p != "" {
		return validateNucleiTemplatesPath(p)
	}
	return "", fmt.Errorf("%w: configure YSCAN_NUCLEI_TEMPLATES or --templates <path>", ErrTemplateDirectoryMissing)
}

func nucleiBinaryNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"nuclei.exe", "nuclei"}
	}
	return []string{"nuclei"}
}

func validateNucleiTemplatesPath(input string) (string, error) {
	resolved := strings.TrimSpace(input)
	if resolved == "" {
		return "", fmt.Errorf("%w: empty path", ErrTemplateDirectoryMissing)
	}

	abs, err := filepath.Abs(resolved)
	if err == nil {
		resolved = abs
	}

	fi, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("%w: path not found: %s", ErrTemplateDirectoryMissing, resolved)
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%w: path is not a directory: %s", ErrTemplateDirectoryMissing, resolved)
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
		switch strings.ToLower(strings.TrimSpace(r.Service)) {
		case "http", "http-unknown":
			t = "http://" + t
		case "https":
			t = "https://" + t
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		targets = append(targets, t)
	}
	return targets
}

func parseTarget(hostField, matchedAt, portField string) (string, int) {
	// matched-at is the concrete endpoint in current Nuclei JSONL. The host
	// field may contain only an IP while port is emitted as a separate field.
	if ip, port, ok := parseHostPort(matchedAt); ok && port > 0 {
		return ip, port
	}
	if ip, port, ok := parseHostPort(hostField); ok && port > 0 {
		return ip, port
	}
	if ip := net.ParseIP(strings.TrimSpace(hostField)); ip != nil {
		port, _ := strconv.Atoi(strings.TrimSpace(portField))
		return ip.String(), port
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
