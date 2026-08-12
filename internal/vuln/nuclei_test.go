package vuln

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golandproject/yscan/internal/model"
)

func TestBuildNucleiArgsIncludesNormalizedTags(t *testing.T) {
	args := buildNucleiArgs("targets.txt", []string{"templates"}, []string{"http", " Redis ", "http"})
	want := []string{"-jsonl", "-silent", "-ni", "-dr", "-rate-limit", "25", "-concurrency", "5", "-l", "targets.txt", "-exclude-tags", "intrusive,dos,auth", "-t", "templates", "-tags", "http,redis"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %v, want %v", args, want)
	}
}

func TestBuildNucleiArgsAlwaysIncludesSafetyExclusions(t *testing.T) {
	args := buildNucleiArgs("targets.txt", []string{"templates"}, nil)
	excludedTags := ""
	for _, arg := range args {
		if arg == "-tags" {
			t.Fatal("empty tags must not add -tags")
		}
	}
	for index, arg := range args {
		if arg == "-exclude-tags" && index+1 < len(args) {
			excludedTags = args[index+1]
			break
		}
	}
	if excludedTags != "intrusive,dos,auth" {
		t.Fatalf("excluded tags = %q, want intrusive,dos,auth", excludedTags)
	}
	joined := " " + strings.Join(args, " ") + " "
	for _, expected := range []string{" -ni ", " -dr ", " -rate-limit 25 ", " -concurrency 5 "} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing process safety flag %q in %v", expected, args)
		}
	}
}

func TestDetectNucleiBinaryUsesConfiguredExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reviewed-nuclei")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ConfigureNucleiBinary(path)
	t.Cleanup(func() { ConfigureNucleiBinary("") })
	resolved, err := DetectNucleiBinary()
	if err != nil || resolved != path {
		t.Fatalf("configured nuclei = %q, %v", resolved, err)
	}
}

func TestParseTargetUsesMatchedEndpointOrSeparateNucleiPort(t *testing.T) {
	if ip, port := parseTarget("127.0.0.1", "http://127.0.0.1:38163/", "38163"); ip != "127.0.0.1" || port != 38163 {
		t.Fatalf("matched endpoint = %s:%d", ip, port)
	}
	if ip, port := parseTarget("127.0.0.1", "", "42441"); ip != "127.0.0.1" || port != 42441 {
		t.Fatalf("separate endpoint = %s:%d", ip, port)
	}
}

func TestParseNucleiJSONLKeepsParsedDescriptionSeparateFromRawEvidence(t *testing.T) {
	raw := `{"template-id":"fixture","host":"https://192.0.2.10","matched-at":"https://192.0.2.10/admin","info":{"name":"Fixture","severity":"high","description":"Readable description"}}`
	findings, err := parseNucleiJSONL(strings.NewReader(raw+"\n"), "192.0.2.10")
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
	if findings[0].Description != "Readable description" || findings[0].Evidence != raw {
		t.Fatalf("parsed finding=%#v", findings[0])
	}
}

func TestBuildTargetsPreservesConfirmedNonStandardHTTPS(t *testing.T) {
	targets := buildTargets("192.0.2.10", []model.ScanResult{
		{Address: "192.0.2.10:30957", Open: true, Service: "https"},
		{Address: "192.0.2.10:23333", Open: true, Service: "http"},
		{Address: "192.0.2.10:22", Open: true, Service: "ssh"},
	})
	want := []string{"https://192.0.2.10:30957", "http://192.0.2.10:23333", "192.0.2.10:22"}
	if !reflect.DeepEqual(targets, want) {
		t.Fatalf("targets=%#v want=%#v", targets, want)
	}
}

func TestRunNucleiReturnsParentCancellation(t *testing.T) {
	originalDetect := detectNucleiBinary
	originalResolve := resolveNucleiTemplates
	originalCommand := newNucleiCommand
	t.Cleanup(func() {
		detectNucleiBinary = originalDetect
		resolveNucleiTemplates = originalResolve
		newNucleiCommand = originalCommand
	})

	marker := t.TempDir() + "/started"
	detectNucleiBinary = func() (string, error) { return "test-nuclei", nil }
	resolveNucleiTemplates = func(string) (string, error) { return t.TempDir(), nil }
	newNucleiCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestRunNucleiCancellationHelper", "--")
		cmd.Env = append(os.Environ(), "YSCAN_NUCLEI_HELPER=1", "YSCAN_NUCLEI_MARKER="+marker)
		return cmd
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := RunNucleiForOpenPorts(ctx, "127.0.0.1", []model.ScanResult{{Address: "127.0.0.1:80", Open: true}}, "templates")
		done <- err
	}()

	deadline := time.After(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("nuclei helper did not start")
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nuclei did not stop after parent context cancellation")
	}
}

func TestRunNucleiWithTemplatePathsUsesOnlyReviewedFiles(t *testing.T) {
	originalDetect := detectNucleiBinary
	originalCommand := newNucleiCommand
	t.Cleanup(func() { detectNucleiBinary = originalDetect; newNucleiCommand = originalCommand })
	template := t.TempDir() + "/reviewed.yaml"
	if err := os.WriteFile(template, []byte("id: reviewed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	detectNucleiBinary = func() (string, error) { return "test-nuclei", nil }
	var args []string
	newNucleiCommand = func(ctx context.Context, _ string, value ...string) *exec.Cmd {
		args = append([]string(nil), value...)
		return exec.CommandContext(ctx, os.Args[0], "-test.run=TestNucleiSuccessHelper", "--")
	}
	_, err := RunNucleiForOpenPortsWithTemplatePaths(context.Background(), "127.0.0.1", []model.ScanResult{{Address: "127.0.0.1:8080", Open: true}}, []string{template})
	if err != nil {
		t.Fatalf("run reviewed template: %v", err)
	}
	found := false
	for index, value := range args {
		if value == "-t" && index+1 < len(args) && args[index+1] == template {
			found = true
		}
	}
	if !found {
		t.Fatalf("reviewed template missing from args: %v", args)
	}
}

func TestRunNucleiTagFallbackTreatsNoMatchingTemplatesAsEmpty(t *testing.T) {
	originalDetect := detectNucleiBinary
	originalResolve := resolveNucleiTemplates
	originalCommand := newNucleiCommand
	t.Cleanup(func() {
		detectNucleiBinary = originalDetect
		resolveNucleiTemplates = originalResolve
		newNucleiCommand = originalCommand
	})
	detectNucleiBinary = func() (string, error) { return "test-nuclei", nil }
	resolveNucleiTemplates = func(string) (string, error) { return t.TempDir(), nil }
	newNucleiCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, os.Args[0], "-test.run=TestNucleiNoTemplatesHelper", "--")
	}
	findings, err := RunNucleiForOpenPortsWithTags(context.Background(), "127.0.0.1", []model.ScanResult{{Address: "127.0.0.1:8080", Open: true}}, "templates", []string{"nginx"})
	if !errors.Is(err, ErrNoTemplates) || len(findings) != 0 {
		t.Fatalf("tag fallback findings=%#v err=%v", findings, err)
	}
}

func TestRunNucleiPreservesParsedFindingWhenProcessExitsNonZero(t *testing.T) {
	originalDetect := detectNucleiBinary
	originalResolve := resolveNucleiTemplates
	originalCommand := newNucleiCommand
	t.Cleanup(func() {
		detectNucleiBinary = originalDetect
		resolveNucleiTemplates = originalResolve
		newNucleiCommand = originalCommand
	})
	detectNucleiBinary = func() (string, error) { return "test-nuclei", nil }
	resolveNucleiTemplates = func(string) (string, error) { return t.TempDir(), nil }
	newNucleiCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestNucleiFindingThenFailureHelper", "--")
		cmd.Env = append(os.Environ(), "YSCAN_NUCLEI_FINDING_FAILURE_HELPER=1")
		return cmd
	}

	findings, err := RunNucleiForOpenPorts(context.Background(), "127.0.0.1", []model.ScanResult{{Address: "127.0.0.1:8080", Open: true, Service: "http"}}, "templates")
	if err == nil || len(findings) != 1 || findings[0].TemplateID != "partial-before-failure" || findings[0].Description != "parsed before process failure" {
		t.Fatalf("partial process result findings=%#v err=%v", findings, err)
	}
	execution := ExecuteNucleiForOpenPortsWithTags(context.Background(), "127.0.0.1", []model.ScanResult{{Address: "127.0.0.1:8080", Open: true, Service: "http"}}, "templates", nil)
	if !execution.Started || !execution.Executed || execution.Err == nil || len(execution.Findings) != 1 {
		t.Fatalf("structured partial execution=%#v", execution)
	}
}

func TestNucleiFindingThenFailureHelper(t *testing.T) {
	if os.Getenv("YSCAN_NUCLEI_FINDING_FAILURE_HELPER") != "1" {
		return
	}
	_, _ = os.Stdout.WriteString(`{"template-id":"partial-before-failure","type":"http","host":"http://127.0.0.1:8080","matched-at":"http://127.0.0.1:8080/","info":{"name":"Partial","severity":"high","description":"parsed before process failure"}}` + "\n")
	_, _ = os.Stderr.WriteString("forced failure after finding\n")
	os.Exit(1)
}

func TestNucleiNoTemplatesHelper(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "" && !strings.Contains(strings.Join(os.Args, " "), "TestNucleiNoTemplatesHelper") {
		return
	}
	_, _ = os.Stderr.WriteString("[FTL] Could not run nuclei: no templates provided for scan\n")
	os.Exit(1)
}

func TestNucleiSuccessHelper(t *testing.T) {
	if os.Getenv("YSCAN_NUCLEI_HELPER") == "" {
		return
	}
}

func TestRunNucleiCancellationHelper(t *testing.T) {
	if os.Getenv("YSCAN_NUCLEI_HELPER") != "1" {
		return
	}
	if err := os.WriteFile(os.Getenv("YSCAN_NUCLEI_MARKER"), []byte("started"), 0600); err != nil {
		os.Exit(2)
	}
	select {}
}

func TestRunNucleiDrainsLargeStderrWithBoundedDiagnostic(t *testing.T) {
	originalDetect := detectNucleiBinary
	originalResolve := resolveNucleiTemplates
	originalCommand := newNucleiCommand
	t.Cleanup(func() {
		detectNucleiBinary = originalDetect
		resolveNucleiTemplates = originalResolve
		newNucleiCommand = originalCommand
	})

	detectNucleiBinary = func() (string, error) { return "test-nuclei", nil }
	resolveNucleiTemplates = func(string) (string, error) { return t.TempDir(), nil }
	newNucleiCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestRunNucleiStderrHelper", "--")
		cmd.Env = append(os.Environ(), "YSCAN_NUCLEI_STDERR_HELPER=1")
		return cmd
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := RunNucleiForOpenPorts(ctx, "127.0.0.1", []model.ScanResult{{Address: "127.0.0.1:80", Open: true}}, "templates")
	if err == nil {
		t.Fatal("large stderr helper must fail")
	}
	if ctx.Err() != nil {
		t.Fatalf("nuclei did not drain stderr before timeout: %v", ctx.Err())
	}
	if !strings.Contains(err.Error(), "[stderr truncated]") {
		t.Fatalf("error does not mark truncated stderr: %v", err)
	}
	maxMessageLen := len("nuclei execution failed: ") + maxNucleiStderrBytes + len("\n[stderr truncated]")
	if len(err.Error()) > maxMessageLen {
		t.Fatalf("error length = %d, maximum = %d", len(err.Error()), maxMessageLen)
	}
}

func TestRunNucleiStderrHelper(t *testing.T) {
	if os.Getenv("YSCAN_NUCLEI_STDERR_HELPER") != "1" {
		return
	}
	_, _ = os.Stderr.Write(bytes.Repeat([]byte("e"), maxNucleiStderrBytes*8))
	os.Exit(1)
}
