package vuln

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"golandproject/yscan/internal/model"
)

func TestBuildNucleiArgsIncludesNormalizedTags(t *testing.T) {
	args := buildNucleiArgs("targets.txt", "templates", []string{"http", " Redis ", "http"})
	want := []string{"-jsonl", "-silent", "-l", "targets.txt", "-exclude-tags", "intrusive,dos,auth", "-t", "templates", "-tags", "http,redis"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %v, want %v", args, want)
	}
}

func TestBuildNucleiArgsAlwaysIncludesSafetyExclusions(t *testing.T) {
	args := buildNucleiArgs("targets.txt", "templates", nil)
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
