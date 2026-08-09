//go:build linux

package planner

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNucleiTemplateIndexRejectsFIFOBeforeBlockingOpen(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "stall.yaml"), 0600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := BuildNucleiTemplateIndex(root)
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO was not rejected as a non-regular template: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("template index blocked while opening FIFO")
	}
}

func TestReadBoundedNucleiTemplateRejectsFIFODescriptorWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stall.yaml")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, _, err := readBoundedNucleiTemplate(path, maxNucleiTemplateTotalBytes)
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO descriptor was not rejected: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("bounded template reader blocked while opening FIFO")
	}
}
