package report

import (
	"os"
	"strings"
	"testing"
	"time"

	"golandproject/yscan/internal/model"
)

func TestRenderMarkdownIncludesRequiredSections(t *testing.T) {
	content := RenderMarkdown(TaskReport{
		Task: model.Task{ID: 3, TaskType: model.TaskTypeScanSubnet, Target: "192.168.1.0/24", Status: model.TaskStatusSuccess},
		Changes: model.TaskChangeSummary{
			HostChanges: model.HostChanges{NewHosts: []string{"192.168.1.10"}},
			PortChanges: model.PortChanges{Opened: []model.PortChange{{IP: "192.168.1.10", Port: 443}}},
		},
		Findings:    []model.Vulnerability{{Severity: "high", TemplateID: "test-template", TargetIP: "192.168.1.10", Name: "Test Finding"}},
		GeneratedAt: time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC),
	})

	for _, section := range []string{"## Task Summary", "## Host Changes", "## Port Changes", "## Vulnerability Summary", "192.168.1.10:443", "test-template"} {
		if !strings.Contains(content, section) {
			t.Fatalf("report does not contain %q", section)
		}
	}
}

func TestWriteAndReadTaskReport(t *testing.T) {
	directory := t.TempDir()
	path, err := WriteTaskReport(directory, TaskReport{Task: model.Task{ID: 8, Target: "10.0.0.0/24"}})
	if err != nil {
		t.Fatalf("write report: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat report: %v", err)
	}
	content, err := ReadTaskReport(directory, 8)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(content), "yscan CAASM Task Report") {
		t.Fatalf("unexpected report content: %s", content)
	}
}
