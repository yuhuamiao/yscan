package workflow

import (
	"context"
	"database/sql"
	"reflect"
	"testing"

	"golandproject/yscan/internal/model"
)

func TestRunTargetTaskRunBuildsSnapshotIndependentOfInventory(t *testing.T) {
	db := openWorkflowDB(t)
	snapshot, err := runTargetTaskRun(context.Background(), TargetTaskRunOptions{
		DB: db,
		Run: model.ScanTaskRun{
			ID:         91,
			ScanTaskID: 12,
			ScanType:   model.ScanTypeIP,
			Target:     "192.168.80.10",
			Config: model.ScanTaskConfig{
				VulnerabilityOn: true,
				NucleiTemplates: "test-templates",
			},
		},
	}, targetDependencies{
		scanHost: func(context.Context, string, string) ([]model.ScanResult, error) {
			return []model.ScanResult{{Address: "192.168.80.10:8443", Open: true, Service: "https", Product: "nginx"}}, nil
		},
		runNuclei: func(_ context.Context, _ string, _ []model.ScanResult, templates string, _ []string) ([]model.NucleiFinding, error) {
			if templates != "test-templates" {
				t.Fatalf("templates = %q", templates)
			}
			return []model.NucleiFinding{{
				TemplateID: "CVE-2026-0002",
				Target:     "https://192.168.80.10:8443",
				TargetIP:   "192.168.80.10",
				TargetPort: 8443,
			}}, nil
		},
		collectFingerprints: func(context.Context, *sql.DB, string, []model.ScanResult) ([]model.AssetFingerprint, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("run target task run: %v", err)
	}
	if snapshot.RunID != 91 {
		t.Fatalf("snapshot run ID = %d", snapshot.RunID)
	}
	if want := []model.ScanTaskRunHost{{IP: "192.168.80.10", IsActive: true}}; !reflect.DeepEqual(snapshot.Hosts, want) {
		t.Fatalf("snapshot hosts = %#v, want %#v", snapshot.Hosts, want)
	}
	if want := []model.ScanTaskRunPort{{IP: "192.168.80.10", Port: 8443, ServiceType: "https", Product: "nginx"}}; !reflect.DeepEqual(snapshot.Ports, want) {
		t.Fatalf("snapshot ports = %#v, want %#v", snapshot.Ports, want)
	}
	if len(snapshot.Vulnerabilities) != 1 || snapshot.Vulnerabilities[0].TemplateID != "CVE-2026-0002" {
		t.Fatalf("snapshot vulnerabilities = %#v", snapshot.Vulnerabilities)
	}
}
