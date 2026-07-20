package workflow

import (
	"context"
	"database/sql"
	"reflect"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/pipeline"
	"golandproject/yscan/internal/storage"
)

func openWorkflowDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	statements := []string{
		`CREATE TABLE banner (id INTEGER PRIMARY KEY, service_name TEXT, banner_pattern TEXT, match_type TEXT, protocol TEXT, port INTEGER, description TEXT)`,
		`CREATE TABLE scan_results (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, port INTEGER NOT NULL, service_id INTEGER, service_type TEXT NOT NULL, scan_time DATETIME, UNIQUE(ip, port))`,
		`CREATE TABLE host_inventory (id INTEGER PRIMARY KEY, ip TEXT NOT NULL UNIQUE, source TEXT, first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL, last_scan DATETIME, is_active INTEGER NOT NULL DEFAULT 1)`,
		`CREATE TABLE task_change_summaries (task_id INTEGER PRIMARY KEY, target TEXT NOT NULL, summary_json TEXT NOT NULL, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create test schema: %v", err)
		}
	}
	return db
}

func TestRunSubnetBuildsAndPersistsChanges(t *testing.T) {
	db := openWorkflowDB(t)
	const cidr = "192.168.10.0/24"
	const source = "subnet:" + cidr
	if err := storage.SyncHostInventory(db, source, []string{"192.168.10.1", "192.168.10.9"}); err != nil {
		t.Fatalf("seed hosts: %v", err)
	}
	if err := storage.SyncOpenPorts(db, "192.168.10.1", []model.ScanResult{
		{Address: "192.168.10.1:80", Open: true, Service: "http"},
	}); err != nil {
		t.Fatalf("seed ports: %v", err)
	}

	progress := make([]int, 0)
	summary, err := runSubnet(context.Background(), SubnetRunOptions{
		DB:     db,
		TaskID: 9,
		CIDR:   cidr,
		UpdateProgress: func(value int) error {
			progress = append(progress, value)
			return nil
		},
	}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return []string{"192.168.10.1", "192.168.10.2"}, nil
		},
		scanHost: func(ip, _ string) []model.ScanResult {
			switch ip {
			case "192.168.10.1":
				return []model.ScanResult{{Address: "192.168.10.1:443", Open: true, Service: "https"}}
			case "192.168.10.2":
				return []model.ScanResult{{Address: "192.168.10.2:6379", Open: true, Service: "redis"}}
			default:
				return nil
			}
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
		saveFindings: func(*sql.DB, int64, []model.NucleiFinding) error { return nil },
	})
	if err != nil {
		t.Fatalf("runSubnet: %v", err)
	}

	if want := []string{"192.168.10.2"}; !reflect.DeepEqual(summary.HostChanges.NewHosts, want) {
		t.Fatalf("new hosts = %v, want %v", summary.HostChanges.NewHosts, want)
	}
	if want := []string{"192.168.10.9"}; !reflect.DeepEqual(summary.HostChanges.InactiveHosts, want) {
		t.Fatalf("inactive hosts = %v, want %v", summary.HostChanges.InactiveHosts, want)
	}
	if want := []model.PortChange{{IP: "192.168.10.1", Port: 443}, {IP: "192.168.10.2", Port: 6379}}; !reflect.DeepEqual(summary.PortChanges.Opened, want) {
		t.Fatalf("opened ports = %v, want %v", summary.PortChanges.Opened, want)
	}
	if want := []model.PortChange{{IP: "192.168.10.1", Port: 80}}; !reflect.DeepEqual(summary.PortChanges.Closed, want) {
		t.Fatalf("closed ports = %v, want %v", summary.PortChanges.Closed, want)
	}
	if progress[len(progress)-1] != 100 {
		t.Fatalf("final progress = %v", progress)
	}

	persisted, err := storage.GetTaskChangeSummary(db, 9)
	if err != nil {
		t.Fatalf("get persisted summary: %v", err)
	}
	if !reflect.DeepEqual(persisted.PortChanges, summary.PortChanges) {
		t.Fatalf("persisted port changes = %v, want %v", persisted.PortChanges, summary.PortChanges)
	}
}

func TestRunSubnetOnlyRunsVulnerabilitiesForOpenHosts(t *testing.T) {
	db := openWorkflowDB(t)
	calls := 0
	_, err := runSubnet(context.Background(), SubnetRunOptions{
		DB:                    db,
		TaskID:                10,
		CIDR:                  "192.168.20.0/24",
		EnableVulnerabilities: true,
	}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return []string{"192.168.20.1"}, nil
		},
		scanHost: func(string, string) []model.ScanResult { return nil },
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			calls++
			return nil, nil
		},
		saveFindings: func(*sql.DB, int64, []model.NucleiFinding) error { return nil },
	})
	if err != nil {
		t.Fatalf("runSubnet: %v", err)
	}
	if calls != 0 {
		t.Fatalf("nuclei calls = %d, want 0", calls)
	}
}

func TestRunSubnetPassesServiceSpecificTemplateGroups(t *testing.T) {
	db := openWorkflowDB(t)
	var gotGroups []string
	_, err := runSubnet(context.Background(), SubnetRunOptions{
		DB:                    db,
		TaskID:                11,
		CIDR:                  "192.168.30.0/24",
		EnableVulnerabilities: true,
	}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return []string{"192.168.30.1"}, nil
		},
		scanHost: func(string, string) []model.ScanResult {
			return []model.ScanResult{{Address: "192.168.30.1:6379", Open: true, Service: "redis"}}
		},
		runNuclei: func(_ context.Context, _ string, _ []model.ScanResult, _ string, groups []string) ([]model.NucleiFinding, error) {
			gotGroups = append([]string(nil), groups...)
			return nil, nil
		},
		saveFindings: func(*sql.DB, int64, []model.NucleiFinding) error { return nil },
	})
	if err != nil {
		t.Fatalf("runSubnet: %v", err)
	}
	if want := []string{"misconfiguration", "redis"}; !reflect.DeepEqual(gotGroups, want) {
		t.Fatalf("template groups = %v, want %v", gotGroups, want)
	}
}
