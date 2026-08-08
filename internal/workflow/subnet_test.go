package workflow

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/pipeline"
	"golandproject/yscan/internal/planner"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/vuln"
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
		`CREATE TABLE host_inventory_scopes (scope TEXT NOT NULL, ip TEXT NOT NULL, first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL, last_checked DATETIME NOT NULL, is_active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (scope, ip))`,
		`CREATE TABLE host_inventory_scope_ports (scope TEXT NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, service_type TEXT NOT NULL, first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL, last_checked DATETIME NOT NULL, is_active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (scope, ip, port))`,
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
	if err := storage.SyncScopeOpenPorts(db, source, "192.168.10.1", []model.ScanResult{
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
		scanHost: func(_ context.Context, ip, _ string) ([]model.ScanResult, error) {
			switch ip {
			case "192.168.10.1":
				return []model.ScanResult{{Address: "192.168.10.1:443", Open: true, Service: "https"}}, nil
			case "192.168.10.2":
				return []model.ScanResult{{Address: "192.168.10.2:6379", Open: true, Service: "redis"}}, nil
			default:
				return nil, nil
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
		scanHost: func(context.Context, string, string) ([]model.ScanResult, error) { return nil, nil },
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
		scanHost: func(context.Context, string, string) ([]model.ScanResult, error) {
			return []model.ScanResult{{Address: "192.168.30.1:6379", Open: true, Service: "redis"}}, nil
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

func TestRunSubnetPortChangesStayWithinScope(t *testing.T) {
	db := openWorkflowDB(t)
	const (
		cidr16  = "192.168.0.0/16"
		cidr24  = "192.168.10.0/24"
		scope16 = "subnet:" + cidr16
		ip      = "192.168.10.10"
	)
	if err := storage.SyncHostInventory(db, scope16, []string{ip}); err != nil {
		t.Fatalf("seed /16 host: %v", err)
	}
	if err := storage.SyncScopeOpenPorts(db, scope16, ip, []model.ScanResult{{Address: ip + ":80", Open: true, Service: "http"}}); err != nil {
		t.Fatalf("seed /16 port: %v", err)
	}

	summary24, err := runSubnet(context.Background(), SubnetRunOptions{
		DB:     db,
		TaskID: 13,
		CIDR:   cidr24,
	}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return []string{ip}, nil
		},
		scanHost: func(context.Context, string, string) ([]model.ScanResult, error) {
			return []model.ScanResult{{Address: ip + ":443", Open: true, Service: "https"}}, nil
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
		saveFindings: func(*sql.DB, int64, []model.NucleiFinding) error { return nil },
	})
	if err != nil {
		t.Fatalf("run /24: %v", err)
	}
	if want := []model.PortChange{{IP: ip, Port: 443}}; !reflect.DeepEqual(summary24.PortChanges.Opened, want) {
		t.Fatalf("/24 opened ports = %v, want %v", summary24.PortChanges.Opened, want)
	}
	if len(summary24.PortChanges.Closed) != 0 {
		t.Fatalf("/24 closed ports = %v, want none", summary24.PortChanges.Closed)
	}

	summary16, err := runSubnet(context.Background(), SubnetRunOptions{
		DB:     db,
		TaskID: 14,
		CIDR:   cidr16,
	}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return []string{ip}, nil
		},
		scanHost: func(context.Context, string, string) ([]model.ScanResult, error) {
			return []model.ScanResult{{Address: ip + ":80", Open: true, Service: "http"}}, nil
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
		saveFindings: func(*sql.DB, int64, []model.NucleiFinding) error { return nil },
	})
	if err != nil {
		t.Fatalf("run /16: %v", err)
	}
	if len(summary16.PortChanges.Opened) != 0 || len(summary16.PortChanges.Closed) != 0 {
		t.Fatalf("/16 diff must ignore /24 port state: %#v", summary16.PortChanges)
	}
}

func TestRunSubnetMarksScopePortsClosedWhenHostsBecomeInactive(t *testing.T) {
	db := openWorkflowDB(t)
	const (
		cidr  = "192.168.50.0/24"
		scope = "subnet:" + cidr
		ip    = "192.168.50.10"
	)
	if err := storage.SyncHostInventory(db, scope, []string{ip}); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	if err := storage.SyncScopeOpenPorts(db, scope, ip, []model.ScanResult{{Address: ip + ":8080", Open: true, Service: "http"}}); err != nil {
		t.Fatalf("seed port: %v", err)
	}

	summary, err := runSubnet(context.Background(), SubnetRunOptions{
		DB:     db,
		TaskID: 15,
		CIDR:   cidr,
	}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return nil, nil
		},
		scanHost: func(context.Context, string, string) ([]model.ScanResult, error) {
			t.Fatal("scanHost must not run when discovery returns no hosts")
			return nil, nil
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
		saveFindings: func(*sql.DB, int64, []model.NucleiFinding) error { return nil },
	})
	if err != nil {
		t.Fatalf("run empty scope: %v", err)
	}
	if want := []model.PortChange{{IP: ip, Port: 8080}}; !reflect.DeepEqual(summary.PortChanges.Closed, want) {
		t.Fatalf("closed ports = %v, want %v", summary.PortChanges.Closed, want)
	}
}

func TestRunSubnetDoesNotReportBackfilledScopeHostsAsNew(t *testing.T) {
	db := openWorkflowDB(t)
	const (
		cidr  = "192.168.60.0/24"
		scope = "subnet:" + cidr
		ip    = "192.168.60.10"
	)
	if _, err := db.Exec(`
		INSERT INTO host_inventory_scopes (scope, ip, first_seen, last_seen, last_checked, is_active)
		VALUES (?, ?, '2026-01-01 00:00:00', '2026-02-01 00:00:00', '2026-02-02 00:00:00', 1)`, scope, ip); err != nil {
		t.Fatalf("seed migrated scope member: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO host_inventory_scope_ports (scope, ip, port, service_type, first_seen, last_seen, last_checked, is_active)
		VALUES (?, ?, 443, 'https', '2026-01-01 00:00:00', '2026-02-01 00:00:00', '2026-02-02 00:00:00', 1)`, scope, ip); err != nil {
		t.Fatalf("seed migrated scope port: %v", err)
	}

	summary, err := runSubnet(context.Background(), SubnetRunOptions{
		DB:     db,
		TaskID: 16,
		CIDR:   cidr,
	}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return []string{ip}, nil
		},
		scanHost: func(context.Context, string, string) ([]model.ScanResult, error) {
			return []model.ScanResult{{Address: ip + ":443", Open: true, Service: "https"}}, nil
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
		saveFindings: func(*sql.DB, int64, []model.NucleiFinding) error { return nil },
	})
	if err != nil {
		t.Fatalf("run subnet with migrated member: %v", err)
	}
	if len(summary.HostChanges.NewHosts) != 0 || len(summary.HostChanges.InactiveHosts) != 0 {
		t.Fatalf("migrated scope member produced host changes: %#v", summary.HostChanges)
	}
	if len(summary.PortChanges.Opened) != 0 || len(summary.PortChanges.Closed) != 0 {
		t.Fatalf("migrated scope port produced changes: %#v", summary.PortChanges)
	}
}

func TestRunSubnetStopsAfterScanContextCancellation(t *testing.T) {
	db := openWorkflowDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scannedHosts := make([]string, 0)
	_, err := runSubnet(ctx, SubnetRunOptions{
		DB:     db,
		TaskID: 12,
		CIDR:   "192.168.40.0/24",
	}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return []string{"192.168.40.1", "192.168.40.2"}, nil
		},
		scanHost: func(ctx context.Context, ip, _ string) ([]model.ScanResult, error) {
			scannedHosts = append(scannedHosts, ip)
			cancel()
			return nil, ctx.Err()
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
		saveFindings: func(*sql.DB, int64, []model.NucleiFinding) error { return nil },
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if want := []string{"192.168.40.1"}; !reflect.DeepEqual(scannedHosts, want) {
		t.Fatalf("scanned hosts = %v, want %v", scannedHosts, want)
	}
}

func TestRunSubnetTaskRunBuildsImmutableSnapshotWithoutScopeBaseline(t *testing.T) {
	db := openWorkflowDB(t)
	const (
		cidr  = "192.168.70.0/24"
		scope = "subnet:" + cidr
	)
	if err := storage.SyncHostInventory(db, scope, []string{"192.168.70.9"}); err != nil {
		t.Fatalf("seed legacy scope host: %v", err)
	}
	if err := storage.SyncScopeOpenPorts(db, scope, "192.168.70.9", []model.ScanResult{{Address: "192.168.70.9:80", Open: true, Service: "http"}}); err != nil {
		t.Fatalf("seed legacy scope port: %v", err)
	}

	snapshot, err := runSubnetTaskRun(context.Background(), SubnetTaskRunOptions{
		DB: db,
		Run: model.ScanTaskRun{
			ID:         71,
			ScanTaskID: 8,
			ScanType:   model.ScanTypeSubnet,
			Target:     cidr,
			Config: model.ScanTaskConfig{
				VulnerabilityOn: true,
				NucleiTemplates: "test-templates",
			},
		},
	}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return []string{"192.168.70.1"}, nil
		},
		scanHost: func(context.Context, string, string) ([]model.ScanResult, error) {
			return []model.ScanResult{{Address: "192.168.70.1:443", Open: true, Service: "https", Product: "nginx"}}, nil
		},
		runNuclei: func(_ context.Context, ip string, _ []model.ScanResult, templates string, _ []string) ([]model.NucleiFinding, error) {
			if ip != "192.168.70.1" || templates != "test-templates" {
				t.Fatalf("nuclei input = (%s, %s)", ip, templates)
			}
			return []model.NucleiFinding{{
				TemplateID: "CVE-2026-0001",
				Name:       "Example finding",
				Severity:   "high",
				Target:     "https://192.168.70.1",
				TargetIP:   "192.168.70.1",
				TargetPort: 443,
			}}, nil
		},
	})
	if err != nil {
		t.Fatalf("run subnet task run: %v", err)
	}
	if snapshot.RunID != 71 {
		t.Fatalf("snapshot run ID = %d", snapshot.RunID)
	}
	if want := []model.ScanTaskRunHost{{IP: "192.168.70.1", IsActive: true}}; !reflect.DeepEqual(snapshot.Hosts, want) {
		t.Fatalf("snapshot hosts = %#v, want %#v", snapshot.Hosts, want)
	}
	if want := []model.ScanTaskRunPort{{IP: "192.168.70.1", Port: 443, ServiceType: "https", Product: "nginx"}}; !reflect.DeepEqual(snapshot.Ports, want) {
		t.Fatalf("snapshot ports = %#v, want %#v", snapshot.Ports, want)
	}
	if len(snapshot.Vulnerabilities) != 1 || snapshot.Vulnerabilities[0].TemplateID != "CVE-2026-0001" || snapshot.Vulnerabilities[0].TargetIP != "192.168.70.1" {
		t.Fatalf("snapshot vulnerabilities = %#v", snapshot.Vulnerabilities)
	}
}

func TestRunSubnetTaskRunUsesConfiguredPortSpecAndReturnsPartialOnCancel(t *testing.T) {
	db := openWorkflowDB(t)
	canceled := false
	selectedHosts := make([]string, 0, 1)
	snapshot, err := runSubnetTaskRun(context.Background(), SubnetTaskRunOptions{
		DB:            db,
		Run:           model.ScanTaskRun{ID: 72, ScanTaskID: 8, ScanType: model.ScanTypeSubnet, Target: "192.168.72.0/24", Config: model.ScanTaskConfig{PortSpec: "80,443"}},
		CheckCanceled: func() (bool, error) { return canceled, nil },
	}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return []string{"192.168.72.1", "192.168.72.2"}, nil
		},
		scanHost: func(context.Context, string, string) ([]model.ScanResult, error) {
			t.Fatal("baseline scan must not run for explicit port_spec")
			return nil, nil
		},
		scanSelected: func(_ context.Context, ip, _ string, ports []int) ([]model.ScanResult, error) {
			if !reflect.DeepEqual(ports, []int{80, 443}) {
				t.Fatalf("selected ports=%v", ports)
			}
			selectedHosts = append(selectedHosts, ip)
			canceled = true
			return []model.ScanResult{{Address: ip + ":443", Open: true, Service: "https"}}, nil
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
	})
	if !errors.Is(err, ErrCanceled) || !reflect.DeepEqual(selectedHosts, []string{"192.168.72.1"}) {
		t.Fatalf("selected hosts=%v err=%v", selectedHosts, err)
	}
	if len(snapshot.Ports) != 1 || snapshot.Ports[0].IP != "192.168.72.1" || snapshot.Ports[0].Port != 443 {
		t.Fatalf("partial snapshot=%#v", snapshot)
	}
}

func TestRunSubnetTaskRunReturnsCurrentHostFingerprintPartialOnCancellation(t *testing.T) {
	db := openWorkflowDB(t)
	const ip = "192.168.74.1"
	snapshot, err := runSubnetTaskRun(context.Background(), SubnetTaskRunOptions{
		DB:  db,
		Run: model.ScanTaskRun{ID: 74, ScanTaskID: 8, ScanType: model.ScanTypeSubnet, Target: "192.168.74.0/24"},
	}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return []string{ip}, nil
		},
		scanHost: func(context.Context, string, string) ([]model.ScanResult, error) {
			return []model.ScanResult{{Address: ip + ":9090", Open: true, Service: "unknown"}}, nil
		},
		collectFingerprints: func(_ context.Context, _ *sql.DB, _ model.ScanTaskRun, _ string, results []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error) {
			results[0].Service = "http"
			results[0].Product = "partial-subnet-product"
			return results, []model.FingerprintRunMatch{{IP: ip, Port: 9090, Protocol: "http", Product: "partial-subnet-product"}}, context.Canceled
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context.Canceled", err)
	}
	if len(snapshot.Hosts) != 1 || snapshot.Hosts[0].IP != ip || len(snapshot.Ports) != 1 || snapshot.Ports[0].Port != 9090 || snapshot.Ports[0].Product != "partial-subnet-product" || len(snapshot.FingerprintMatches) != 1 {
		t.Fatalf("subnet fingerprint cancellation partial snapshot=%#v", snapshot)
	}
}

func TestRunSubnetTaskRunKeepsCurrentHostPortsWhenScannerFails(t *testing.T) {
	db := openWorkflowDB(t)
	const ip = "192.168.75.1"
	scanErr := errors.New("scanner stopped after partial read")
	snapshot, err := runSubnetTaskRun(context.Background(), SubnetTaskRunOptions{
		DB: db, Run: model.ScanTaskRun{ID: 75, ScanTaskID: 8, ScanType: model.ScanTypeSubnet, Target: "192.168.75.0/24"},
	}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return []string{ip}, nil
		},
		scanHost: func(context.Context, string, string) ([]model.ScanResult, error) {
			return []model.ScanResult{{Address: ip + ":3306", Open: true, Service: "mysql"}}, scanErr
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
	})
	if !errors.Is(err, scanErr) {
		t.Fatalf("error=%v, want %v", err, scanErr)
	}
	if len(snapshot.Hosts) != 1 || snapshot.Hosts[0].IP != ip || len(snapshot.Ports) != 1 || snapshot.Ports[0].Port != 3306 {
		t.Fatalf("scanner partial snapshot=%#v", snapshot)
	}
}

func TestRunSubnetTaskRunKeepsObservationsWhenNucleiFails(t *testing.T) {
	db := openWorkflowDB(t)
	const ip = "192.168.76.1"
	nucleiErr := errors.New("nuclei fixture failed")
	snapshot, err := runSubnetTaskRun(context.Background(), SubnetTaskRunOptions{
		DB:  db,
		Run: model.ScanTaskRun{ID: 76, ScanTaskID: 8, ScanType: model.ScanTypeSubnet, Target: "192.168.76.0/24", Config: model.ScanTaskConfig{VulnerabilityOn: true}},
	}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return []string{ip, "192.168.76.2"}, nil
		},
		scanHost: func(_ context.Context, host, _ string) ([]model.ScanResult, error) {
			return []model.ScanResult{{Address: host + ":6379", Open: true, Service: "redis"}}, nil
		},
		collectFingerprints: func(_ context.Context, _ *sql.DB, _ model.ScanTaskRun, host string, results []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error) {
			results[0].Product = "redis"
			return results, []model.FingerprintRunMatch{{IP: host, Port: 6379, Protocol: "tcp", Product: "redis", Soft: true}}, nil
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return []model.NucleiFinding{{TemplateID: "redis-partial", TargetIP: ip, TargetPort: 6379}}, nucleiErr
		},
	})
	if !errors.Is(err, nucleiErr) {
		t.Fatalf("error=%v, want %v", err, nucleiErr)
	}
	if len(snapshot.Ports) != 1 || snapshot.Ports[0].IP != ip || len(snapshot.FingerprintMatches) != 1 {
		t.Fatalf("nuclei failure lost observations: %#v", snapshot)
	}
	if len(snapshot.Vulnerabilities) != 1 || snapshot.Vulnerabilities[0].TemplateID != "redis-partial" || len(snapshot.TemplateCandidates) == 0 {
		t.Fatalf("nuclei failure lost validation partials: %#v", snapshot)
	}
	if snapshot.Validation.Status != model.ScanTaskRunValidationFailed || snapshot.Validation.Error == "" || snapshot.Validation.FindingCount != 1 {
		t.Fatalf("nuclei failure validation state=%#v", snapshot.Validation)
	}
}

func TestTemplateCandidateCoverageUsesStructuredProtocolNotReason(t *testing.T) {
	port := model.ScanResult{Address: "192.168.73.1:443", Open: true, Service: "https"}
	tcpCandidate := model.ScanTaskRunTemplateCandidate{TemplateID: "fixture", Path: "fixture.yaml", Source: "fingerprint_mapping", Reason: "arbitrary changed display text", IP: "192.168.73.1", Port: 443, Protocol: "tcp"}
	if remaining := portsWithoutFingerprintMappings([]model.ScanResult{port}, []model.ScanTaskRunTemplateCandidate{tcpCandidate}); len(remaining) != 1 {
		t.Fatal("TCP candidate must not suppress HTTPS fallback on the same port")
	}
	httpsCandidate := tcpCandidate
	httpsCandidate.Protocol = "https"
	if remaining := portsWithoutFingerprintMappings([]model.ScanResult{port}, []model.ScanTaskRunTemplateCandidate{httpsCandidate}); len(remaining) != 0 {
		t.Fatal("structured HTTPS candidate did not suppress its own endpoint fallback")
	}
	if unique := uniqueTemplateCandidates([]model.ScanTaskRunTemplateCandidate{tcpCandidate, httpsCandidate}); len(unique) != 2 {
		t.Fatalf("same template on distinct protocols collapsed: %#v", unique)
	}
}

func TestAutomaticTemplateIndexMapsExecutesAndReportsCoverage(t *testing.T) {
	db, err := storage.InitDBAt(filepath.Join(t.TempDir(), "automatic-index.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	root := t.TempDir()
	templatePath := filepath.Join(root, "network", "exposed-redis.yaml")
	if err := os.MkdirAll(filepath.Dir(templatePath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(templatePath, []byte(`
id: exposed-redis
info:
  name: Redis Exposure
  severity: high
  tags: network,redis,unauth,exposure,tcp,discovery
tcp:
  - inputs:
      - data: "info\r\nquit\r\n"
`), 0600); err != nil {
		t.Fatal(err)
	}
	index, err := planner.BuildNucleiTemplateIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	const ip = "192.168.77.10"
	port := model.ScanResult{Address: ip + ":6379", Open: true, Service: "redis", Product: "redis"}
	match := model.FingerprintRunMatch{IP: ip, Port: 6379, Protocol: "tcp", Product: "redis", CPE: "cpe:2.3:a:redislabs:redis:*:*:*:*:*:*:*:*"}
	executions := 0
	result := runFingerprintMappingValidation(context.Background(), db, model.ScanTaskRun{ID: 77}, ip, []model.ScanResult{port}, []model.FingerprintRunMatch{match}, root, index,
		func(_ context.Context, target string, ports []model.ScanResult, paths []string) vuln.NucleiExecutionResult {
			executions++
			if target != ip || len(ports) != 1 || len(paths) != 1 || paths[0] != templatePath {
				t.Fatalf("automatic invocation target=%s ports=%#v paths=%#v", target, ports, paths)
			}
			return vuln.NucleiExecutionResult{Started: true, Executed: true, Findings: []model.NucleiFinding{{TemplateID: "exposed-redis", Name: "Redis Exposure", Target: ip + ":6379", TargetIP: ip, TargetPort: 6379}}}
		})
	if result.err != nil || executions != 1 || len(result.candidates) != 1 || result.candidates[0].Source != "automatic_template_index" || result.candidates[0].ProductKey != "redis" || result.candidates[0].TemplateSHA256 == "" || result.candidates[0].TemplateSetRevision != index.Revision {
		t.Fatalf("automatic mapping result=%#v executions=%d", result, executions)
	}
	snapshot := model.ScanTaskRunSnapshot{Vulnerabilities: snapshotVulnerabilities(result.findings)}
	tracker := newRunValidationTracker()
	tracker.observe(result)
	tracker.finish(&snapshot, result.err)
	if snapshot.Validation.Status != model.ScanTaskRunValidationSuccess || snapshot.Validation.IdentifiedProductCount != 1 || snapshot.Validation.MappedProductCount != 1 || len(snapshot.Validation.UnmappedProducts) != 0 || snapshot.Validation.TemplateCount != 1 || snapshot.Validation.ExecutedTemplateCount != 1 || snapshot.Validation.FindingCount != 1 {
		t.Fatalf("validation coverage=%#v", snapshot.Validation)
	}
}

func TestValidationReportsIdentifiedProductWithoutTemplateAsUnmapped(t *testing.T) {
	tracker := newRunValidationTracker()
	identity := validationProductIdentity("192.168.77.11", 8080, "http", "fixture-app")
	tracker.observe(validationExecutionResult{identifiedProducts: map[string]struct{}{identity: {}}})
	snapshot := model.ScanTaskRunSnapshot{}
	tracker.finish(&snapshot, nil)
	if snapshot.Validation.Status != model.ScanTaskRunValidationNoCandidates || snapshot.Validation.IdentifiedProductCount != 1 || snapshot.Validation.MappedProductCount != 0 || !reflect.DeepEqual(snapshot.Validation.UnmappedProducts, []string{identity}) {
		t.Fatalf("unmapped validation coverage=%#v", snapshot.Validation)
	}
}
