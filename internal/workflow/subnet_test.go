package workflow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"golandproject/yscan/internal/fingerprint"
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
		`CREATE TABLE host_inventory_scopes (scope TEXT NOT NULL, ip TEXT NOT NULL, first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL, last_checked DATETIME NOT NULL, is_active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (scope, ip))`,
		`CREATE TABLE host_inventory_scope_ports (scope TEXT NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, service_type TEXT NOT NULL, first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL, last_checked DATETIME NOT NULL, is_active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (scope, ip, port))`,
		`CREATE TABLE task_change_summaries (task_id INTEGER PRIMARY KEY, target TEXT NOT NULL, summary_json TEXT NOT NULL, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)`,
		`CREATE TABLE asset_fingerprints (ip TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL, rule_id TEXT NOT NULL, source_id TEXT NOT NULL, vendor TEXT, product TEXT NOT NULL, version TEXT, cpe TEXT, confidence INTEGER NOT NULL, evidence_json TEXT NOT NULL, first_seen DATETIME, last_seen DATETIME, PRIMARY KEY (ip, port, protocol, rule_id, source_id))`,
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
		collectFingerprints: func(context.Context, *sql.DB, string, []model.ScanResult) ([]model.AssetFingerprint, error) {
			return nil, nil
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

func TestPlannedValidationKeepsFingerprintCandidatesOnMatchedPort(t *testing.T) {
	db := openWorkflowDB(t)
	const ip = "192.168.71.1"
	if err := storage.UpsertAssetFingerprints(db, []model.AssetFingerprint{{IP: ip, Port: 443, Protocol: "https", RuleID: "nginx-rule", SourceID: "test", Product: "nginx", Confidence: 90, Evidence: []model.FingerprintEvidence{{Target: "header", Operator: "contains", Pattern: "nginx", Summary: "server contains nginx"}}}}); err != nil {
		t.Fatalf("seed fingerprint: %v", err)
	}
	root := t.TempDir()
	data := "id: nginx-test\ninfo:\n  name: nginx test\n  severity: medium\n  tags: nginx\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}'\n"
	if err := os.WriteFile(filepath.Join(root, "nginx.yaml"), []byte(data), 0600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	ports := []model.ScanResult{{Address: ip + ":80", Open: true, Service: "http"}, {Address: ip + ":443", Open: true, Service: "https"}}
	var exactPorts, fallbackPorts []int
	current := []model.AssetFingerprint{{IP: ip, Port: 443, Protocol: "https", RuleID: "nginx-rule", SourceID: "test", Product: "nginx", Confidence: 90, Evidence: []model.FingerprintEvidence{{Target: "header", Operator: "contains", Pattern: "nginx", Summary: "server contains nginx"}}}}
	_, candidates, err := runPlannedValidation(context.Background(), ip, ports, current, root,
		func(_ context.Context, _ string, received []model.ScanResult, _ string, _ []string) ([]model.NucleiFinding, error) {
			fallbackPorts = append(fallbackPorts, portNumber(t, received))
			return nil, nil
		},
		func(_ context.Context, _ string, received []model.ScanResult, _ string, _ []string) ([]model.NucleiFinding, error) {
			exactPorts = append(exactPorts, portNumber(t, received))
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("planned validation: %v", err)
	}
	if !reflect.DeepEqual(exactPorts, []int{443}) || !reflect.DeepEqual(fallbackPorts, []int{80}) {
		t.Fatalf("exact ports=%v fallback ports=%v", exactPorts, fallbackPorts)
	}
	matched := false
	for _, candidate := range candidates {
		if candidate.TemplateID == "nginx-test" {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("fingerprint candidate missing: %#v", candidates)
	}
	_, staleCandidates, err := runPlannedValidation(context.Background(), ip, ports, nil, root,
		func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
		func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			t.Fatal("historical fingerprint must not execute exact template")
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("plan without current evidence: %v", err)
	}
	for _, candidate := range staleCandidates {
		if candidate.TemplateID == "nginx-test" {
			t.Fatalf("historical candidate leaked: %#v", staleCandidates)
		}
	}
}

func TestCollectRunFingerprintsPersistsCurrentPortEvidence(t *testing.T) {
	db := openWorkflowDB(t)
	const ip = "192.168.72.1"
	ports := []model.ScanResult{{Address: ip + ":6379", Open: true, Service: "redis", Banner: "-ERR operation not permitted\r\n"}}
	if _, err := collectRunFingerprints(context.Background(), db, ip, ports); err != nil {
		t.Fatalf("collect fingerprints: %v", err)
	}
	fingerprints, err := storage.ListAssetFingerprints(db, storage.AssetFingerprintQuery{IP: ip, Port: 6379, Protocol: "tcp"})
	if err != nil || len(fingerprints) != 1 || fingerprints[0].Product != "redis" {
		t.Fatalf("fingerprints=%#v err=%v", fingerprints, err)
	}
}

func TestRunSubnetTaskRunUsesFingerprintForUnknownService(t *testing.T) {
	db := openWorkflowDB(t)
	root := t.TempDir()
	data := "id: nginx-network\ninfo:\n  name: nginx network\n  severity: medium\n  tags: nginx\ntcp:\n  - host:\n      - '{{Hostname}}'\n    port: 8443\n"
	if err := os.WriteFile(filepath.Join(root, "nginx.yaml"), []byte(data), 0600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	const ip = "192.168.73.1"
	var exactPorts []int
	fallbackCalls := 0
	_, err := runSubnetTaskRun(context.Background(), SubnetTaskRunOptions{DB: db, Run: model.ScanTaskRun{ID: 73, ScanTaskID: 7, ScanType: model.ScanTypeSubnet, Target: "192.168.73.0/24", Config: model.ScanTaskConfig{VulnerabilityOn: true, NucleiTemplates: root}}}, subnetDependencies{
		discover: func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error) {
			return []string{ip}, nil
		},
		scanHost: func(context.Context, string, string) ([]model.ScanResult, error) {
			return []model.ScanResult{{Address: ip + ":8443", Open: true, Service: "unknown"}}, nil
		},
		collectFingerprints: func(_ context.Context, database *sql.DB, _ string, _ []model.ScanResult) ([]model.AssetFingerprint, error) {
			records := []model.AssetFingerprint{{IP: ip, Port: 8443, Protocol: "tcp", RuleID: "nginx-rule", SourceID: "test", Product: "nginx", Confidence: 90, Evidence: []model.FingerprintEvidence{{Target: "banner", Operator: "contains", Pattern: "nginx", Summary: "nginx banner"}}}}
			return records, storage.UpsertAssetFingerprints(database, records)
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			fallbackCalls++
			return nil, nil
		},
		runNucleiPaths: func(_ context.Context, _ string, ports []model.ScanResult, _ string, _ []string) ([]model.NucleiFinding, error) {
			exactPorts = append(exactPorts, portNumber(t, ports))
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("run subnet task run: %v", err)
	}
	if !reflect.DeepEqual(exactPorts, []int{8443}) || fallbackCalls != 0 {
		t.Fatalf("exact ports=%v fallback calls=%d", exactPorts, fallbackCalls)
	}
}

func TestShouldCollectHTTPEvidenceForUnknownNonStandardPort(t *testing.T) {
	if !shouldCollectHTTPEvidence(8443, "unknown") {
		t.Fatal("unknown non-standard service must receive bounded HTTP probe")
	}
	if shouldCollectHTTPEvidence(6379, "redis") {
		t.Fatal("identified non-HTTP service must not receive HTTP probe")
	}
}

func TestHTTPS8443EvidenceFlowsToExactTemplateCandidate(t *testing.T) {
	db := openWorkflowDB(t)
	root := t.TempDir()
	data := "id: thinkphp-test\ninfo:\n  name: thinkphp test\n  severity: medium\n  tags: thinkphp\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}'\n"
	if err := os.WriteFile(filepath.Join(root, "thinkphp.yaml"), []byte(data), 0600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	const ip = "192.168.74.1"
	ports := []model.ScanResult{{Address: ip + ":8443", Open: true, Service: "https"}}
	collector := func(_ context.Context, target string, _ fingerprint.HTTPEvidenceOptions) (fingerprint.HTTPEvidence, error) {
		if target != "https://"+ip+":8443" {
			t.Fatalf("HTTPS target = %q", target)
		}
		return fingerprint.HTTPEvidence{Headers: http.Header{"X-Powered-By": []string{"thinkphp"}}, HeaderText: "X-Powered-By: thinkphp\n", BodySummary: "thinkphp"}, nil
	}
	rules := []fingerprint.Rule{{ID: "https-test", SourceID: "test", Product: fingerprint.ProductIdentity{Name: "thinkphp"}, Protocols: []fingerprint.Protocol{fingerprint.ProtocolHTTPS}, MatchMode: fingerprint.MatchAll, Matchers: []fingerprint.Matcher{{Target: fingerprint.EvidenceHeader, Operator: fingerprint.MatchContains, Pattern: "thinkphp", CaseInsensitive: true}, {Target: fingerprint.EvidenceBody, Operator: fingerprint.MatchContains, Pattern: "thinkphp", CaseInsensitive: true}}}}
	current, err := collectRunFingerprintsWithRules(context.Background(), db, ip, ports, rules, collector)
	if err != nil {
		t.Fatalf("collect fingerprints: %v", err)
	}
	fingerprints, err := storage.ListAssetFingerprints(db, storage.AssetFingerprintQuery{IP: ip, Port: 8443, Protocol: "https"})
	if err != nil || len(fingerprints) == 0 || fingerprints[0].Product != "thinkphp" {
		t.Fatalf("HTTPS fingerprints=%#v err=%v", fingerprints, err)
	}
	var exactPorts []int
	_, candidates, err := runPlannedValidation(context.Background(), ip, ports, current, root,
		func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			t.Fatal("service fallback must not run")
			return nil, nil
		},
		func(_ context.Context, _ string, received []model.ScanResult, _ string, _ []string) ([]model.NucleiFinding, error) {
			exactPorts = append(exactPorts, portNumber(t, received))
			return nil, nil
		},
	)
	if err != nil || !reflect.DeepEqual(exactPorts, []int{8443}) || len(candidates) != 1 || candidates[0].TemplateID != "thinkphp-test" {
		t.Fatalf("ports=%v candidates=%#v err=%v", exactPorts, candidates, err)
	}
}

func TestHTTPFailureRetainsUnknownServiceBannerForExactCandidate(t *testing.T) {
	db := openWorkflowDB(t)
	root := t.TempDir()
	data := "id: redis-network\ninfo:\n  name: redis network\n  severity: medium\n  tags: redis\ntcp:\n  - host:\n      - '{{Hostname}}'\n    port: 6379\n"
	if err := os.WriteFile(filepath.Join(root, "redis.yaml"), []byte(data), 0600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	const ip = "192.168.75.1"
	ports := []model.ScanResult{{Address: ip + ":6379", Open: true, Service: "unknown", Banner: "redis_version:7.2"}}
	rules := []fingerprint.Rule{{ID: "redis-banner", SourceID: "test", Product: fingerprint.ProductIdentity{Name: "redis"}, Protocols: []fingerprint.Protocol{fingerprint.ProtocolTCP}, Matchers: []fingerprint.Matcher{{Target: fingerprint.EvidenceBanner, Operator: fingerprint.MatchContains, Pattern: "redis"}}}}
	current, err := collectRunFingerprintsWithRules(context.Background(), db, ip, ports, rules, func(context.Context, string, fingerprint.HTTPEvidenceOptions) (fingerprint.HTTPEvidence, error) {
		return fingerprint.HTTPEvidence{}, errors.New("HTTP probe unavailable")
	})
	if err != nil {
		t.Fatalf("collect banner fallback: %v", err)
	}
	fingerprints, err := storage.ListAssetFingerprints(db, storage.AssetFingerprintQuery{IP: ip, Port: 6379, Protocol: "tcp"})
	if err != nil || len(fingerprints) != 1 || fingerprints[0].Confidence != 70 {
		t.Fatalf("banner fingerprints=%#v err=%v", fingerprints, err)
	}
	var exactPorts []int
	_, candidates, err := runPlannedValidation(context.Background(), ip, ports, current, root,
		func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			t.Fatal("service fallback must not run")
			return nil, nil
		},
		func(_ context.Context, _ string, received []model.ScanResult, _ string, _ []string) ([]model.NucleiFinding, error) {
			exactPorts = append(exactPorts, portNumber(t, received))
			return nil, nil
		},
	)
	if err != nil || !reflect.DeepEqual(exactPorts, []int{6379}) || len(candidates) != 1 || candidates[0].TemplateID != "redis-network" {
		t.Fatalf("ports=%v candidates=%#v err=%v", exactPorts, candidates, err)
	}
}

func portNumber(t *testing.T, ports []model.ScanResult) int {
	t.Helper()
	if len(ports) != 1 {
		t.Fatalf("received ports = %#v", ports)
	}
	_, port, err := net.SplitHostPort(ports[0].Address)
	if err != nil {
		t.Fatalf("split port: %v", err)
	}
	var number int
	if _, err := fmt.Sscanf(port, "%d", &number); err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return number
}
