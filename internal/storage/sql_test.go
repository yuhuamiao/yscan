package storage

import (
	"database/sql"
	"reflect"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"golandproject/yscan/internal/model"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestInitSQLiteSchemaMigratesLegacyDatabase(t *testing.T) {
	db := openTestDB(t)
	legacySchema := []string{
		`CREATE TABLE banner (id INTEGER PRIMARY KEY, service_name TEXT NOT NULL, banner_pattern TEXT NOT NULL, description TEXT)`,
		`CREATE TABLE domain_info (id INTEGER PRIMARY KEY, domain TEXT NOT NULL, subdomain TEXT NOT NULL UNIQUE, is_wildcard INTEGER NOT NULL DEFAULT 0, title TEXT, first_seen DATETIME NOT NULL, last_scan DATETIME, source TEXT)`,
		`CREATE TABLE domain_ips (id INTEGER PRIMARY KEY, domain_id INTEGER NOT NULL, subdomain TEXT NOT NULL, ip TEXT NOT NULL, ports TEXT, UNIQUE(domain_id, ip))`,
		`CREATE TABLE host_inventory (id INTEGER PRIMARY KEY, ip TEXT NOT NULL UNIQUE, source TEXT, first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL, last_scan DATETIME, is_active INTEGER NOT NULL DEFAULT 1)`,
		`CREATE TABLE scan_results (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, port INTEGER NOT NULL, service_id INTEGER, service_type TEXT NOT NULL, scan_time DATETIME, UNIQUE(ip, port))`,
		`CREATE TABLE tasks (id INTEGER PRIMARY KEY, task_type TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL, progress INTEGER NOT NULL DEFAULT 0, error_msg TEXT, started_at DATETIME, finished_at DATETIME, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)`,
	}
	for _, statement := range legacySchema {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create legacy schema: %v", err)
		}
	}
	const (
		legacyScope = "subnet:192.168.10.0/24"
		legacyIP    = "192.168.10.10"
	)
	if _, err := db.Exec(`
		INSERT INTO host_inventory (ip, source, first_seen, last_seen, last_scan, is_active)
		VALUES (?, ?, '2026-01-01 00:00:00', '2026-02-01 00:00:00', '2026-02-02 00:00:00', 1)`, legacyIP, legacyScope); err != nil {
		t.Fatalf("seed legacy host inventory: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO scan_results (ip, port, service_type, scan_time)
		VALUES (?, 443, 'https', '2026-02-02 00:00:00')`, legacyIP); err != nil {
		t.Fatalf("seed legacy port inventory: %v", err)
	}

	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	var tableName string
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'host_inventory'`).Scan(&tableName); err != nil {
		t.Fatalf("host_inventory missing: %v", err)
	}
	if tableName != "host_inventory" {
		t.Fatalf("table name = %q", tableName)
	}
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'host_inventory_scopes'`).Scan(&tableName); err != nil {
		t.Fatalf("host_inventory_scopes missing: %v", err)
	}
	members, err := ListHostScopeMemberships(db, HostScopeMembershipQuery{Scope: legacyScope})
	if err != nil {
		t.Fatalf("list migrated scope members: %v", err)
	}
	if len(members) != 1 || members[0].IP != legacyIP || !members[0].IsActive {
		t.Fatalf("migrated members = %#v", members)
	}
	assets, err := ListHostInventory(db, HostInventoryQuery{Source: legacyScope})
	if err != nil {
		t.Fatalf("list migrated source compatibility alias: %v", err)
	}
	if len(assets) != 1 || assets[0].IP != legacyIP {
		t.Fatalf("migrated assets = %#v", assets)
	}
	ports, err := ListScopeActivePorts(db, legacyScope)
	if err != nil {
		t.Fatalf("list scope ports after migration: %v", err)
	}
	if len(ports) != 0 {
		t.Fatalf("global scan_results must not become a scope-port baseline, got %#v", ports)
	}
	taskID, err := CreateTask(db, model.TaskTypeScanIP, "192.168.10.10")
	if err != nil {
		t.Fatalf("create task after migration: %v", err)
	}
	if err := UpdateTaskReportError(db, taskID, "legacy migration check"); err != nil {
		t.Fatalf("write report error after migration: %v", err)
	}
	task, err := GetTaskByID(db, taskID)
	if err != nil {
		t.Fatalf("read task after migration: %v", err)
	}
	if task.ReportError != "legacy migration check" {
		t.Fatalf("report error after migration = %q", task.ReportError)
	}
}

func TestInitSQLiteSchemaCreatesScanTasksWithoutChangingLegacyTasks(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	legacyTaskID, err := CreateTask(db, model.TaskTypeScanIP, "192.168.10.10")
	if err != nil {
		t.Fatalf("create v1 task: %v", err)
	}
	if legacyTaskID == 0 {
		t.Fatal("v1 task ID must be assigned")
	}

	var tableName string
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'scan_tasks'`).Scan(&tableName); err != nil {
		t.Fatalf("scan_tasks table missing: %v", err)
	}
	if tableName != "scan_tasks" {
		t.Fatalf("table name = %q", tableName)
	}

	var legacyCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tasks WHERE id = ?`, legacyTaskID).Scan(&legacyCount); err != nil {
		t.Fatalf("query v1 task: %v", err)
	}
	if legacyCount != 1 {
		t.Fatalf("v1 task count = %d, want 1", legacyCount)
	}

	if _, err := db.Exec(`
		INSERT INTO scan_tasks (target, scan_type, mode, status, config_hash)
		VALUES ('192.168.10.0/24', 'subnet', 'scheduled', 'enabled', 'config-v1')`); err != nil {
		t.Fatalf("insert scan task: %v", err)
	}
}

func TestSyncAndListHostInventory(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	const source = "subnet:192.168.10.0/24"
	if err := SyncHostInventory(db, source, []string{"192.168.10.2", "192.168.10.1", "invalid", "192.168.10.1"}); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	active := true
	hosts, err := ListHostInventory(db, HostInventoryQuery{Source: source, IsActive: &active})
	if err != nil {
		t.Fatalf("list active hosts: %v", err)
	}
	if len(hosts) != 2 || hosts[0].IP != "192.168.10.1" || hosts[1].IP != "192.168.10.2" {
		t.Fatalf("active hosts = %#v", hosts)
	}
	if hosts[0].FirstSeen == "" || hosts[0].LastSeen == "" || !hosts[0].IsActive {
		t.Fatalf("unexpected host state: %#v", hosts[0])
	}

	if err := SyncHostInventory(db, source, []string{"192.168.10.2"}); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	active = false
	inactiveHosts, err := ListHostInventory(db, HostInventoryQuery{Source: source, IsActive: &active})
	if err != nil {
		t.Fatalf("list inactive hosts: %v", err)
	}
	if len(inactiveHosts) != 1 || inactiveHosts[0].IP != "192.168.10.1" || inactiveHosts[0].IsActive {
		t.Fatalf("inactive hosts = %#v", inactiveHosts)
	}
}

func TestSyncHostScopeInventoryKeepsOverlappingScopesIndependent(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	const (
		scope16 = "subnet:192.168.0.0/16"
		scope24 = "subnet:192.168.10.0/24"
		ip      = "192.168.10.10"
	)
	if err := SyncHostInventory(db, scope16, []string{ip}); err != nil {
		t.Fatalf("seed legacy inventory: %v", err)
	}
	if err := SyncHostScopeInventory(db, scope16, []string{ip}); err != nil {
		t.Fatalf("sync /16 scope: %v", err)
	}
	if err := SyncHostScopeInventory(db, scope24, []string{ip}); err != nil {
		t.Fatalf("sync /24 scope: %v", err)
	}
	if err := SyncHostScopeInventory(db, scope24, nil); err != nil {
		t.Fatalf("mark /24 scope inactive: %v", err)
	}

	active := true
	members16, err := ListHostScopeMemberships(db, HostScopeMembershipQuery{Scope: scope16, IsActive: &active})
	if err != nil {
		t.Fatalf("list /16 members: %v", err)
	}
	if len(members16) != 1 || members16[0].IP != ip || !members16[0].IsActive {
		t.Fatalf("/16 members = %#v", members16)
	}

	active = false
	members24, err := ListHostScopeMemberships(db, HostScopeMembershipQuery{Scope: scope24, IsActive: &active})
	if err != nil {
		t.Fatalf("list /24 members: %v", err)
	}
	if len(members24) != 1 || members24[0].IP != ip || members24[0].IsActive {
		t.Fatalf("/24 members = %#v", members24)
	}

	var source string
	if err := db.QueryRow(`SELECT source FROM host_inventory WHERE ip = ?`, ip).Scan(&source); err != nil {
		t.Fatalf("read legacy source: %v", err)
	}
	if source != scope16 {
		t.Fatalf("scope sync changed legacy source to %q, want %q", source, scope16)
	}
}

func TestSyncHostInventoryAggregatesOverlappingScopes(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	const (
		scope16 = "subnet:192.168.0.0/16"
		scope24 = "subnet:192.168.10.0/24"
		ip      = "192.168.10.10"
	)
	if err := SyncHostInventory(db, scope16, []string{ip}); err != nil {
		t.Fatalf("sync /16: %v", err)
	}
	if err := SyncHostInventory(db, scope24, []string{ip}); err != nil {
		t.Fatalf("sync /24: %v", err)
	}
	if err := SyncHostInventory(db, scope24, nil); err != nil {
		t.Fatalf("mark /24 inactive: %v", err)
	}

	var globalActive int
	if err := db.QueryRow(`SELECT is_active FROM host_inventory WHERE ip = ?`, ip).Scan(&globalActive); err != nil {
		t.Fatalf("read global state: %v", err)
	}
	if globalActive != 1 {
		t.Fatalf("global state = %d, want active because /16 remains active", globalActive)
	}

	if _, err := db.Exec(`
		UPDATE host_inventory_scopes
		SET first_seen = CASE scope
			WHEN ? THEN '2026-01-01 00:00:00'
			ELSE '2026-01-02 00:00:00'
		END,
		last_seen = CASE scope
			WHEN ? THEN '2026-02-01 00:00:00'
			ELSE '2026-03-01 00:00:00'
		END,
		last_checked = CASE scope
			WHEN ? THEN '2026-02-02 00:00:00'
			ELSE '2026-03-02 00:00:00'
		END
		WHERE ip = ?`, scope16, scope16, scope16, ip); err != nil {
		t.Fatalf("set membership timestamps: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin aggregate refresh: %v", err)
	}
	if err := refreshHostInventoryAggregateTx(tx, ip, scope16); err != nil {
		_ = tx.Rollback()
		t.Fatalf("refresh aggregate: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit aggregate refresh: %v", err)
	}

	var firstSeen, lastSeen string
	if err := db.QueryRow(`SELECT first_seen, last_seen FROM host_inventory WHERE ip = ?`, ip).Scan(&firstSeen, &lastSeen); err != nil {
		t.Fatalf("read aggregate timestamps: %v", err)
	}
	if firstSeen != "2026-01-01T00:00:00Z" || lastSeen != "2026-03-01T00:00:00Z" {
		t.Fatalf("aggregate timestamps = (%q, %q), want earliest and latest scope timestamps", firstSeen, lastSeen)
	}

	if err := SyncHostInventory(db, scope16, nil); err != nil {
		t.Fatalf("mark /16 inactive: %v", err)
	}
	if err := db.QueryRow(`SELECT is_active FROM host_inventory WHERE ip = ?`, ip).Scan(&globalActive); err != nil {
		t.Fatalf("read inactive global state: %v", err)
	}
	if globalActive != 0 {
		t.Fatalf("global state = %d, want inactive after every scope is inactive", globalActive)
	}
}

func TestSyncOpenPortsReplacesPreviousPortInventory(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	ip := "192.168.10.10"
	if err := SyncOpenPorts(db, ip, []model.ScanResult{
		{Address: "192.168.10.10:80", Open: true, Service: "http"},
		{Address: "192.168.10.10:443", Open: true, Service: "unknown"},
	}); err != nil {
		t.Fatalf("initial port sync: %v", err)
	}
	if err := SyncOpenPorts(db, ip, []model.ScanResult{
		{Address: "192.168.10.10:443", Open: true, Service: "https"},
	}); err != nil {
		t.Fatalf("second port sync: %v", err)
	}

	ports, err := ListOpenPortsByIP(db, ip)
	if err != nil {
		t.Fatalf("list ports: %v", err)
	}
	if want := []int{443}; !reflect.DeepEqual(ports, want) {
		t.Fatalf("ports = %v, want %v", ports, want)
	}
}

func TestScopePortInventoryKeepsOverlappingScopesIndependent(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	const (
		scope16 = "subnet:192.168.0.0/16"
		scope24 = "subnet:192.168.10.0/24"
		ip      = "192.168.10.10"
	)
	if err := SyncHostInventory(db, scope16, []string{ip}); err != nil {
		t.Fatalf("sync /16 host: %v", err)
	}
	if err := SyncHostInventory(db, scope24, []string{ip}); err != nil {
		t.Fatalf("sync /24 host: %v", err)
	}
	if err := SyncScopeOpenPorts(db, scope16, ip, []model.ScanResult{{Address: ip + ":80", Open: true, Service: "http"}}); err != nil {
		t.Fatalf("sync /16 ports: %v", err)
	}
	if err := SyncScopeOpenPorts(db, scope24, ip, []model.ScanResult{{Address: ip + ":443", Open: true, Service: "https"}}); err != nil {
		t.Fatalf("sync /24 ports: %v", err)
	}

	ports16, err := ListScopeActivePorts(db, scope16)
	if err != nil {
		t.Fatalf("list /16 ports: %v", err)
	}
	ports24, err := ListScopeActivePorts(db, scope24)
	if err != nil {
		t.Fatalf("list /24 ports: %v", err)
	}
	if want := map[string][]int{ip: {80}}; !reflect.DeepEqual(ports16, want) {
		t.Fatalf("/16 ports = %#v, want %#v", ports16, want)
	}
	if want := map[string][]int{ip: {443}}; !reflect.DeepEqual(ports24, want) {
		t.Fatalf("/24 ports = %#v, want %#v", ports24, want)
	}

	if err := SyncScopeOpenPorts(db, scope24, ip, []model.ScanResult{{Address: ip + ":8080", Open: true, Service: "http"}}); err != nil {
		t.Fatalf("resync /24 ports: %v", err)
	}
	ports16, err = ListScopeActivePorts(db, scope16)
	if err != nil {
		t.Fatalf("list unchanged /16 ports: %v", err)
	}
	ports24, err = ListScopeActivePorts(db, scope24)
	if err != nil {
		t.Fatalf("list updated /24 ports: %v", err)
	}
	if want := map[string][]int{ip: {80}}; !reflect.DeepEqual(ports16, want) {
		t.Fatalf("/16 ports changed after /24 resync: %#v", ports16)
	}
	if want := map[string][]int{ip: {8080}}; !reflect.DeepEqual(ports24, want) {
		t.Fatalf("/24 ports = %#v, want %#v", ports24, want)
	}

	if err := SyncHostInventory(db, scope24, nil); err != nil {
		t.Fatalf("mark /24 host inactive: %v", err)
	}
	if err := DeactivateScopePortsForInactiveHosts(db, scope24); err != nil {
		t.Fatalf("deactivate /24 ports: %v", err)
	}
	ports24, err = ListScopeActivePorts(db, scope24)
	if err != nil {
		t.Fatalf("list inactive /24 ports: %v", err)
	}
	if len(ports24) != 0 {
		t.Fatalf("inactive /24 ports = %#v", ports24)
	}
}

func TestSaveAndGetTaskChangeSummary(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	want := model.TaskChangeSummary{
		TaskID: 7,
		Target: "192.168.10.0/24",
		HostChanges: model.HostChanges{
			NewHosts:      []string{"192.168.10.10"},
			InactiveHosts: []string{"192.168.10.20"},
		},
		PortChanges: model.PortChanges{
			Opened: []model.PortChange{{IP: "192.168.10.10", Port: 443}},
			Closed: []model.PortChange{{IP: "192.168.10.20", Port: 80}},
		},
	}
	if err := SaveTaskChangeSummary(db, want); err != nil {
		t.Fatalf("save summary: %v", err)
	}

	got, err := GetTaskChangeSummary(db, want.TaskID)
	if err != nil {
		t.Fatalf("get summary: %v", err)
	}
	if got.GeneratedAt == "" {
		t.Fatal("summary generated time is empty")
	}
	got.GeneratedAt = ""
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summary = %#v, want %#v", got, want)
	}
}

func TestGetAssetDetail(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}
	if err := SyncHostInventory(db, "subnet:192.168.10.0/24", []string{"192.168.10.10"}); err != nil {
		t.Fatalf("sync host: %v", err)
	}
	if err := SyncOpenPorts(db, "192.168.10.10", []model.ScanResult{
		{Address: "192.168.10.10:443", Open: true, Service: "https"},
	}); err != nil {
		t.Fatalf("sync ports: %v", err)
	}

	detail, err := GetAssetDetail(db, "192.168.10.10")
	if err != nil {
		t.Fatalf("get asset detail: %v", err)
	}
	if detail.Host.IP != "192.168.10.10" || detail.Host.ScopeCount != 1 || len(detail.Scopes) != 1 || len(detail.Ports) != 1 || detail.Ports[0].Port != 443 {
		t.Fatalf("asset detail = %#v", detail)
	}
}

func TestAssetReadModelUsesScopeMemberships(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	const (
		scope16 = "subnet:192.168.0.0/16"
		scope24 = "subnet:192.168.10.0/24"
		ip      = "192.168.10.10"
	)
	if err := SyncHostInventory(db, scope16, []string{ip}); err != nil {
		t.Fatalf("sync /16: %v", err)
	}
	if err := SyncHostInventory(db, scope24, []string{ip}); err != nil {
		t.Fatalf("sync /24: %v", err)
	}
	if err := SyncHostInventory(db, scope24, nil); err != nil {
		t.Fatalf("mark /24 inactive: %v", err)
	}

	active := true
	assets, err := ListHostInventory(db, HostInventoryQuery{Scope: scope24, IsActive: &active})
	if err != nil {
		t.Fatalf("list assets by scope: %v", err)
	}
	if len(assets) != 1 || assets[0].IP != ip || !assets[0].IsActive || assets[0].ScopeCount != 2 {
		t.Fatalf("assets by scope = %#v", assets)
	}

	legacyAssets, err := ListHostInventory(db, HostInventoryQuery{Source: scope24})
	if err != nil {
		t.Fatalf("list assets by source compatibility alias: %v", err)
	}
	if len(legacyAssets) != 1 || legacyAssets[0].IP != ip {
		t.Fatalf("assets by source alias = %#v", legacyAssets)
	}

	detail, err := GetAssetDetail(db, ip)
	if err != nil {
		t.Fatalf("get asset detail: %v", err)
	}
	if detail.Host.ScopeCount != 2 || len(detail.Scopes) != 2 {
		t.Fatalf("asset scopes = %#v", detail)
	}
	if detail.Scopes[0].Scope != scope16 || !detail.Scopes[0].IsActive {
		t.Fatalf("/16 membership = %#v", detail.Scopes[0])
	}
	if detail.Scopes[1].Scope != scope24 || detail.Scopes[1].IsActive {
		t.Fatalf("/24 membership = %#v", detail.Scopes[1])
	}
}

func TestListTasksAndFindingsReturnEmptySlices(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	tasks, err := ListTasks(db)
	if err != nil {
		t.Fatalf("list tasks: %v", err)
	}
	if tasks == nil {
		t.Fatal("empty task list must be a non-nil slice")
	}

	findings, err := ListVulnerabilitiesByTask(db, 999)
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if findings == nil {
		t.Fatal("empty findings list must be a non-nil slice")
	}
}

func TestCancelTaskRequestsCancellationAndWinsAtFinalization(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	taskID, err := CreateTask(db, model.TaskTypeScanIP, "192.168.10.10")
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := UpdateTaskStatus(db, taskID, model.TaskStatusRunning, ""); err != nil {
		t.Fatalf("start task: %v", err)
	}
	if err := CancelTask(db, taskID); err != nil {
		t.Fatalf("request cancellation: %v", err)
	}

	status, err := GetTaskStatus(db, taskID)
	if err != nil {
		t.Fatalf("get cancellation request status: %v", err)
	}
	if status != model.TaskStatusCancelRequested {
		t.Fatalf("status after cancellation request = %q, want %q", status, model.TaskStatusCancelRequested)
	}
	if canceled, err := IsTaskCanceled(db, taskID); err != nil || !canceled {
		t.Fatalf("cancellation request must stop execution, canceled=%t err=%v", canceled, err)
	}

	finalStatus, err := FinalizeTask(db, taskID, nil)
	if err != nil {
		t.Fatalf("finalize successful worker result: %v", err)
	}
	if finalStatus != model.TaskStatusCanceled {
		t.Fatalf("final status = %q, want %q", finalStatus, model.TaskStatusCanceled)
	}
}

func TestFinalizeTaskSuccessCannotBeCanceledLater(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	taskID, err := CreateTask(db, model.TaskTypeScanIP, "192.168.10.10")
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := UpdateTaskStatus(db, taskID, model.TaskStatusRunning, ""); err != nil {
		t.Fatalf("start task: %v", err)
	}

	finalStatus, err := FinalizeTask(db, taskID, nil)
	if err != nil {
		t.Fatalf("finalize successful task: %v", err)
	}
	if finalStatus != model.TaskStatusSuccess {
		t.Fatalf("final status = %q, want %q", finalStatus, model.TaskStatusSuccess)
	}
	if err := CancelTask(db, taskID); err == nil {
		t.Fatal("canceling a successful task must fail")
	}

	status, err := GetTaskStatus(db, taskID)
	if err != nil {
		t.Fatalf("get final status: %v", err)
	}
	if status != model.TaskStatusSuccess {
		t.Fatalf("status after rejected cancellation = %q, want %q", status, model.TaskStatusSuccess)
	}
}

func TestUpdateTaskReportErrorPreservesTerminalTask(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	taskID, err := CreateTask(db, model.TaskTypeScanIP, "192.168.10.10")
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if err := UpdateTaskStatus(db, taskID, model.TaskStatusRunning, ""); err != nil {
		t.Fatalf("start task: %v", err)
	}
	if _, err := FinalizeTask(db, taskID, nil); err != nil {
		t.Fatalf("finalize task: %v", err)
	}
	before, err := GetTaskByID(db, taskID)
	if err != nil {
		t.Fatalf("get finalized task: %v", err)
	}

	if err := UpdateTaskReportError(db, taskID, "write report: permission denied"); err != nil {
		t.Fatalf("update report error: %v", err)
	}
	after, err := GetTaskByID(db, taskID)
	if err != nil {
		t.Fatalf("get task with report error: %v", err)
	}
	if after.Status != model.TaskStatusSuccess || after.FinishedAt != before.FinishedAt {
		t.Fatalf("report error changed terminal task: before=%#v after=%#v", before, after)
	}
	if after.ReportError != "write report: permission denied" {
		t.Fatalf("report error = %q", after.ReportError)
	}
}
