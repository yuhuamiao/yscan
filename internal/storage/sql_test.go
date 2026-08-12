package storage

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestM11V2RoleMigrationIsMarkedReentrantAndRestoresFrozenRoles(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join("testdata", "m11-v2-before-t320.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(fixture)); err != nil {
		t.Fatalf("load previous M11/V2 fixture: %v", err)
	}
	if err := ensureSQLiteMigrations(db); err != nil {
		t.Fatalf("upgrade previous M11/V2 fixture: %v", err)
	}

	want := map[string][2]string{
		"nginx":   {"web_server", "web_server"},
		"openssh": {"network_service", "network_service"},
		"redis":   {"network_service", "network_service"},
	}
	for _, table := range []string{"fingerprint_rules", "asset_fingerprint_matches", "asset_fingerprint_conclusions"} {
		var rows *sql.Rows
		if table == "fingerprint_rules" {
			rows, err = db.Query(`SELECT product.canonical_name, rule.product_role, rule.exclusive_group
				FROM fingerprint_rules AS rule JOIN fingerprint_products AS product ON product.id = rule.fingerprint_product_id
				WHERE rule.fingerprint_source_rule_id BETWEEN 9400 AND 9402`)
		} else {
			rows, err = db.Query(`SELECT product_key, product_role, exclusive_group FROM ` + table + ` WHERE scan_task_run_id = 9900`)
		}
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var product, role, group string
			if err := rows.Scan(&product, &role, &group); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if expected := want[product]; role != expected[0] || group != expected[1] {
				rows.Close()
				t.Fatalf("%s %s role=%q/%q want=%q/%q", table, product, role, group, expected[0], expected[1])
			}
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	var markerCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, t320FrozenProductRolesMigration).Scan(&markerCount); err != nil || markerCount != 1 {
		t.Fatalf("migration marker count=%d err=%v", markerCount, err)
	}
	if _, err := db.Exec(`UPDATE fingerprint_rules SET product_role = 'sentinel' WHERE id = 9500`); err != nil {
		t.Fatal(err)
	}
	if err := ensureSQLiteMigrations(db); err != nil {
		t.Fatal(err)
	}
	var role string
	if err := db.QueryRow(`SELECT product_role FROM fingerprint_rules WHERE id = 9500`).Scan(&role); err != nil || role != "sentinel" {
		t.Fatalf("completed migration reran: role=%q err=%v", role, err)
	}

	newRun, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: 9800, ScheduledFor: "2026-08-02T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	var frozenCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM scan_task_run_fingerprint_imports AS frozen
		JOIN fingerprint_rules AS rule ON rule.fingerprint_source_rule_id IN
			(SELECT id FROM fingerprint_source_rules WHERE fingerprint_import_id = frozen.fingerprint_import_id)
		WHERE frozen.scan_task_run_id = ? AND frozen.fingerprint_import_id = 9200
			AND rule.product_role IN ('web_server', 'network_service', 'sentinel')`, newRun.ID).Scan(&frozenCount); err != nil || frozenCount != 3 {
		t.Fatalf("new run frozen classified rules=%d err=%v", frozenCount, err)
	}
}

func TestInitSQLiteSchemaBackfillsLayeredFingerprintConfidence(t *testing.T) {
	db := openTestDB(t)
	for _, statement := range []string{
		`CREATE TABLE asset_fingerprint_matches (
			id INTEGER PRIMARY KEY, scan_task_run_id INTEGER NOT NULL, fingerprint_import_id INTEGER NOT NULL,
			fingerprint_source_rule_id INTEGER NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL,
			product_key TEXT NOT NULL, version TEXT, cpe TEXT, tags_json TEXT NOT NULL DEFAULT '[]', is_soft INTEGER NOT NULL DEFAULT 0,
			evidence_summary TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE asset_fingerprint_conclusions (
			id INTEGER PRIMARY KEY, scan_task_run_id INTEGER NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL,
			product_key TEXT NOT NULL, version TEXT, cpe TEXT, tags_json TEXT NOT NULL DEFAULT '[]',
			conclusion_status TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(scan_task_run_id, ip, port, protocol, product_key)
		)`,
		`INSERT INTO asset_fingerprint_matches (id, scan_task_run_id, fingerprint_import_id, fingerprint_source_rule_id, ip, port, protocol, product_key, version, cpe, evidence_summary)
		 VALUES (1, 7, 10, 100, '192.168.90.1', 22, 'tcp', 'openssh', '9.6', 'cpe:/a:openbsd:openssh:9.6', 'a'),
		        (2, 7, 11, 101, '192.168.90.1', 22, 'tcp', 'openssh', NULL, NULL, 'b')`,
		`INSERT INTO asset_fingerprint_conclusions (id, scan_task_run_id, ip, port, protocol, product_key, version, cpe, conclusion_status)
		 VALUES (1, 7, '192.168.90.1', 22, 'tcp', 'openssh', '9.6', 'cpe:/a:openbsd:openssh:9.6', 'corroborated')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("migrate layered confidence: %v", err)
	}
	var productStatus, versionStatus, cpeStatus, legacyStatus string
	var productSources, versionSources, cpeSources int
	if err := db.QueryRow(`SELECT conclusion_status, product_status, product_source_count, version_status, version_source_count, cpe_status, cpe_source_count FROM asset_fingerprint_conclusions WHERE id = 1`).Scan(&legacyStatus, &productStatus, &productSources, &versionStatus, &versionSources, &cpeStatus, &cpeSources); err != nil {
		t.Fatal(err)
	}
	if legacyStatus != "corroborated" || productStatus != "corroborated" || productSources != 2 || versionStatus != "matched" || versionSources != 1 || cpeStatus != "matched" || cpeSources != 1 {
		t.Fatalf("backfilled confidence legacy=%s product=%s/%d version=%s/%d cpe=%s/%d", legacyStatus, productStatus, productSources, versionStatus, versionSources, cpeStatus, cpeSources)
	}
}

func TestInitSQLiteSchemaClearsConflictingLegacyVersionAndCPE(t *testing.T) {
	db := openTestDB(t)
	for _, statement := range []string{
		`CREATE TABLE asset_fingerprint_matches (
			id INTEGER PRIMARY KEY, scan_task_run_id INTEGER NOT NULL, fingerprint_import_id INTEGER NOT NULL,
			fingerprint_source_rule_id INTEGER NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL,
			product_key TEXT NOT NULL, version TEXT, cpe TEXT, tags_json TEXT NOT NULL DEFAULT '[]', is_soft INTEGER NOT NULL DEFAULT 0,
			evidence_summary TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE asset_fingerprint_conclusions (
			id INTEGER PRIMARY KEY, scan_task_run_id INTEGER NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL,
			product_key TEXT NOT NULL, version TEXT, cpe TEXT, tags_json TEXT NOT NULL DEFAULT '[]',
			conclusion_status TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(scan_task_run_id, ip, port, protocol, product_key)
		)`,
		`INSERT INTO asset_fingerprint_matches (id, scan_task_run_id, fingerprint_import_id, fingerprint_source_rule_id, ip, port, protocol, product_key, version, cpe, evidence_summary)
		 VALUES (1, 8, 20, 200, '192.168.90.2', 80, 'http', 'fixture', '1.0', 'cpe:/a:fixture:server:1.0', 'a'),
		        (2, 8, 21, 201, '192.168.90.2', 80, 'http', 'fixture', '2.0', 'cpe:/a:fixture:server:2.0', 'b')`,
		`INSERT INTO asset_fingerprint_conclusions (id, scan_task_run_id, ip, port, protocol, product_key, version, cpe, conclusion_status)
		 VALUES (1, 8, '192.168.90.2', 80, 'http', 'fixture', '1.0', 'cpe:/a:fixture:server:1.0', 'corroborated')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := initSQLiteSchema(db); err != nil {
		t.Fatal(err)
	}
	var version, cpe sql.NullString
	var versionStatus, cpeStatus string
	if err := db.QueryRow(`SELECT version, cpe, version_status, cpe_status FROM asset_fingerprint_conclusions WHERE id = 1`).Scan(&version, &cpe, &versionStatus, &cpeStatus); err != nil {
		t.Fatal(err)
	}
	if version.Valid || cpe.Valid || versionStatus != "conflicted" || cpeStatus != "conflicted" {
		t.Fatalf("conflicting migration version=%v cpe=%v statuses=%s/%s", version, cpe, versionStatus, cpeStatus)
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

	rows, err := db.Query(`SELECT port FROM current_port_inventory WHERE ip = ? ORDER BY port`, ip)
	if err != nil {
		t.Fatalf("list current V2 ports: %v", err)
	}
	defer rows.Close()
	var ports []int
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			t.Fatalf("scan current V2 port: %v", err)
		}
		ports = append(ports, port)
	}
	if want := []int{443}; !reflect.DeepEqual(ports, want) {
		t.Fatalf("current V2 ports = %v, want %v", ports, want)
	}
	var legacyCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM scan_results WHERE ip = ?`, ip).Scan(&legacyCount); err != nil {
		t.Fatalf("count legacy scan results: %v", err)
	}
	if legacyCount != 0 {
		t.Fatalf("V2 port sync wrote legacy scan_results rows: %d", legacyCount)
	}
}

func TestPortInventoryRespectsSelectedScanCoverage(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	const (
		ip    = "192.168.10.20"
		scope = "subnet:192.168.10.0/24"
	)
	fullResults := []model.ScanResult{
		{Address: ip + ":80", Open: true, Service: "http"},
		{Address: ip + ":32123", Open: true, Service: "unknown"},
	}
	fullCoverage := FullPortScanCoverage()
	if err := SyncOpenPorts(db, ip, fullResults, fullCoverage); err != nil {
		t.Fatalf("seed full current inventory: %v", err)
	}
	if err := SyncScopeOpenPorts(db, scope, ip, fullResults, fullCoverage); err != nil {
		t.Fatalf("seed full scope inventory: %v", err)
	}

	baselineCoverage := SelectedPortScanCoverage([]int{80, 443})
	baselineResults := []model.ScanResult{{Address: ip + ":443", Open: true, Service: "https"}}
	if err := SyncOpenPorts(db, ip, baselineResults, baselineCoverage); err != nil {
		t.Fatalf("sync selected current inventory: %v", err)
	}
	if err := SyncScopeOpenPorts(db, scope, ip, baselineResults, baselineCoverage); err != nil {
		t.Fatalf("sync selected scope inventory: %v", err)
	}
	if got, want := listCurrentPortsForTest(t, db, ip), []int{443, 32123}; !reflect.DeepEqual(got, want) {
		t.Fatalf("current ports after selected scan = %v, want %v", got, want)
	}
	scopePorts, err := ListScopeActivePorts(db, scope)
	if err != nil {
		t.Fatalf("list scope ports after selected scan: %v", err)
	}
	if want := map[string][]int{ip: {443, 32123}}; !reflect.DeepEqual(scopePorts, want) {
		t.Fatalf("scope ports after selected scan = %#v, want %#v", scopePorts, want)
	}

	if err := SyncOpenPorts(db, ip, baselineResults, fullCoverage); err != nil {
		t.Fatalf("sync full current inventory: %v", err)
	}
	if err := SyncScopeOpenPorts(db, scope, ip, baselineResults, fullCoverage); err != nil {
		t.Fatalf("sync full scope inventory: %v", err)
	}
	if got, want := listCurrentPortsForTest(t, db, ip), []int{443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("current ports after full scan = %v, want %v", got, want)
	}
	scopePorts, err = ListScopeActivePorts(db, scope)
	if err != nil {
		t.Fatalf("list scope ports after full scan: %v", err)
	}
	if want := map[string][]int{ip: {443}}; !reflect.DeepEqual(scopePorts, want) {
		t.Fatalf("scope ports after full scan = %#v, want %#v", scopePorts, want)
	}
}

func TestPortInventoryHandlesLargeCoverageWithoutSQLVariableOverflow(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	const (
		ip    = "192.168.10.22"
		scope = "subnet:192.168.10.0/24"
	)
	seed := []model.ScanResult{
		{Address: ip + ":80", Open: true, Service: "http"},
		{Address: ip + ":443", Open: true, Service: "https"},
		{Address: ip + ":55000", Open: true, Service: "unknown"},
	}
	if err := SyncOpenAndScopePorts(db, scope, ip, seed, FullPortScanCoverage()); err != nil {
		t.Fatalf("seed port inventories: %v", err)
	}

	open443 := []model.ScanResult{{Address: ip + ":443", Open: true, Service: "https"}}
	largeSelected := SelectedPortScanCoverage(portRangeForTest(50000))
	if err := SyncOpenAndScopePorts(db, scope, ip, open443, largeSelected); err != nil {
		t.Fatalf("sync inventories with 50000 selected ports: %v", err)
	}
	assertInventoryPortsForTest(t, db, scope, ip, []int{443, 55000})

	explicitFullRange := SelectedPortScanCoverage(portRangeForTest(65535))
	if err := SyncOpenAndScopePorts(db, scope, ip, open443, explicitFullRange); err != nil {
		t.Fatalf("sync inventories with explicit full range: %v", err)
	}
	assertInventoryPortsForTest(t, db, scope, ip, []int{443})

	open55000 := []model.ScanResult{{Address: ip + ":55000", Open: true, Service: "unknown"}}
	if err := SyncOpenAndScopePorts(db, scope, ip, open55000, SelectedPortScanCoverage([]int{55000})); err != nil {
		t.Fatalf("restore outside port: %v", err)
	}
	if err := SyncOpenAndScopePorts(db, scope, ip, open443, FullPortScanCoverage()); err != nil {
		t.Fatalf("sync inventories with full coverage: %v", err)
	}
	assertInventoryPortsForTest(t, db, scope, ip, []int{443})
}

func TestPortInventoryCoverageSyncRollsBackAtomically(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	const (
		ip    = "192.168.10.23"
		scope = "subnet:192.168.10.0/24"
	)
	seed := []model.ScanResult{
		{Address: ip + ":80", Open: true, Product: "http"},
		{Address: ip + ":8080", Open: true, Product: "http-alt"},
	}
	if err := SyncOpenAndScopePorts(db, scope, ip, seed, FullPortScanCoverage()); err != nil {
		t.Fatalf("seed port inventories: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TRIGGER reject_scope_port_deactivation
		BEFORE UPDATE OF is_active ON host_inventory_scope_ports
		WHEN OLD.scope = 'subnet:192.168.10.0/24' AND OLD.ip = '192.168.10.23' AND OLD.port = 8080 AND NEW.is_active = 0
		BEGIN SELECT RAISE(ABORT, 'reject scope port deactivation'); END`); err != nil {
		t.Fatalf("create scope inventory trigger: %v", err)
	}
	updated := []model.ScanResult{
		{Address: ip + ":80", Open: true, Product: "https"},
		{Address: ip + ":443", Open: true, Product: "https"},
	}
	if err := SyncOpenAndScopePorts(db, scope, ip, updated, FullPortScanCoverage()); err == nil {
		t.Fatal("combined inventory sync unexpectedly succeeded")
	}
	assertInventoryPortsForTest(t, db, scope, ip, []int{80, 8080})
	var currentService string
	if err := db.QueryRow(`SELECT service_type FROM current_port_inventory WHERE ip = ? AND port = 80`, ip).Scan(&currentService); err != nil {
		t.Fatalf("query current inventory service: %v", err)
	}
	if currentService != "http" {
		t.Fatalf("current inventory service = %q, want rolled-back value http", currentService)
	}
	var scopeService string
	if err := db.QueryRow(`SELECT service_type FROM host_inventory_scope_ports WHERE scope = ? AND ip = ? AND port = 80`, scope, ip).Scan(&scopeService); err != nil {
		t.Fatalf("query scope inventory service: %v", err)
	}
	if scopeService != "http" {
		t.Fatalf("scope inventory service = %q, want rolled-back value http", scopeService)
	}
}

func portRangeForTest(maxPort int) []int {
	ports := make([]int, maxPort)
	for index := range ports {
		ports[index] = index + 1
	}
	return ports
}

func assertInventoryPortsForTest(t *testing.T, db *sql.DB, scope, ip string, want []int) {
	t.Helper()
	if got := listCurrentPortsForTest(t, db, ip); !reflect.DeepEqual(got, want) {
		t.Fatalf("current inventory ports = %v, want %v", got, want)
	}
	scopePorts, err := ListScopeActivePorts(db, scope)
	if err != nil {
		t.Fatalf("list scope ports: %v", err)
	}
	if wantByIP := map[string][]int{ip: want}; !reflect.DeepEqual(scopePorts, wantByIP) {
		t.Fatalf("scope inventory ports = %#v, want %#v", scopePorts, wantByIP)
	}
}

func TestPortInventoryRejectsResultsOutsideDeclaredCoverage(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}
	const ip = "192.168.10.21"
	result := []model.ScanResult{{Address: ip + ":32123", Open: true, Service: "unknown"}}
	if err := SyncOpenPorts(db, ip, result, SelectedPortScanCoverage([]int{80, 443})); err == nil {
		t.Fatal("result outside selected coverage must be rejected")
	}
	if got := listCurrentPortsForTest(t, db, ip); len(got) != 0 {
		t.Fatalf("rejected result changed current inventory: %v", got)
	}
}

func listCurrentPortsForTest(t *testing.T, db *sql.DB, ip string) []int {
	t.Helper()
	rows, err := db.Query(`SELECT port FROM current_port_inventory WHERE ip = ? ORDER BY port`, ip)
	if err != nil {
		t.Fatalf("list current ports: %v", err)
	}
	defer rows.Close()
	ports := make([]int, 0)
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			t.Fatalf("scan current port: %v", err)
		}
		ports = append(ports, port)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate current ports: %v", err)
	}
	return ports
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
		{Address: "192.168.10.10:22", Open: true, Service: "openssh"},
	}); err != nil {
		t.Fatalf("sync ports: %v", err)
	}
	task := createScheduledTaskForTest(t, db, "192.168.10.0/24")
	run := createRunningTaskRun(t, db, task.ID, "2026-08-07T02:00:00Z")
	if err := SaveScanTaskRunSnapshot(db, model.ScanTaskRunSnapshot{
		RunID: run.ID,
		Ports: []model.ScanTaskRunPort{
			{IP: "192.168.10.10", Port: 22, ServiceType: "openssh", Product: "openssh"},
			{IP: "192.168.10.10", Port: 443, ServiceType: "https", Product: "nginx"},
		},
		ProtocolEvidence: []model.ScanTaskRunProtocolEvidence{
			{IP: "192.168.10.10", Port: 22, EvidenceType: model.ProtocolEvidencePassiveBanner, Protocol: "tcp", Responded: true, BannerCapturedLength: 28, BannerSHA256: strings.Repeat("a", 64)},
			{IP: "192.168.10.10", Port: 22, EvidenceType: model.ProtocolEvidenceActiveProbe, ProbeName: "GenericLines", Protocol: "tcp", Responded: true, BannerCapturedLength: 31, BannerSHA256: strings.Repeat("b", 64)},
			{IP: "192.168.10.10", Port: 22, EvidenceType: model.ProtocolEvidenceActiveProbe, ProbeName: "GetRequest", Protocol: "tcp", Responded: true, BannerCapturedLength: 35, BannerSHA256: strings.Repeat("d", 64)},
			{IP: "192.168.10.10", Port: 443, EvidenceType: model.ProtocolEvidenceWeb, Protocol: "https", Responded: true, StatusCode: 200, Server: "nginx", Title: "Console", BodyCapturedLength: 917, BodySHA256: strings.Repeat("c", 64)},
		},
		Validation: model.ScanTaskRunValidation{Status: model.ScanTaskRunValidationDisabled},
	}); err != nil {
		t.Fatalf("save protocol evidence: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = 'success', finished_at = datetime('now') WHERE id = ?`, run.ID); err != nil {
		t.Fatal(err)
	}

	detail, err := GetAssetDetail(db, "192.168.10.10")
	if err != nil {
		t.Fatalf("get asset detail: %v", err)
	}
	if detail.Host.IP != "192.168.10.10" || detail.Host.ScopeCount != 1 || len(detail.Scopes) != 1 || len(detail.Ports) != 2 {
		t.Fatalf("asset detail = %#v", detail)
	}
	ssh, web := detail.Ports[0], detail.Ports[1]
	if ssh.Port != 22 || ssh.Protocol != "tcp" || ssh.ResponseLength != 28 || len(ssh.ProtocolEvidence) != 3 || ssh.ProtocolEvidence[0].EvidenceType != model.ProtocolEvidenceActiveProbe || web.Port != 443 || web.Protocol != "https" || web.StatusCode != 200 || web.Server != "nginx" || web.ResponseLength != 917 || len(web.ProtocolEvidence) != 1 {
		t.Fatalf("asset protocol evidence ssh=%#v web=%#v", ssh, web)
	}
}

func TestGetAssetDetailKeepsEndpointProfileWithinOneRun(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}
	const ip = "192.168.10.12"
	if err := SyncHostInventory(db, "ip:"+ip, []string{ip}); err != nil {
		t.Fatalf("sync host: %v", err)
	}
	if err := SyncOpenPorts(db, ip, []model.ScanResult{{Address: ip + ":443", Open: true, Service: "https"}}); err != nil {
		t.Fatalf("sync ports: %v", err)
	}
	task := createScheduledTaskForTest(t, db, ip)

	oldRun := createRunningTaskRun(t, db, task.ID, "2026-08-07T02:00:00Z")
	if err := SaveScanTaskRunSnapshot(db, model.ScanTaskRunSnapshot{
		RunID: oldRun.ID,
		Ports: []model.ScanTaskRunPort{{IP: ip, Port: 443, ServiceType: "https", Product: "nginx"}},
		ProtocolEvidence: []model.ScanTaskRunProtocolEvidence{{
			IP: ip, Port: 443, EvidenceType: model.ProtocolEvidenceWeb, Protocol: "https", Responded: true,
			StatusCode: 200, Server: "old-nginx", Title: "Old console", BodyCapturedLength: 100,
		}},
		Validation:         model.ScanTaskRunValidation{Status: model.ScanTaskRunValidationSuccess, CandidateEndpointCount: 1, ExecutedEndpointCount: 1, TemplateCount: 1, FindingCount: 1},
		TemplateCandidates: []model.ScanTaskRunTemplateCandidate{{TemplateID: "old-template", Path: "old.yaml", Source: "fixture", Reason: "old", IP: ip, Port: 443, Protocol: "https"}},
		Vulnerabilities:    []model.ScanTaskRunVulnerability{{FindingKey: "old-finding", TemplateID: "old-template", Name: "Old finding", Severity: "low", Target: "https://" + ip + ":443", TargetIP: ip, TargetPort: 443}},
	}); err != nil {
		t.Fatalf("save old snapshot: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO asset_fingerprint_conclusions
			(scan_task_run_id, ip, port, protocol, product_key, product_role, exclusive_group, version, tags_json,
			 conclusion_status, product_status, product_source_count, version_status, version_source_count, cpe_status, cpe_source_count)
		VALUES (?, ?, 443, 'https', 'nginx', 'web_server', 'web_server', '1.20', '[]',
			'matched', 'matched', 1, 'matched', 1, 'unobserved', 0)`, oldRun.ID, ip); err != nil {
		t.Fatalf("seed old conclusion: %v", err)
	}

	newRun := createRunningTaskRun(t, db, task.ID, "2026-08-08T02:00:00Z")
	if err := SaveScanTaskRunSnapshot(db, model.ScanTaskRunSnapshot{
		RunID: newRun.ID,
		Ports: []model.ScanTaskRunPort{{IP: ip, Port: 443, ServiceType: "https", Product: "flask"}},
		ProtocolEvidence: []model.ScanTaskRunProtocolEvidence{{
			IP: ip, Port: 443, EvidenceType: model.ProtocolEvidenceWeb, Protocol: "https", Responded: true,
			StatusCode: 201, Server: "Werkzeug", Title: "New console", BodyCapturedLength: 200,
		}},
		Validation:         model.ScanTaskRunValidation{Status: model.ScanTaskRunValidationSuccess, CandidateEndpointCount: 1, ExecutedEndpointCount: 1, TemplateCount: 1, FindingCount: 1},
		TemplateCandidates: []model.ScanTaskRunTemplateCandidate{{TemplateID: "new-template", Path: "new.yaml", Source: "fixture", Reason: "new", IP: ip, Port: 443, Protocol: "https"}},
		Vulnerabilities:    []model.ScanTaskRunVulnerability{{FindingKey: "new-finding", TemplateID: "new-template", Name: "New finding", Severity: "high", Target: "https://" + ip + ":443", TargetIP: ip, TargetPort: 443}},
	}); err != nil {
		t.Fatalf("save new snapshot: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO asset_fingerprint_conclusions
			(scan_task_run_id, ip, port, protocol, product_key, product_role, exclusive_group, version, tags_json,
			 conclusion_status, product_status, product_source_count, version_status, version_source_count, cpe_status, cpe_source_count)
		VALUES (?, ?, 443, 'https', 'flask', 'framework', 'web_framework', '3.1.2', '["python"]',
			'matched', 'matched', 1, 'matched', 1, 'unobserved', 0)`, newRun.ID, ip); err != nil {
		t.Fatalf("seed new conclusion: %v", err)
	}

	detail, err := GetAssetDetail(db, ip)
	if err != nil {
		t.Fatalf("get asset detail: %v", err)
	}
	if len(detail.Ports) != 1 {
		t.Fatalf("ports = %#v", detail.Ports)
	}
	port := detail.Ports[0]
	if port.ObservationRunID != newRun.ID || port.Server != "Werkzeug" || port.StatusCode != 201 || port.Title != "New console" {
		t.Fatalf("endpoint observation mixed runs: %#v", port)
	}
	if len(port.Technologies) != 1 || port.Technologies[0].ProductKey != "flask" || port.Technologies[0].Version != "3.1.2" {
		t.Fatalf("endpoint technologies mixed runs: %#v", port.Technologies)
	}
	if port.Validation.CandidateTemplateCount != 1 || port.Validation.FindingCount != 1 || len(port.Validation.Findings) != 1 || port.Validation.Findings[0].FindingKey != "new-finding" {
		t.Fatalf("endpoint validation mixed runs: %#v", port.Validation)
	}
	encoded, err := json.Marshal(port)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "old-") || strings.Contains(string(encoded), "nginx") {
		t.Fatalf("old run leaked into endpoint profile: %s", encoded)
	}
}

func TestAssetEndpointValidationDoesNotInheritRunSuccessWithoutCandidates(t *testing.T) {
	ports := []model.AssetPort{{
		ObservationRunID: 7,
		ProtocolEvidence: []model.ScanTaskRunProtocolEvidence{{Responded: true}},
		Technologies:     []model.AssetTechnology{{ProductKey: "dropbear"}},
		Validation: model.AssetValidationSummary{
			Enabled: true, Status: model.ScanTaskRunValidationSuccess, UnmappedProducts: []string{"dropbear"},
		},
	}}
	finalizeAssetPortProfiles(ports)
	if ports[0].Validation.Status != model.ScanTaskRunValidationNoCandidates || ports[0].Validation.Reason != "mapping_missing" {
		t.Fatalf("endpoint validation=%#v", ports[0].Validation)
	}
	foundReason := false
	for _, reason := range ports[0].UnresolvedReasons {
		foundReason = foundReason || reason == "mapping_missing"
	}
	if !foundReason {
		t.Fatalf("endpoint unresolved reasons=%#v", ports[0].UnresolvedReasons)
	}
}

func TestProtocolEvidenceMigrationPreservesLegacyRowsAndAllowsMultipleProbes(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Exec(`CREATE TABLE scan_task_runs (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE scan_task_run_protocol_evidence (
		scan_task_run_id INTEGER NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL,
		responded INTEGER NOT NULL DEFAULT 0, status_code INTEGER, server TEXT, title TEXT,
		banner_captured_length INTEGER NOT NULL DEFAULT 0, banner_sha256 TEXT, banner_truncated INTEGER NOT NULL DEFAULT 0,
		header_captured_length INTEGER NOT NULL DEFAULT 0, header_sha256 TEXT, header_truncated INTEGER NOT NULL DEFAULT 0,
		body_captured_length INTEGER NOT NULL DEFAULT 0, body_sha256 TEXT, body_truncated INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (scan_task_run_id, ip, port, protocol))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO scan_task_run_protocol_evidence (scan_task_run_id, ip, port, protocol, responded, banner_captured_length, banner_sha256) VALUES (1, '192.0.2.10', 22, 'tcp', 1, 28, ?)`, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := migrateProtocolEvidenceSchema(db); err != nil {
		t.Fatalf("migrate protocol evidence: %v", err)
	}
	var evidenceType, probeName string
	if err := db.QueryRow(`SELECT evidence_type, probe_name FROM scan_task_run_protocol_evidence WHERE scan_task_run_id = 1`).Scan(&evidenceType, &probeName); err != nil || evidenceType != model.ProtocolEvidencePassiveBanner || probeName != "" {
		t.Fatalf("legacy evidence type=%q probe=%q err=%v", evidenceType, probeName, err)
	}
	for _, probe := range []string{"GenericLines", "GetRequest"} {
		if _, err := db.Exec(`INSERT INTO scan_task_run_protocol_evidence (scan_task_run_id, ip, port, evidence_type, probe_name, protocol, responded) VALUES (1, '192.0.2.10', 22, ?, ?, 'tcp', 1)`, model.ProtocolEvidenceActiveProbe, probe); err != nil {
			t.Fatalf("insert active probe %s: %v", probe, err)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM scan_task_run_protocol_evidence WHERE scan_task_run_id = 1`).Scan(&count); err != nil || count != 3 {
		t.Fatalf("protocol evidence count=%d err=%v", count, err)
	}
}

func TestMigrationBackfillsAuditReportPathForExistingRunReports(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatal(err)
	}
	task := createScheduledTaskForTest(t, db, "192.0.2.0/24")
	run := createRunningTaskRun(t, db, task.ID, "2026-08-07T03:00:00Z")
	const reportPath = "reports/scan-task-1-run-1.md"
	if _, err := db.Exec(`UPDATE scan_task_runs SET report_path = ?, audit_report_path = NULL WHERE id = ?`, reportPath, run.ID); err != nil {
		t.Fatal(err)
	}
	if err := ensureSQLiteMigrations(db); err != nil {
		t.Fatal(err)
	}
	loaded, err := GetScanTaskRun(db, run.ID)
	if err != nil || loaded.AuditReportPath != "reports/scan-task-1-run-1-audit.md" {
		t.Fatalf("audit report path=%q err=%v", loaded.AuditReportPath, err)
	}
}

func TestGetAssetDetailExcludesLegacyScanResults(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}
	const ip = "192.168.10.11"
	if err := SyncHostInventory(db, "ip:"+ip, []string{ip}); err != nil {
		t.Fatalf("sync host: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO scan_results (ip, port, service_type) VALUES (?, 9999, 'legacy')`, ip); err != nil {
		t.Fatalf("seed legacy result: %v", err)
	}
	if err := SyncOpenPorts(db, ip, []model.ScanResult{{Address: ip + ":443", Open: true, Service: "https"}}); err != nil {
		t.Fatalf("sync V2 port: %v", err)
	}
	detail, err := GetAssetDetail(db, ip)
	if err != nil {
		t.Fatalf("get asset detail: %v", err)
	}
	if len(detail.Ports) != 1 || detail.Ports[0].Port != 443 {
		t.Fatalf("asset detail included legacy ports: %#v", detail.Ports)
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
