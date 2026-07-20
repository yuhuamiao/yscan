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
	}
	for _, statement := range legacySchema {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create legacy schema: %v", err)
		}
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
	if detail.Host.IP != "192.168.10.10" || len(detail.Ports) != 1 || detail.Ports[0].Port != 443 {
		t.Fatalf("asset detail = %#v", detail)
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
