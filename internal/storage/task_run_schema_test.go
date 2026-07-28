package storage

import "testing"

func TestScanTaskRunSchemaUsesScheduledForUniquenessAndRunSnapshots(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	result, err := db.Exec(`
		INSERT INTO scan_tasks (target, scan_type, mode, status, cron, timezone, config_hash)
		VALUES ('192.168.10.0/24', 'subnet', 'scheduled', 'enabled', '0 2 * * *', 'Asia/Shanghai', 'config-v1')`)
	if err != nil {
		t.Fatalf("insert scan task: %v", err)
	}
	taskID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read scan task ID: %v", err)
	}

	const scheduledFor = "2026-07-24T02:00:00Z"
	if _, err := db.Exec(`
		INSERT INTO scan_task_runs (scan_task_id, sequence, scheduled_for, status, target, scan_type, config_hash)
		VALUES (?, 1, NULL, 'queued', '192.168.10.0/24', 'subnet', 'config-v1')`, taskID); err == nil {
		t.Fatal("run without scheduled_for must be rejected")
	}
	result, err = db.Exec(`
		INSERT INTO scan_task_runs (scan_task_id, sequence, scheduled_for, status, target, scan_type, config_hash)
		VALUES (?, 1, ?, 'queued', '192.168.10.0/24', 'subnet', 'config-v1')`, taskID, scheduledFor)
	if err != nil {
		t.Fatalf("insert scan task run: %v", err)
	}
	runID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read run ID: %v", err)
	}

	if _, err := db.Exec(`
		INSERT INTO scan_task_runs (scan_task_id, sequence, scheduled_for, status, target, scan_type, config_hash)
		VALUES (?, 2, ?, 'queued', '192.168.10.0/24', 'subnet', 'config-v1')`, taskID, scheduledFor); err == nil {
		t.Fatal("duplicate (scan_task_id, scheduled_for) must be rejected")
	}

	if _, err := db.Exec(`
		INSERT INTO scan_task_run_hosts (scan_task_run_id, ip)
		VALUES (?, '192.168.10.10')`, runID); err != nil {
		t.Fatalf("insert host snapshot without global inventory: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO scan_task_run_ports (scan_task_run_id, ip, port, service_type)
		VALUES (?, '192.168.10.10', 443, 'https')`, runID); err != nil {
		t.Fatalf("insert port snapshot without global inventory: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO scan_task_run_vulnerabilities (scan_task_run_id, finding_key, template_id, target)
		VALUES (?, 'CVE-2026-0001:https://192.168.10.10', 'CVE-2026-0001', 'https://192.168.10.10')`, runID); err != nil {
		t.Fatalf("insert vulnerability snapshot without global inventory: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO scan_task_run_hosts (scan_task_run_id, ip)
		VALUES (999, '192.168.10.11')`); err == nil {
		t.Fatal("snapshot without a run must be rejected")
	}

	for _, table := range []string{"scan_task_run_hosts", "scan_task_run_ports", "scan_task_run_vulnerabilities"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE scan_task_run_id = ?`, runID).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 1 {
			t.Fatalf("%s count = %d, want 1", table, count)
		}
	}
}
