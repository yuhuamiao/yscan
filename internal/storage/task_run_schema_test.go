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

func TestRunLifecycleMigrationBackfillsOnceWithoutRewritingNewTriggers(t *testing.T) {
	db := openTestDB(t)
	for _, statement := range []string{
		`CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, scan_type TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL, cron TEXT, timezone TEXT, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL DEFAULT (datetime('now')), updated_at DATETIME NOT NULL DEFAULT (datetime('now')), archived_at DATETIME)`,
		`CREATE TABLE scan_task_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_task_id INTEGER NOT NULL, sequence INTEGER NOT NULL, scheduled_for DATETIME NOT NULL, status TEXT NOT NULL, target TEXT NOT NULL, scan_type TEXT NOT NULL, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', error_message TEXT, report_path TEXT, started_at DATETIME, finished_at DATETIME, created_at DATETIME NOT NULL DEFAULT (datetime('now')), updated_at DATETIME NOT NULL DEFAULT (datetime('now')), UNIQUE(scan_task_id, sequence), UNIQUE(scan_task_id, scheduled_for))`,
		`INSERT INTO scan_tasks (id, target, scan_type, mode, status) VALUES (1, '192.168.10.10', 'ip', 'once', 'enabled')`,
		`INSERT INTO scan_tasks (id, target, scan_type, mode, status, cron, timezone) VALUES (2, '192.168.10.0/24', 'subnet', 'scheduled', 'enabled', '0 2 * * *', 'UTC')`,
		`INSERT INTO scan_task_runs (id, scan_task_id, sequence, scheduled_for, status, target, scan_type) VALUES (1, 1, 1, '2026-08-01T00:00:00Z', 'queued', '192.168.10.10', 'ip')`,
		`INSERT INTO scan_task_runs (id, scan_task_id, sequence, scheduled_for, status, target, scan_type) VALUES (2, 2, 1, '2026-08-01T02:00:00Z', 'success', '192.168.10.0/24', 'subnet')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("upgrade legacy run schema: %v", err)
	}
	var onceTrigger, onceStage, scheduledTrigger, scheduledStage string
	var onceProgress, scheduledProgress int
	if err := db.QueryRow(`SELECT trigger, stage, progress FROM scan_task_runs WHERE id = 1`).Scan(&onceTrigger, &onceStage, &onceProgress); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT trigger, stage, progress FROM scan_task_runs WHERE id = 2`).Scan(&scheduledTrigger, &scheduledStage, &scheduledProgress); err != nil {
		t.Fatal(err)
	}
	if onceTrigger != "initial" || onceStage != "queued" || onceProgress != 0 || scheduledTrigger != "scheduled" || scheduledStage != "completed" || scheduledProgress != 100 {
		t.Fatalf("once=%s/%s/%d scheduled=%s/%s/%d", onceTrigger, onceStage, onceProgress, scheduledTrigger, scheduledStage, scheduledProgress)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET trigger = 'manual' WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	if err := db.QueryRow(`SELECT trigger FROM scan_task_runs WHERE id = 2`).Scan(&scheduledTrigger); err != nil || scheduledTrigger != "manual" {
		t.Fatalf("repeat migration trigger=%q err=%v", scheduledTrigger, err)
	}
}
