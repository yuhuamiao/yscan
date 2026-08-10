package storage

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"golandproject/yscan/internal/model"
)

func TestScanTaskLifecycleAndSchedulingBoundary(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	if _, err := CreateScanTask(db, model.ScanTask{
		Target:   "192.168.10.10",
		ScanType: model.ScanTypeIP,
		Mode:     model.ScanTaskModeOnce,
		Cron:     "0 2 * * *",
	}); err == nil {
		t.Fatal("one-time task with cron must be rejected")
	}
	if _, err := CreateScanTask(db, model.ScanTask{
		Target:   "192.168.10.10",
		ScanType: model.ScanTypeIP,
		Mode:     model.ScanTaskModeOnce,
		Status:   model.ScanTaskStatusArchived,
	}); err == nil {
		t.Fatal("task must not be created archived")
	}

	task, err := CreateScanTask(db, model.ScanTask{
		Target:   "192.168.10.0/24",
		ScanType: model.ScanTypeSubnet,
		Mode:     model.ScanTaskModeScheduled,
		Cron:     "0 2 * * *",
		Timezone: "Asia/Shanghai",
		Config:   model.ScanTaskConfig{PortSpec: "80,443"},
	})
	if err != nil {
		t.Fatalf("create scheduled task: %v", err)
	}
	if task.Status != model.ScanTaskStatusEnabled || task.ConfigHash == "" {
		t.Fatalf("created task = %#v", task)
	}

	task.Config.PortSpec = "80,443,8080"
	updated, err := UpdateScanTask(db, task)
	if err != nil {
		t.Fatalf("update scheduled task: %v", err)
	}
	if updated.Config.PortSpec != "80,443,8080" || updated.ConfigHash == task.ConfigHash {
		t.Fatalf("updated task = %#v", updated)
	}

	if err := PauseScanTask(db, task.ID); err != nil {
		t.Fatalf("pause task: %v", err)
	}
	paused, err := GetScanTask(db, task.ID)
	if err != nil {
		t.Fatalf("get paused task: %v", err)
	}
	if paused.Status != model.ScanTaskStatusPaused {
		t.Fatalf("status after pause = %q", paused.Status)
	}
	if err := ResumeScanTask(db, task.ID); err != nil {
		t.Fatalf("resume task: %v", err)
	}
	if err := ArchiveScanTask(db, task.ID); err != nil {
		t.Fatalf("archive task: %v", err)
	}
	if err := ResumeScanTask(db, task.ID); !errors.Is(err, ErrScanTaskArchived) {
		t.Fatalf("resume archived task error = %v, want ErrScanTaskArchived", err)
	}
	if _, err := UpdateScanTask(db, updated); !errors.Is(err, ErrScanTaskArchived) {
		t.Fatalf("update archived task error = %v, want ErrScanTaskArchived", err)
	}
}

func TestCompactPortSpecMigrationRepairsExistingTaskAndRunWithoutChangingHashes(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM schema_migrations WHERE name = ?`, t349CompactPortSpecMigration); err != nil {
		t.Fatal(err)
	}
	values := make([]string, 65535)
	for index := range values {
		values[index] = strconv.Itoa(index + 1)
	}
	expanded := strings.Join(values, ",")
	content, err := json.Marshal(model.ScanTaskConfig{PortSpec: expanded})
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.Exec(`INSERT INTO scan_tasks (target, scan_type, mode, status, config_json, config_hash, created_at, updated_at) VALUES ('127.0.0.1', 'ip', 'once', 'enabled', ?, 'legacy-task-hash', datetime('now'), datetime('now'))`, string(content))
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := result.LastInsertId()
	if _, err := db.Exec(`INSERT INTO scan_task_runs (scan_task_id, sequence, scheduled_for, status, trigger, stage, progress, target, scan_type, config_json, config_hash, created_at, updated_at) VALUES (?, 1, datetime('now'), 'success', 'initial', 'completed', 100, '127.0.0.1', 'ip', ?, 'legacy-run-hash', datetime('now'), datetime('now'))`, taskID, string(content)); err != nil {
		t.Fatal(err)
	}
	if err := migrateCompactScanTaskPortSpecs(db); err != nil {
		t.Fatal(err)
	}
	var taskConfig, taskHash, runConfig, runHash string
	if err := db.QueryRow(`SELECT config_json, config_hash FROM scan_tasks WHERE id = ?`, taskID).Scan(&taskConfig, &taskHash); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT config_json, config_hash FROM scan_task_runs WHERE scan_task_id = ?`, taskID).Scan(&runConfig, &runHash); err != nil {
		t.Fatal(err)
	}
	if len(taskConfig) > 512 || len(runConfig) > 512 || !strings.Contains(taskConfig, `"port_spec":"1-65535"`) || !strings.Contains(runConfig, `"port_spec":"1-65535"`) {
		t.Fatalf("configs were not compacted task_len=%d run_len=%d task=%s run=%s", len(taskConfig), len(runConfig), taskConfig, runConfig)
	}
	if taskHash != "legacy-task-hash" || runHash != "legacy-run-hash" {
		t.Fatalf("historical hashes changed task=%q run=%q", taskHash, runHash)
	}
	migratedTask, err := GetScanTask(db, taskID)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := UpdateScanTask(db, migratedTask)
	if err != nil {
		t.Fatalf("save migrated task without changes: %v", err)
	}
	if unchanged.ConfigHash != "legacy-task-hash" {
		t.Fatalf("no-op save changed migrated hash to %q", unchanged.ConfigHash)
	}
	if err := migrateCompactScanTaskPortSpecs(db); err != nil {
		t.Fatalf("idempotent migration: %v", err)
	}
}
