package storage

import (
	"database/sql"
	"errors"
	"reflect"
	"testing"

	"golandproject/yscan/internal/model"
)

func TestScanTaskRunSnapshotIsWriteOnceAndIndependentOfGlobalInventory(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}
	task := createScheduledTaskForTest(t, db, "192.168.10.0/24")
	run := createRunningTaskRun(t, db, task.ID, "2026-07-24T02:00:00Z")

	want := model.ScanTaskRunSnapshot{
		RunID: run.ID,
		Hosts: []model.ScanTaskRunHost{{
			IP:       "192.168.10.10",
			IsActive: true,
		}},
		Ports: []model.ScanTaskRunPort{{
			IP:          "192.168.10.10",
			Port:        443,
			ServiceType: "https",
			Product:     "nginx",
		}},
		Vulnerabilities: []model.ScanTaskRunVulnerability{{
			FindingKey: "CVE-2026-0001:https://192.168.10.10",
			TemplateID: "CVE-2026-0001",
			Severity:   "high",
			Target:     "https://192.168.10.10",
			TargetIP:   "192.168.10.10",
			TargetPort: 443,
		}},
	}
	if err := SaveScanTaskRunSnapshot(db, want); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	got, err := GetScanTaskRunSnapshot(db, run.ID)
	if err != nil {
		t.Fatalf("get snapshot: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot = %#v, want %#v", got, want)
	}
	if err := SaveScanTaskRunSnapshot(db, want); !errors.Is(err, ErrScanTaskRunSnapshotWritten) {
		t.Fatalf("overwrite snapshot error = %v, want ErrScanTaskRunSnapshotWritten", err)
	}

	finishedRun := createRunningTaskRun(t, db, task.ID, "2026-07-25T02:00:00Z")
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = 'success' WHERE id = ?`, finishedRun.ID); err != nil {
		t.Fatalf("finish run: %v", err)
	}
	if err := SaveScanTaskRunSnapshot(db, model.ScanTaskRunSnapshot{RunID: finishedRun.ID}); !errors.Is(err, ErrScanTaskRunSnapshotNotWritable) {
		t.Fatalf("write completed run snapshot error = %v, want ErrScanTaskRunSnapshotNotWritable", err)
	}
}

func createRunningTaskRun(t *testing.T, db *sql.DB, taskID int64, scheduledFor string) model.ScanTaskRun {
	t.Helper()
	run, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: taskID, ScheduledFor: scheduledFor})
	if err != nil {
		t.Fatalf("create scan task run: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = 'running' WHERE id = ?`, run.ID); err != nil {
		t.Fatalf("start scan task run: %v", err)
	}
	return run
}
