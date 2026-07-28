package storage

import (
	"errors"
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
