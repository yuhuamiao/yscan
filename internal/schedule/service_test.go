package schedule

import (
	"context"
	"errors"
	"testing"
	"time"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

func TestTaskServiceCreatesExactlyOneRunForOneTimeTask(t *testing.T) {
	db := openRunnerTestDB(t)
	now := time.Date(2026, time.July, 24, 2, 0, 0, 0, time.UTC)
	service := NewTaskService(db, ClockFunc(func() time.Time { return now }))

	task, run, err := service.Create(context.Background(), model.ScanTask{
		Target:   "192.168.10.10",
		ScanType: model.ScanTypeIP,
		Mode:     model.ScanTaskModeOnce,
	})
	if err != nil {
		t.Fatalf("create one-time task: %v", err)
	}
	if run == nil || run.ScanTaskID != task.ID || run.Status != model.ScanTaskRunStatusQueued || run.ScheduledFor != "2026-07-24T02:00:00Z" {
		t.Fatalf("one-time initial run = %#v", run)
	}
	if _, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-25T02:00:00Z"}); !errors.Is(err, storage.ErrOneTimeScanTaskRunExists) {
		t.Fatalf("second one-time run error = %v, want ErrOneTimeScanTaskRunExists", err)
	}
}

func TestTaskServiceCreatesScheduledTaskWithoutInitialRun(t *testing.T) {
	db := openRunnerTestDB(t)
	service := NewTaskService(db, ClockFunc(func() time.Time { return time.Date(2026, time.July, 24, 2, 0, 0, 0, time.UTC) }))

	task, run, err := service.Create(context.Background(), model.ScanTask{
		Target:   "192.168.10.0/24",
		ScanType: model.ScanTypeSubnet,
		Mode:     model.ScanTaskModeScheduled,
		Cron:     "0 2 * * *",
		Timezone: "UTC",
	})
	if err != nil {
		t.Fatalf("create scheduled task: %v", err)
	}
	if run != nil {
		t.Fatalf("scheduled task must not create an initial run, got %#v", run)
	}
	for _, scheduledFor := range []string{"2026-07-24T02:00:00Z", "2026-07-25T02:00:00Z"} {
		if _, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: scheduledFor}); err != nil {
			t.Fatalf("create scheduled run %s: %v", scheduledFor, err)
		}
	}
	runs, err := storage.ListScanTaskRuns(db, task.ID)
	if err != nil {
		t.Fatalf("list scheduled runs: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("scheduled task runs = %#v, want two", runs)
	}
}

func TestTaskServiceNormalizesSubnetAndRejectsPublicIPv4Targets(t *testing.T) {
	db := openRunnerTestDB(t)
	service := NewTaskService(db, ClockFunc(func() time.Time { return time.Date(2026, time.July, 24, 2, 0, 0, 0, time.UTC) }))
	task, _, err := service.Create(context.Background(), model.ScanTask{
		Target:   "192.168.10.12/24",
		ScanType: model.ScanTypeSubnet,
		Mode:     model.ScanTaskModeScheduled,
		Cron:     "0 2 * * *",
		Timezone: "UTC",
	})
	if err != nil || task.Target != "192.168.10.0/24" {
		t.Fatalf("normalized task = %#v, error = %v", task, err)
	}
	if _, _, err := service.Create(context.Background(), model.ScanTask{
		Target:   "8.8.8.8",
		ScanType: model.ScanTypeIP,
		Mode:     model.ScanTaskModeOnce,
	}); err == nil {
		t.Fatal("public IP task must be rejected")
	}
	loopback, _, err := service.Create(context.Background(), model.ScanTask{Target: "127.0.0.1", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce})
	if err != nil || loopback.Target != "127.0.0.1" {
		t.Fatalf("loopback acceptance task=%#v err=%v", loopback, err)
	}
	if _, _, err := service.Create(context.Background(), model.ScanTask{
		Target:   "not-an-ip",
		ScanType: model.ScanTypeIP,
		Mode:     model.ScanTaskModeOnce,
	}); err == nil {
		t.Fatal("non-IP target must be rejected")
	}
	for _, target := range []string{"169.254.1.1", "224.0.0.1", "0.0.0.0"} {
		if _, err := NormalizeInternalScanTarget(model.ScanTypeIP, target); err == nil {
			t.Fatalf("non-internal IP accepted: %s", target)
		}
	}
	for _, target := range []string{"10.0.0.0/7", "127.0.0.0/7", "192.168.0.0/15", "8.8.8.0/24"} {
		if _, err := NormalizeInternalScanTarget(model.ScanTypeSubnet, target); err == nil {
			t.Fatalf("CIDR crossing internal boundary accepted: %s", target)
		}
	}
}

func TestTaskServiceUpdatePreservesExistingRunSnapshot(t *testing.T) {
	db := openRunnerTestDB(t)
	service := NewTaskService(db, nil)
	task, _, err := service.Create(context.Background(), model.ScanTask{Target: "192.168.30.0/24", ScanType: model.ScanTypeSubnet, Mode: model.ScanTaskModeScheduled, Cron: "0 2 * * *", Timezone: "UTC", Config: model.ScanTaskConfig{PortSpec: "80"}})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	task.Target, task.Cron, task.Timezone, task.Config.PortSpec = "192.168.31.12/24", "30 3 * * *", "Asia/Shanghai", "443"
	updated, err := service.Update(context.Background(), task)
	if err != nil {
		t.Fatalf("update task: %v", err)
	}
	if updated.Target != "192.168.31.0/24" || updated.Cron != "30 3 * * *" || updated.Timezone != "Asia/Shanghai" {
		t.Fatalf("updated task = %#v", updated)
	}
	preserved, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || preserved.Target != "192.168.30.0/24" || preserved.Config.PortSpec != "80" {
		t.Fatalf("run snapshot = %#v, err=%v", preserved, err)
	}
	if _, err := service.Update(context.Background(), model.ScanTask{ID: task.ID, Target: task.Target, ScanType: task.ScanType, Mode: task.Mode, Cron: "@every 1m", Timezone: task.Timezone, Config: task.Config, Status: task.Status}); err == nil {
		t.Fatal("invalid updated cron must be rejected")
	}
}

func TestTaskServiceRejectsInvalidPortSpecOnCreateAndUpdate(t *testing.T) {
	db := openRunnerTestDB(t)
	service := NewTaskService(db, ClockFunc(func() time.Time { return time.Date(2026, 7, 24, 2, 0, 0, 0, time.UTC) }))
	if _, _, err := service.Create(context.Background(), model.ScanTask{Target: "192.168.30.10", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce, Config: model.ScanTaskConfig{PortSpec: "443-80"}}); err == nil {
		t.Fatal("invalid create port_spec was accepted")
	}
	task, _, err := service.Create(context.Background(), model.ScanTask{Target: "192.168.30.0/24", ScanType: model.ScanTypeSubnet, Mode: model.ScanTaskModeScheduled, Cron: "0 2 * * *", Timezone: "UTC", Config: model.ScanTaskConfig{PortSpec: "443,80"}})
	if err != nil || task.Config.PortSpec != "80,443" {
		t.Fatalf("created task=%#v err=%v", task, err)
	}
	task.Config.PortSpec = "invalid"
	if _, err := service.Update(context.Background(), task); err == nil {
		t.Fatal("invalid update port_spec was accepted")
	}
}

func TestTaskServiceKeepsFullPortRangeCompactInTaskAndRun(t *testing.T) {
	db := openRunnerTestDB(t)
	service := NewTaskService(db, ClockFunc(func() time.Time { return time.Date(2026, 7, 24, 2, 0, 0, 0, time.UTC) }))
	task, run, err := service.Create(context.Background(), model.ScanTask{
		Target: "192.168.30.10", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce,
		Config: model.ScanTaskConfig{PortSpec: "1-65535"},
	})
	if err != nil || run == nil {
		t.Fatalf("create task=%#v run=%#v err=%v", task, run, err)
	}
	if task.Config.PortSpec != "1-65535" || run.Config.PortSpec != "1-65535" {
		t.Fatalf("expanded port specs task=%q run=%q", task.Config.PortSpec, run.Config.PortSpec)
	}
	var taskConfigLength, runConfigLength int
	if err := db.QueryRow(`SELECT length(config_json) FROM scan_tasks WHERE id = ?`, task.ID).Scan(&taskConfigLength); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT length(config_json) FROM scan_task_runs WHERE id = ?`, run.ID).Scan(&runConfigLength); err != nil {
		t.Fatal(err)
	}
	if taskConfigLength > 512 || runConfigLength > 512 {
		t.Fatalf("compact config lengths task=%d run=%d", taskConfigLength, runConfigLength)
	}
}

func TestTaskServiceRunNowStartsInitialAndScheduledManualRuns(t *testing.T) {
	db := openRunnerTestDB(t)
	now := time.Date(2026, time.August, 9, 12, 0, 0, 123, time.UTC)
	service := NewTaskService(db, ClockFunc(func() time.Time { return now }))
	once, initial, err := service.Create(context.Background(), model.ScanTask{Target: "192.168.44.10", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce})
	if err != nil || initial == nil {
		t.Fatalf("create once task=%#v run=%#v err=%v", once, initial, err)
	}
	returned, start, err := service.RunNow(context.Background(), once.ID)
	if err != nil || !start || returned.ID != initial.ID || returned.Trigger != model.ScanTaskRunTriggerInitial {
		t.Fatalf("run initial now=%#v start=%t err=%v", returned, start, err)
	}
	scheduled, _, err := service.Create(context.Background(), model.ScanTask{Target: "192.168.45.0/24", ScanType: model.ScanTypeSubnet, Mode: model.ScanTaskModeScheduled, Cron: "0 2 * * *", Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	manual, start, err := service.RunNow(context.Background(), scheduled.ID)
	if err != nil || !start || manual.Trigger != model.ScanTaskRunTriggerManual || manual.ScheduledFor != now.Format(time.RFC3339Nano) {
		t.Fatalf("scheduled run now=%#v start=%t err=%v", manual, start, err)
	}
}
