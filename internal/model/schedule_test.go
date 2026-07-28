package model

import "testing"

func TestScanTaskAndRunModelsUseSeparateStates(t *testing.T) {
	task := ScanTask{
		Target:   "192.168.10.0/24",
		ScanType: ScanTypeSubnet,
		Mode:     ScanTaskModeScheduled,
		Status:   ScanTaskStatusEnabled,
		Cron:     "0 2 * * *",
		Timezone: "Asia/Shanghai",
	}
	if !task.Valid() {
		t.Fatalf("scheduled task should be valid: %#v", task)
	}

	run := ScanTaskRun{
		ScanTaskID:   1,
		Sequence:     1,
		ScheduledFor: "2026-07-24T02:00:00Z",
		Status:       ScanTaskRunStatusQueued,
		Target:       task.Target,
		ScanType:     task.ScanType,
	}
	if !run.Valid() {
		t.Fatalf("run should be valid: %#v", run)
	}
	if IsScanTaskStatus(run.Status) || IsScanTaskRunStatus(task.Status) {
		t.Fatal("logical task and run statuses must not be interchangeable")
	}
	if !IsScanTaskRunStatus(ScanTaskRunStatusCancelRequested) {
		t.Fatal("run cancellation request must be a non-terminal run state")
	}
}

func TestScanTaskValidationRejectsIncompleteSchedule(t *testing.T) {
	task := ScanTask{
		Target:   "192.168.10.10",
		ScanType: ScanTypeIP,
		Mode:     ScanTaskModeScheduled,
		Status:   ScanTaskStatusEnabled,
		Cron:     "0 2 * * *",
	}
	if task.Valid() {
		t.Fatal("scheduled task without timezone must be invalid")
	}

	run := ScanTaskRun{
		ScanTaskID:   1,
		Sequence:     1,
		ScheduledFor: "2026-07-24T02:00:00Z",
		Status:       ScanTaskStatusEnabled,
		Target:       "192.168.10.10",
		ScanType:     ScanTypeIP,
	}
	if run.Valid() {
		t.Fatal("logical task status must be rejected as a run status")
	}
}
