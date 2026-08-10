package schedule

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

func TestParseCreateCLIArgs(t *testing.T) {
	task, err := ParseCreateCLIArgs([]string{
		"--target", "192.168.10.0/24",
		"--scan-type", "subnet",
		"--mode", "scheduled",
		"--cron", "0 2 * * *",
		"--timezone", "Asia/Shanghai",
		"--vuln",
		"--port-spec", "80,443",
	}, CLIConfig{NucleiTemplates: "/templates", DNSResolveMode: "internal", DNSDenyCIDRs: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatalf("parse create args: %v", err)
	}
	if task.Target != "192.168.10.0/24" || task.ScanType != model.ScanTypeSubnet || task.Mode != model.ScanTaskModeScheduled || task.Cron != "0 2 * * *" || task.Timezone != "Asia/Shanghai" {
		t.Fatalf("parsed task = %#v", task)
	}
	if !task.Config.VulnerabilityOn || task.Config.NucleiTemplates != "/templates" || task.Config.PortSpec != "80,443" || task.Config.DNSResolveMode != "internal" {
		t.Fatalf("parsed config = %#v", task.Config)
	}
}

func TestRunCLIManagesScheduledTaskLifecycle(t *testing.T) {
	db := openRunnerTestDB(t)
	output := &bytes.Buffer{}
	if err := RunCLI(context.Background(), db, []string{
		"create", "--target", "192.168.10.0/24", "--scan-type", "subnet", "--mode", "scheduled", "--cron", "0 2 * * *", "--timezone", "UTC",
	}, CLIConfig{}, nil, output); err != nil {
		t.Fatalf("create scheduled task: %v", err)
	}
	if !strings.Contains(output.String(), "ScanTask 1 created") {
		t.Fatalf("create output = %q", output.String())
	}
	output.Reset()
	if err := RunCLI(context.Background(), db, []string{"pause", "1"}, CLIConfig{}, nil, output); err != nil {
		t.Fatalf("pause task: %v", err)
	}
	if !strings.Contains(output.String(), "paused") {
		t.Fatalf("pause output = %q", output.String())
	}

	service := NewTaskService(db, ClockFunc(func() time.Time { return time.Date(2026, time.July, 24, 2, 0, 0, 0, time.UTC) }))
	if _, _, err := service.Create(context.Background(), model.ScanTask{
		Target:   "192.168.20.0/24",
		ScanType: model.ScanTypeSubnet,
		Mode:     model.ScanTaskModeScheduled,
		Cron:     "0 2 * * *",
		Timezone: "UTC",
	}); err != nil {
		t.Fatalf("create direct task for list: %v", err)
	}
	output.Reset()
	if err := RunCLI(context.Background(), db, []string{"list"}, CLIConfig{}, nil, output); err != nil {
		t.Fatalf("list tasks: %v", err)
	}
	if !strings.Contains(output.String(), "192.168.20.0/24") {
		t.Fatalf("list output = %q", output.String())
	}
}

func TestRunCLIUpdatesTaskAndDocumentsUpdateCommand(t *testing.T) {
	db := openRunnerTestDB(t)
	service := NewTaskService(db, nil)
	created, _, err := service.Create(context.Background(), model.ScanTask{
		Target:   "192.168.33.0/24",
		ScanType: model.ScanTypeSubnet,
		Mode:     model.ScanTaskModeScheduled,
		Cron:     "0 2 * * *",
		Timezone: "UTC",
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	output := &bytes.Buffer{}
	if err := RunCLI(context.Background(), db, []string{"update", strconv.FormatInt(created.ID, 10), "--target", "192.168.34.0/24", "--scan-type", "subnet", "--mode", "scheduled", "--cron", "30 3 * * *", "--timezone", "Asia/Shanghai", "--port-spec", "443"}, CLIConfig{}, nil, output); err != nil {
		t.Fatalf("update task: %v", err)
	}
	updated, err := storage.GetScanTask(db, created.ID)
	if err != nil || updated.Target != "192.168.34.0/24" || updated.Cron != "30 3 * * *" || updated.Config.PortSpec != "443" {
		t.Fatalf("updated task=%#v err=%v", updated, err)
	}
	if !strings.Contains(output.String(), "updated") {
		t.Fatalf("update output=%q", output.String())
	}
	output.Reset()
	if err := RunCLI(context.Background(), db, []string{"show", strconv.FormatInt(created.ID, 10)}, CLIConfig{}, nil, output); err != nil || !strings.Contains(output.String(), "ports=443") {
		t.Fatalf("show updated task output=%q err=%v", output.String(), err)
	}
	output.Reset()
	if err := RunCLI(context.Background(), db, nil, CLIConfig{}, nil, output); err != nil {
		t.Fatalf("usage: %v", err)
	}
	if !strings.Contains(output.String(), "schedule update") {
		t.Fatalf("usage must describe update: %q", output.String())
	}
}

func TestRunCLIKeepsOneTimeRunQueuedWhenGlobalSlotIsBusy(t *testing.T) {
	db := openRunnerTestDB(t)
	output := &bytes.Buffer{}
	err := RunCLI(context.Background(), db, []string{"create", "--target", "192.168.30.10", "--scan-type", "ip", "--mode", "once"}, CLIConfig{}, func(context.Context, model.ScanTaskRun) error { return ErrGlobalConcurrencyUnavailable }, output)
	if err != nil || !strings.Contains(output.String(), "queued: waiting for global execution slot") {
		t.Fatalf("output=%q err=%v", output.String(), err)
	}
	runs, err := storage.ListScanTaskRuns(db, 1)
	if err != nil || len(runs) != 1 || runs[0].Status != model.ScanTaskRunStatusQueued {
		t.Fatalf("queued runs=%#v err=%v", runs, err)
	}
}

func TestRunCLITriggersShowsAndCancelsV2Run(t *testing.T) {
	db := openRunnerTestDB(t)
	service := NewTaskService(db, nil)
	task, _, err := service.Create(context.Background(), model.ScanTask{Target: "192.168.44.0/24", ScanType: model.ScanTypeSubnet, Mode: model.ScanTaskModeScheduled, Cron: "0 2 * * *", Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	output := &bytes.Buffer{}
	var started model.ScanTaskRun
	if err := RunCLI(context.Background(), db, []string{"run", strconv.FormatInt(task.ID, 10)}, CLIConfig{}, func(_ context.Context, run model.ScanTaskRun) error { started = run; return nil }, output); err != nil {
		t.Fatalf("run now: %v", err)
	}
	if started.Trigger != model.ScanTaskRunTriggerManual || !strings.Contains(output.String(), `"progress": 0`) {
		t.Fatalf("started=%#v output=%s", started, output.String())
	}
	output.Reset()
	if err := RunCLI(context.Background(), db, []string{"run-show", strconv.FormatInt(task.ID, 10), strconv.FormatInt(started.ID, 10)}, CLIConfig{}, nil, output); err != nil || !strings.Contains(output.String(), `"stage": "queued"`) {
		t.Fatalf("run-show output=%s err=%v", output.String(), err)
	}
	output.Reset()
	if err := RunCLI(context.Background(), db, []string{"cancel", strconv.FormatInt(task.ID, 10), strconv.FormatInt(started.ID, 10)}, CLIConfig{}, nil, output); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	canceled, err := storage.GetScanTaskRun(db, started.ID)
	if err != nil || canceled.Status != model.ScanTaskRunStatusCancelRequested {
		t.Fatalf("canceled=%#v err=%v", canceled, err)
	}
	if err := RunCLI(context.Background(), db, []string{"unknown"}, CLIConfig{}, nil, output); err == nil {
		t.Fatal("unsupported CLI command must return a failing result")
	}
}
