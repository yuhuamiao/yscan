package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"golandproject/yscan/internal/model"
	appRuntime "golandproject/yscan/internal/runtime"
	"golandproject/yscan/internal/schedule"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/workflow"
)

func TestTopLevelHelpDoesNotInitializeDatabase(t *testing.T) {
	workingDirectory := t.TempDir()
	previousDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previousDirectory) })

	if err := runMainArgs([]string{"--help"}); err != nil {
		t.Fatalf("run help: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workingDirectory, "asm.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("help initialized asm.db: %v", err)
	}
}

func TestTopLevelVersionDoesNotInitializeHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "missing-home")
	if err := runMainArgs([]string{"--home", home, "--version"}); err != nil {
		t.Fatalf("run version: %v", err)
	}
	if _, err := os.Stat(home); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("version initialized home: %v", err)
	}
}

func TestNormalizeServerCommandKeepsOneServiceEntry(t *testing.T) {
	server, deprecated := normalizeServerCommand([]string{"server", "127.0.0.1:8080"})
	if deprecated || strings.Join(server, " ") != "server 127.0.0.1:8080" {
		t.Fatalf("server normalization = %v, %t", server, deprecated)
	}
	legacy, deprecated := normalizeServerCommand([]string{"api", "127.0.0.1:9090", "--allow-cidr", "192.168.1.0/24"})
	if !deprecated || strings.Join(legacy, " ") != "server 127.0.0.1:9090 --allow-cidr 192.168.1.0/24" {
		t.Fatalf("API compatibility normalization = %v, %t", legacy, deprecated)
	}
}

func TestServerServiceLogRotationAndTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yscan.log")
	writer, err := appRuntime.OpenRotatingLogWriter(path, 1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 5; index++ {
		if _, err := writer.Write([]byte(strings.Repeat("x", 700) + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{path, path + ".1", path + ".2"} {
		if _, err := os.Stat(expected); err != nil {
			t.Fatalf("missing rotated log %s: %v", expected, err)
		}
	}
	if _, err := os.Stat(path + ".3"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unbounded rotated log remains: %v", err)
	}
	for _, bounded := range []string{path, path + ".1", path + ".2"} {
		info, err := os.Stat(bounded)
		if err != nil || info.Size() > 1024 {
			t.Fatalf("rotated log %s size=%d err=%v", bounded, info.Size(), err)
		}
	}
	if err := os.WriteFile(path, []byte("one\ntwo\nthree\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := appRuntime.PrintServerLogs(context.Background(), &output, path, 2, false); err != nil {
		t.Fatal(err)
	}
	if output.String() != "two\nthree\n" {
		t.Fatalf("tail = %q", output.String())
	}
}

func TestRunAPIAndSchedulerStopsAPIWhenSchedulerFails(t *testing.T) {
	apiStarted := make(chan struct{})
	apiStopped := make(chan struct{})
	schedulerFailure := errors.New("scheduler database failure")

	err := runAPIAndScheduler(context.Background(), func(ctx context.Context) error {
		close(apiStarted)
		<-ctx.Done()
		close(apiStopped)
		return nil
	}, func(context.Context) error {
		<-apiStarted
		return schedulerFailure
	})
	if err == nil || !strings.Contains(err.Error(), "schedule runner stopped") || !errors.Is(err, schedulerFailure) {
		t.Fatalf("service error = %v", err)
	}
	select {
	case <-apiStopped:
	default:
		t.Fatal("API component was not stopped after scheduler failure")
	}
}

func TestRecoveryCompletesBeforeAPIAndSchedulerStart(t *testing.T) {
	recoveryStarted := make(chan struct{})
	releaseRecovery := make(chan struct{})
	apiStarted := make(chan struct{})
	schedulerFailure := errors.New("stop after startup ordering check")

	result := make(chan error, 1)
	go func() {
		result <- recoverThenRunAPIAndScheduler(context.Background(), func() error {
			close(recoveryStarted)
			<-releaseRecovery
			return nil
		}, func(ctx context.Context) error {
			close(apiStarted)
			<-ctx.Done()
			return nil
		}, func(context.Context) error {
			<-apiStarted
			return schedulerFailure
		})
	}()

	<-recoveryStarted
	select {
	case <-apiStarted:
		t.Fatal("API started before startup recovery completed")
	default:
	}
	close(releaseRecovery)
	if err := <-result; err == nil || !errors.Is(err, schedulerFailure) {
		t.Fatalf("service result = %v", err)
	}
}

func TestServerShutdownDrainsAPIRequestsBeforeSchedulerStops(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	requestEntered := make(chan struct{})
	releaseRequest := make(chan struct{})
	schedulerStopped := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- runAPIAndSchedulerWithDrain(parent, func(ctx context.Context, drained func() error) error {
			close(requestEntered)
			<-ctx.Done()
			<-releaseRequest
			return drained()
		}, func(ctx context.Context) error {
			<-ctx.Done()
			close(schedulerStopped)
			return nil
		})
	}()
	<-requestEntered
	cancel()
	select {
	case <-schedulerStopped:
		t.Fatal("scheduler stopped before the entered API request drained")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseRequest)
	select {
	case <-schedulerStopped:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after API requests drained")
	}
	if err := <-result; err != nil {
		t.Fatalf("graceful service shutdown: %v", err)
	}
}

func TestRecoveredServicePreservesRunCreatedAfterAPIStarts(t *testing.T) {
	db := openLogicalScanTaskRunTestDB(t)
	oldTask, err := storage.CreateScanTask(db, model.ScanTask{
		Target: "192.168.10.20", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce,
	})
	if err != nil {
		t.Fatalf("create prior task: %v", err)
	}
	oldRun, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{
		ScanTaskID: oldTask.ID, ScheduledFor: "2026-08-10T01:00:00Z", Status: model.ScanTaskRunStatusRunning,
	})
	if err != nil {
		t.Fatalf("create prior running run: %v", err)
	}

	runner := schedule.NewRunner(db, nil)
	serviceContext, stopService := context.WithCancel(context.Background())
	defer stopService()
	type creationResult struct {
		run model.ScanTaskRun
		err error
	}
	created := make(chan creationResult, 1)
	serviceResult := make(chan error, 1)
	go func() {
		serviceResult <- recoverThenRunAPIAndScheduler(serviceContext, runner.RecoverStartupState, func(ctx context.Context) error {
			prior, err := storage.GetScanTaskRun(db, oldRun.ID)
			if err != nil {
				created <- creationResult{err: err}
				return err
			}
			if prior.Status != model.ScanTaskRunStatusFailed || prior.ErrorMessage != "interrupted by service restart" {
				err := fmt.Errorf("prior run was not recovered before API start: %#v", prior)
				created <- creationResult{err: err}
				return err
			}
			newTask, err := storage.CreateScanTask(db, model.ScanTask{
				Target: "192.168.10.21", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce,
			})
			if err != nil {
				created <- creationResult{err: err}
				return err
			}
			newRun, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{
				ScanTaskID: newTask.ID, ScheduledFor: "2026-08-10T01:01:00Z", Status: model.ScanTaskRunStatusRunning,
			})
			created <- creationResult{run: newRun, err: err}
			if err != nil {
				return err
			}
			<-ctx.Done()
			return nil
		}, runner.RunLoop)
	}()

	creation := <-created
	if creation.err != nil {
		t.Fatalf("API creation after recovery: %v", creation.err)
	}
	stopService()
	if err := <-serviceResult; err != nil {
		t.Fatalf("service shutdown: %v", err)
	}
	persisted, err := storage.GetScanTaskRun(db, creation.run.ID)
	if err != nil {
		t.Fatalf("get current-process run: %v", err)
	}
	if persisted.Status != model.ScanTaskRunStatusRunning || persisted.ErrorMessage != "" {
		t.Fatalf("current-process run was treated as restart residue: %#v", persisted)
	}
}

func TestRunAPIAndSchedulerTreatsParentCancellationAsCleanShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 2)
	result := make(chan error, 1)
	run := func(ctx context.Context) error {
		started <- struct{}{}
		<-ctx.Done()
		return nil
	}
	go func() { result <- runAPIAndScheduler(ctx, run, run) }()
	<-started
	<-started
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("clean shutdown returned error: %v", err)
	}
}

func TestCommandNeedsLegacyBannerMatcher(t *testing.T) {
	for _, command := range []string{"scan", "subnet", "status", "list", "cancel", "findings", "schedule", "fingerprint", "api", "legacy-list", "legacy-status", "legacy-findings"} {
		if commandNeedsLegacyBannerMatcher([]string{command}) {
			t.Fatalf("management command %s must not load a matcher engine", command)
		}
	}
	if commandNeedsLegacyBannerMatcher(nil) {
		t.Fatal("help mode must not load a matcher engine")
	}
}

func TestLogicalScanTaskRunExecutorRoutesIPRuns(t *testing.T) {
	originalTargetRun := runTargetTaskRun
	t.Cleanup(func() { runTargetTaskRun = originalTargetRun })
	runTargetTaskRun = func(_ context.Context, options workflow.TargetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
		if options.Run.ID != 42 || options.Network != "tcp" {
			t.Fatalf("target run options = %#v", options)
		}
		return model.ScanTaskRunSnapshot{RunID: options.Run.ID}, nil
	}

	snapshot, err := (logicalScanTaskRunExecutor{baseTask: model.Scanner{Network: "tcp"}}).Execute(context.Background(), model.ScanTaskRun{
		ID:       42,
		ScanType: model.ScanTypeIP,
	})
	if err != nil || snapshot.RunID != 42 {
		t.Fatalf("logical IP executor result = %#v, error = %v", snapshot, err)
	}
}

func TestQuickScanCreatesOnlyV2TaskRunAndSnapshot(t *testing.T) {
	db, err := storage.InitDBAt(filepath.Join(t.TempDir(), "quick-v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	originalTargetRun, originalReport := runTargetTaskRun, generateScanTaskRunReport
	t.Cleanup(func() { runTargetTaskRun, generateScanTaskRunReport = originalTargetRun, originalReport })
	runTargetTaskRun = func(_ context.Context, options workflow.TargetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
		if options.Run.Target != "127.0.0.1" || options.Run.Config.PortSpec != "80,443" {
			t.Fatalf("quick run options=%#v", options.Run)
		}
		return model.ScanTaskRunSnapshot{Hosts: []model.ScanTaskRunHost{{IP: "127.0.0.1", IsActive: true}}, Ports: []model.ScanTaskRunPort{{IP: "127.0.0.1", Port: 80, ServiceType: "http"}}}, nil
	}
	generateScanTaskRunReport = func(*sql.DB, int64, int64, string) (string, error) { return "reports/quick-v2.md", nil }
	if err := runQuickV2Scan(context.Background(), db, model.Scanner{Network: "tcp"}, "127.0.0.1", model.ScanTypeIP, false, "80,443"); err != nil {
		t.Fatalf("quick V2 scan: %v", err)
	}
	tasks, err := storage.ListScanTasks(db)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("V2 tasks=%#v err=%v", tasks, err)
	}
	runs, err := storage.ListScanTaskRuns(db, tasks[0].ID)
	if err != nil || len(runs) != 1 || runs[0].Status != model.ScanTaskRunStatusSuccess || runs[0].Progress != 100 {
		t.Fatalf("V2 runs=%#v err=%v", runs, err)
	}
	snapshot, err := storage.GetScanTaskRunSnapshot(db, runs[0].ID)
	if err != nil || len(snapshot.Ports) != 1 || snapshot.Ports[0].Port != 80 {
		t.Fatalf("V2 snapshot=%#v err=%v", snapshot, err)
	}
	legacyTasks, err := storage.ListTasks(db)
	if err != nil || len(legacyTasks) != 0 {
		t.Fatalf("legacy tasks=%#v err=%v", legacyTasks, err)
	}
}

func TestSuccessfulScanTaskRunIsNotPublishedBeforeReportFinishes(t *testing.T) {
	db, err := storage.InitDBAt(filepath.Join(t.TempDir(), "report-finalization.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service := schedule.NewTaskService(db, nil)
	task, run, err := service.Create(context.Background(), model.ScanTask{
		Target: "127.0.0.1", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce,
		Config: model.ScanTaskConfig{PortSpec: "80"},
	})
	if err != nil || run == nil {
		t.Fatalf("create task=%#v run=%#v err=%v", task, run, err)
	}
	originalTargetRun, originalReport := runTargetTaskRun, generateScanTaskRunReport
	t.Cleanup(func() { runTargetTaskRun, generateScanTaskRunReport = originalTargetRun, originalReport })
	runTargetTaskRun = func(context.Context, workflow.TargetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
		return model.ScanTaskRunSnapshot{Hosts: []model.ScanTaskRunHost{{IP: "127.0.0.1", IsActive: true}}}, nil
	}
	reportStarted := make(chan model.ScanTaskRun, 1)
	releaseReport := make(chan struct{})
	generateScanTaskRunReport = func(db *sql.DB, _, runID int64, _ string) (string, error) {
		observed, lookupErr := storage.GetScanTaskRun(db, runID)
		if lookupErr != nil {
			return "", lookupErr
		}
		reportStarted <- observed
		<-releaseReport
		return "reports/ready.md", nil
	}
	done := make(chan error, 1)
	go func() {
		done <- executeLogicalScanTaskRun(context.Background(), db, model.Scanner{Network: "tcp"}, *run)
	}()

	observed := <-reportStarted
	if observed.Status != model.ScanTaskRunStatusRunning || observed.Stage != model.ScanTaskRunStageReporting || observed.Progress != 99 || observed.FinishedAt != "" {
		t.Fatalf("run exposed before report completion: %#v", observed)
	}
	persisted, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || persisted.Status != model.ScanTaskRunStatusRunning || persisted.Stage != model.ScanTaskRunStageReporting || persisted.Progress != 99 {
		t.Fatalf("persisted reporting run=%#v err=%v", persisted, err)
	}
	close(releaseReport)
	if err := <-done; err != nil {
		t.Fatalf("finish run: %v", err)
	}
	completed, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || completed.Status != model.ScanTaskRunStatusSuccess || completed.Stage != model.ScanTaskRunStageCompleted || completed.Progress != 100 || completed.FinishedAt == "" || completed.ReportError != "" {
		t.Fatalf("completed run=%#v err=%v", completed, err)
	}
}

func TestSuccessfulScanTaskRunKeepsReportFailureDiagnosticAtFinalization(t *testing.T) {
	db, err := storage.InitDBAt(filepath.Join(t.TempDir(), "report-error-finalization.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service := schedule.NewTaskService(db, nil)
	_, run, err := service.Create(context.Background(), model.ScanTask{Target: "127.0.0.1", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce, Config: model.ScanTaskConfig{PortSpec: "80"}})
	if err != nil || run == nil {
		t.Fatalf("create run=%#v err=%v", run, err)
	}
	originalTargetRun, originalReport := runTargetTaskRun, generateScanTaskRunReport
	t.Cleanup(func() { runTargetTaskRun, generateScanTaskRunReport = originalTargetRun, originalReport })
	runTargetTaskRun = func(context.Context, workflow.TargetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
		return model.ScanTaskRunSnapshot{}, nil
	}
	generateScanTaskRunReport = func(*sql.DB, int64, int64, string) (string, error) {
		return "", errors.New("report directory is read-only")
	}
	if err := executeLogicalScanTaskRun(context.Background(), db, model.Scanner{Network: "tcp"}, *run); err != nil {
		t.Fatal(err)
	}
	completed, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || completed.Status != model.ScanTaskRunStatusSuccess || completed.Stage != model.ScanTaskRunStageCompleted || completed.Progress != 100 || completed.ReportError != "report directory is read-only" {
		t.Fatalf("completed run=%#v err=%v", completed, err)
	}
}

func TestFailedAndCanceledScanTaskRunsKeepTerminalStageWhileReportGenerates(t *testing.T) {
	tests := []struct {
		name       string
		cancelRun  bool
		wantStatus string
		wantStage  string
	}{
		{name: "failed", wantStatus: model.ScanTaskRunStatusFailed, wantStage: model.ScanTaskRunStageFailed},
		{name: "canceled", cancelRun: true, wantStatus: model.ScanTaskRunStatusCanceled, wantStage: model.ScanTaskRunStageCanceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := storage.InitDBAt(filepath.Join(t.TempDir(), "terminal-report.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			service := schedule.NewTaskService(db, nil)
			task, run, err := service.Create(context.Background(), model.ScanTask{
				Target: "127.0.0.1", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce,
				Config: model.ScanTaskConfig{PortSpec: "80"},
			})
			if err != nil || run == nil {
				t.Fatalf("create task=%#v run=%#v err=%v", task, run, err)
			}
			if tt.cancelRun {
				if err := storage.CancelScanTaskRun(db, task.ID, run.ID); err != nil {
					t.Fatal(err)
				}
			}

			originalTargetRun, originalReport := runTargetTaskRun, generateScanTaskRunReport
			t.Cleanup(func() { runTargetTaskRun, generateScanTaskRunReport = originalTargetRun, originalReport })
			runTargetTaskRun = func(context.Context, workflow.TargetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
				return model.ScanTaskRunSnapshot{}, errors.New("scan failed")
			}
			reportStarted := make(chan model.ScanTaskRun, 1)
			releaseReport := make(chan struct{})
			generateScanTaskRunReport = func(db *sql.DB, _, runID int64, _ string) (string, error) {
				observed, lookupErr := storage.GetScanTaskRun(db, runID)
				if lookupErr != nil {
					return "", lookupErr
				}
				reportStarted <- observed
				<-releaseReport
				return "reports/terminal.md", nil
			}
			done := make(chan error, 1)
			go func() {
				done <- executeLogicalScanTaskRun(context.Background(), db, model.Scanner{Network: "tcp"}, *run)
			}()

			observed := <-reportStarted
			if observed.Status != tt.wantStatus || observed.Stage != tt.wantStage || observed.Progress == 99 {
				t.Fatalf("run changed while report was pending: %#v", observed)
			}
			close(releaseReport)
			if err := <-done; err != nil {
				t.Fatalf("finish terminal report: %v", err)
			}
			completed, err := storage.GetScanTaskRun(db, run.ID)
			if err != nil || completed.Status != tt.wantStatus || completed.Stage != tt.wantStage || completed.Progress == 99 {
				t.Fatalf("terminal run=%#v err=%v", completed, err)
			}
		})
	}
}

func TestProcessTaskExecutionGeneratesReportFromFinalSnapshot(t *testing.T) {
	db := openTaskExecutionTestDB(t)
	taskID, err := storage.CreateTask(db, model.TaskTypeScanIP, "192.168.1.10")
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	restoreTaskExecutionDependencies(t)
	executeTaskForTaskExecution = func(context.Context, *sql.DB, int64, model.Scanner, string, string) error {
		return nil
	}
	var reportTask model.Task
	generateTaskReport = func(db *sql.DB, taskID int64, _ string) (string, error) {
		var err error
		reportTask, err = storage.GetTaskByID(db, taskID)
		return "reports/task-1.md", err
	}

	processTaskExecution(db, taskID, model.Scanner{}, model.TaskTypeScanIP, "192.168.1.10")
	if reportTask.Status != model.TaskStatusSuccess || reportTask.FinishedAt == "" {
		t.Fatalf("report read non-final task snapshot: %#v", reportTask)
	}

	task, err := storage.GetTaskByID(db, taskID)
	if err != nil {
		t.Fatalf("get completed task: %v", err)
	}
	if task.Status != model.TaskStatusSuccess || task.FinishedAt == "" || task.ReportError != "" {
		t.Fatalf("completed task = %#v", task)
	}
}

func TestProcessTaskExecutionKeepsSuccessWhenReportFails(t *testing.T) {
	db := openTaskExecutionTestDB(t)
	taskID, err := storage.CreateTask(db, model.TaskTypeScanIP, "192.168.1.10")
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	restoreTaskExecutionDependencies(t)
	executeTaskForTaskExecution = func(context.Context, *sql.DB, int64, model.Scanner, string, string) error {
		return nil
	}
	generateTaskReport = func(*sql.DB, int64, string) (string, error) {
		return "", errors.New("report directory is read-only")
	}

	processTaskExecution(db, taskID, model.Scanner{}, model.TaskTypeScanIP, "192.168.1.10")
	task, err := storage.GetTaskByID(db, taskID)
	if err != nil {
		t.Fatalf("get task after report failure: %v", err)
	}
	if task.Status != model.TaskStatusSuccess || task.FinishedAt == "" {
		t.Fatalf("report failure changed scan terminal state: %#v", task)
	}
	if task.ReportError != "report directory is read-only" {
		t.Fatalf("report error = %q", task.ReportError)
	}
}

func TestProcessTaskExecutionReportsFailureAndCancellationSnapshots(t *testing.T) {
	tests := []struct {
		name       string
		cancelTask bool
		wantStatus string
	}{
		{name: "failure", wantStatus: model.TaskStatusFailed},
		{name: "cancellation", cancelTask: true, wantStatus: model.TaskStatusCanceled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openTaskExecutionTestDB(t)
			taskID, err := storage.CreateTask(db, model.TaskTypeScanIP, "192.168.1.10")
			if err != nil {
				t.Fatalf("create task: %v", err)
			}
			if tt.cancelTask {
				if err := storage.CancelTask(db, taskID); err != nil {
					t.Fatalf("request cancellation: %v", err)
				}
			}

			restoreTaskExecutionDependencies(t)
			executeTaskForTaskExecution = func(context.Context, *sql.DB, int64, model.Scanner, string, string) error {
				return errors.New("scan execution failed")
			}
			var reportTask model.Task
			generateTaskReport = func(db *sql.DB, taskID int64, _ string) (string, error) {
				var err error
				reportTask, err = storage.GetTaskByID(db, taskID)
				return "reports/task-1.md", err
			}

			processTaskExecution(db, taskID, model.Scanner{}, model.TaskTypeScanIP, "192.168.1.10")
			if reportTask.Status != tt.wantStatus || reportTask.FinishedAt == "" {
				t.Fatalf("report task = %#v, want status %q with finished time", reportTask, tt.wantStatus)
			}
		})
	}
}

func TestLogicalScanTaskRunDoesNotReportWhileQueuedForGlobalSlot(t *testing.T) {
	db := openLogicalScanTaskRunTestDB(t)
	firstTask, err := storage.CreateScanTask(db, model.ScanTask{
		Target:   "192.168.80.10",
		ScanType: model.ScanTypeIP,
		Mode:     model.ScanTaskModeOnce,
	})
	if err != nil {
		t.Fatalf("create first task: %v", err)
	}
	queued, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: firstTask.ID, ScheduledFor: "2026-07-28T00:00:00Z"})
	if err != nil {
		t.Fatalf("create queued run: %v", err)
	}
	secondTask, err := storage.CreateScanTask(db, model.ScanTask{
		Target:   "192.168.80.11",
		ScanType: model.ScanTypeIP,
		Mode:     model.ScanTaskModeOnce,
	})
	if err != nil {
		t.Fatalf("create second task: %v", err)
	}
	active, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: secondTask.ID, ScheduledFor: "2026-07-28T00:01:00Z"})
	if err != nil {
		t.Fatalf("create active run: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ?, started_at = datetime('now') WHERE id = ?`, model.ScanTaskRunStatusRunning, active.ID); err != nil {
		t.Fatalf("mark active run: %v", err)
	}

	originalGenerate := generateScanTaskRunReport
	t.Cleanup(func() { generateScanTaskRunReport = originalGenerate })
	reportCalls := 0
	generateScanTaskRunReport = func(*sql.DB, int64, int64, string) (string, error) {
		reportCalls++
		return "", nil
	}

	err = executeLogicalScanTaskRun(context.Background(), db, model.Scanner{}, queued)
	if !errors.Is(err, schedule.ErrGlobalConcurrencyUnavailable) {
		t.Fatalf("execute queued run error=%v", err)
	}
	persisted, err := storage.GetScanTaskRun(db, queued.ID)
	if err != nil {
		t.Fatalf("get queued run: %v", err)
	}
	if persisted.Status != model.ScanTaskRunStatusQueued || persisted.ReportPath != "" || persisted.ReportError != "" || reportCalls != 0 {
		t.Fatalf("queued run=%#v reportCalls=%d", persisted, reportCalls)
	}
}

func TestRecoveredInterruptedRunGeneratesTerminalReport(t *testing.T) {
	db := openLogicalScanTaskRunTestDB(t)
	task, err := storage.CreateScanTask(db, model.ScanTask{Target: "192.168.80.20", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeScheduled, Cron: "0 2 * * *", Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-08-09T02:00:00Z", Trigger: model.ScanTaskRunTriggerScheduled})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ?, stage = ?, started_at = datetime('now') WHERE id = ?`, model.ScanTaskRunStatusRunning, model.ScanTaskRunStageDiscovery, run.ID); err != nil {
		t.Fatal(err)
	}
	recovered, err := storage.FinalizeInterruptedScanTaskRunsWithResult(db)
	if err != nil || len(recovered) != 1 || recovered[0].Status != model.ScanTaskRunStatusFailed {
		t.Fatalf("recovered=%#v err=%v", recovered, err)
	}
	originalReport := generateScanTaskRunReport
	t.Cleanup(func() { generateScanTaskRunReport = originalReport })
	reportCalls := 0
	generateScanTaskRunReport = func(_ *sql.DB, taskID, runID int64, _ string) (string, error) {
		reportCalls++
		if taskID != task.ID || runID != run.ID {
			t.Fatalf("report target=%d/%d", taskID, runID)
		}
		return "reports/recovered.md", nil
	}
	if err := generateRecoveredScanTaskRunReport(db, recovered[0]); err != nil || reportCalls != 1 {
		t.Fatalf("generate recovered report calls=%d err=%v", reportCalls, err)
	}
}

func restoreTaskExecutionDependencies(t *testing.T) {
	t.Helper()
	originalExecute := executeTaskForTaskExecution
	originalGenerate := generateTaskReport
	t.Cleanup(func() {
		executeTaskForTaskExecution = originalExecute
		generateTaskReport = originalGenerate
	})
}

func openTaskExecutionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Exec(`
		CREATE TABLE tasks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			task_type TEXT NOT NULL,
			target TEXT NOT NULL,
			status TEXT NOT NULL,
			progress INTEGER NOT NULL DEFAULT 0,
			error_msg TEXT,
			report_error TEXT,
			started_at DATETIME,
			finished_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`); err != nil {
		t.Fatalf("create task schema: %v", err)
	}
	return db
}

func openLogicalScanTaskRunTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, scan_type TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL, cron TEXT, timezone TEXT, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL DEFAULT (datetime('now')), updated_at DATETIME NOT NULL DEFAULT (datetime('now')), archived_at DATETIME)`,
		`CREATE TABLE scan_task_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_task_id INTEGER NOT NULL, sequence INTEGER NOT NULL, scheduled_for DATETIME NOT NULL, status TEXT NOT NULL, trigger TEXT NOT NULL DEFAULT 'scheduled', stage TEXT NOT NULL DEFAULT 'queued', progress INTEGER NOT NULL DEFAULT 0, target TEXT NOT NULL, scan_type TEXT NOT NULL, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', error_message TEXT, report_path TEXT, audit_report_path TEXT, report_error TEXT, started_at DATETIME, finished_at DATETIME, snapshot_written_at DATETIME, created_at DATETIME NOT NULL DEFAULT (datetime('now')), updated_at DATETIME NOT NULL DEFAULT (datetime('now')), UNIQUE(scan_task_id, sequence), UNIQUE(scan_task_id, scheduled_for))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create scan task run test schema: %v", err)
		}
	}
	return db
}
