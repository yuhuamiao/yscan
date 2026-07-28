package report

import (
	"database/sql"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

func TestRenderMarkdownIncludesRequiredSections(t *testing.T) {
	content := RenderMarkdown(TaskReport{
		Task: model.Task{ID: 3, TaskType: model.TaskTypeScanSubnet, Target: "192.168.1.0/24", Status: model.TaskStatusSuccess},
		Changes: model.TaskChangeSummary{
			HostChanges: model.HostChanges{NewHosts: []string{"192.168.1.10"}},
			PortChanges: model.PortChanges{Opened: []model.PortChange{{IP: "192.168.1.10", Port: 443}}},
		},
		Findings:    []model.Vulnerability{{Severity: "high", TemplateID: "test-template", TargetIP: "192.168.1.10", Name: "Test Finding"}},
		GeneratedAt: time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC),
	})

	for _, section := range []string{"## Task Summary", "## Host Changes", "## Port Changes", "## Vulnerability Summary", "192.168.1.10:443", "test-template"} {
		if !strings.Contains(content, section) {
			t.Fatalf("report does not contain %q", section)
		}
	}
}

func TestWriteAndReadTaskReport(t *testing.T) {
	directory := t.TempDir()
	path, err := WriteTaskReport(directory, TaskReport{Task: model.Task{ID: 8, Target: "10.0.0.0/24"}})
	if err != nil {
		t.Fatalf("write report: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat report: %v", err)
	}
	content, err := ReadTaskReport(directory, 8)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(content), "yscan CAASM Task Report") {
		t.Fatalf("unexpected report content: %s", content)
	}
}

func TestWriteAndReadScanTaskRunReport(t *testing.T) {
	directory := t.TempDir()
	report := ScanTaskRunReport{
		Task: model.ScanTask{ID: 7, Target: "192.168.1.0/24"},
		Run:  model.ScanTaskRun{ID: 9, ScanTaskID: 7, Status: model.ScanTaskRunStatusSuccess},
	}
	if _, err := WriteScanTaskRunReport(directory, report); err != nil {
		t.Fatalf("write scan task run report: %v", err)
	}
	content, err := ReadScanTaskRunReport(directory, 7, 9)
	if err != nil {
		t.Fatalf("read scan task run report: %v", err)
	}
	if !strings.Contains(string(content), "yscan CAASM Scan Task Run Report") {
		t.Fatalf("unexpected report content: %s", content)
	}
}

func TestGenerateScanTaskRunReportUsesTaskLocalRunDiff(t *testing.T) {
	db := openRunReportDB(t)
	task, err := storage.CreateScanTask(db, model.ScanTask{
		Target:   "192.168.10.0/24",
		ScanType: model.ScanTypeSubnet,
		Mode:     model.ScanTaskModeScheduled,
		Cron:     "0 2 * * *",
		Timezone: "UTC",
	})
	if err != nil {
		t.Fatalf("create scan task: %v", err)
	}
	first := completeRunReportTest(t, db, task.ID, "2026-07-24T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.10", IsActive: true}},
		Ports: []model.ScanTaskRunPort{{IP: "192.168.10.10", Port: 80, ServiceType: "http"}},
	})
	second := completeRunReportTest(t, db, task.ID, "2026-07-25T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.10", IsActive: true}, {IP: "192.168.10.20", IsActive: true}},
		Ports: []model.ScanTaskRunPort{{IP: "192.168.10.10", Port: 443, ServiceType: "https"}},
		Vulnerabilities: []model.ScanTaskRunVulnerability{{
			FindingKey: "CVE-2026-0001|https://192.168.10.10|192.168.10.10|443",
			TemplateID: "CVE-2026-0001",
			Severity:   "high",
			Target:     "https://192.168.10.10",
			TargetIP:   "192.168.10.10",
			TargetPort: 443,
		}},
	})
	if first.ID == 0 {
		t.Fatal("first run must be created")
	}
	if err := storage.UpdateScanTaskRunReportError(db, second.ID, "previous write failed"); err != nil {
		t.Fatalf("seed report diagnostic: %v", err)
	}

	path, err := GenerateScanTaskRunReport(db, task.ID, second.ID, t.TempDir())
	if err != nil {
		t.Fatalf("generate run report: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read run report: %v", err)
	}
	for _, expected := range []string{
		"yscan CAASM Scan Task Run Report",
		"| Logical Task ID | " + strconv.FormatInt(task.ID, 10) + " |",
		"| Run ID | " + strconv.FormatInt(second.ID, 10) + " |",
		"192.168.10.20",
		"192.168.10.10:443",
		"CVE-2026-0001",
	} {
		if !strings.Contains(string(content), expected) {
			t.Fatalf("run report does not contain %q:\n%s", expected, content)
		}
	}
	persisted, err := storage.GetScanTaskRun(db, second.ID)
	if err != nil || persisted.ReportPath != path || persisted.ReportError != "" {
		t.Fatalf("persisted report = %#v, error = %v, want path %q and cleared diagnostic", persisted, err, path)
	}
}

func openRunReportDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open report SQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, scan_type TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL, cron TEXT, timezone TEXT, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, archived_at DATETIME)`,
		`CREATE TABLE scan_task_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_task_id INTEGER NOT NULL, sequence INTEGER NOT NULL, scheduled_for DATETIME NOT NULL, status TEXT NOT NULL, target TEXT NOT NULL, scan_type TEXT NOT NULL, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', error_message TEXT, report_path TEXT, report_error TEXT, started_at DATETIME, finished_at DATETIME, snapshot_written_at DATETIME, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, UNIQUE(scan_task_id, sequence), UNIQUE(scan_task_id, scheduled_for))`,
		`CREATE TABLE scan_task_run_hosts (scan_task_run_id INTEGER NOT NULL, ip TEXT NOT NULL, is_active INTEGER NOT NULL, PRIMARY KEY(scan_task_run_id, ip))`,
		`CREATE TABLE scan_task_run_ports (scan_task_run_id INTEGER NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, service_type TEXT NOT NULL, product TEXT, banner TEXT, PRIMARY KEY(scan_task_run_id, ip, port))`,
		`CREATE TABLE scan_task_run_vulnerabilities (scan_task_run_id INTEGER NOT NULL, finding_key TEXT NOT NULL, template_id TEXT, name TEXT, severity TEXT, target TEXT NOT NULL, target_ip TEXT, target_port INTEGER, matched_at TEXT, evidence TEXT, PRIMARY KEY(scan_task_run_id, finding_key))`,
		`CREATE TABLE scan_task_run_template_candidates (scan_task_run_id INTEGER NOT NULL, template_id TEXT NOT NULL, path TEXT NOT NULL, source TEXT NOT NULL, reason TEXT NOT NULL, PRIMARY KEY(scan_task_run_id, template_id, path))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create report schema: %v", err)
		}
	}
	return db
}

func completeRunReportTest(t *testing.T, db *sql.DB, taskID int64, scheduledFor string, snapshot model.ScanTaskRunSnapshot) model.ScanTaskRun {
	t.Helper()
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: taskID, ScheduledFor: scheduledFor})
	if err != nil {
		t.Fatalf("create report run: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ? WHERE id = ?`, model.ScanTaskRunStatusRunning, run.ID); err != nil {
		t.Fatalf("start report run: %v", err)
	}
	snapshot.RunID = run.ID
	if err := storage.SaveScanTaskRunSnapshot(db, snapshot); err != nil {
		t.Fatalf("save report snapshot: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ? WHERE id = ?`, model.ScanTaskRunStatusSuccess, run.ID); err != nil {
		t.Fatalf("finish report run: %v", err)
	}
	return run
}
