package storage

import (
	"database/sql"
	"errors"
	"reflect"
	"strings"
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
		ProtocolEvidence: []model.ScanTaskRunProtocolEvidence{{
			IP: "192.168.10.10", Port: 443, EvidenceType: model.ProtocolEvidenceWeb, Protocol: "https", Responded: true, Outcome: model.ProtocolProbeOutcomeResponded, StatusCode: 200,
			Server: "nginx", Title: "Admin", HeaderCapturedLength: 117, HeaderSHA256: strings.Repeat("a", 64),
			BodyCapturedLength: 917, BodySHA256: strings.Repeat("b", 64),
		}},
		Validation: model.ScanTaskRunValidation{Status: model.ScanTaskRunValidationSuccess, IdentifiedProductCount: 2, MappedProductCount: 1, UnmappedProducts: []string{"192.168.10.10:443/https product=php"}, CandidateEndpointCount: 1, ExecutedEndpointCount: 1, TemplateCount: 2, ExecutedTemplateCount: 2, FindingCount: 1, StartedAt: "2026-07-24T02:00:01Z", FinishedAt: "2026-07-24T02:00:03Z"},
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

func TestSnapshotAndFingerprintMatchesRollbackTogether(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}
	fingerprintImport, err := ImportFingerprintBatch(db, fingerprintBatchFixture("atomic", "atomic-archive", "atomic-rule"))
	if err != nil {
		t.Fatalf("import fingerprint fixture: %v", err)
	}
	var sourceRuleID int64
	if err := db.QueryRow(`SELECT id FROM fingerprint_source_rules WHERE fingerprint_import_id = ?`, fingerprintImport.ID).Scan(&sourceRuleID); err != nil {
		t.Fatalf("read source rule: %v", err)
	}
	task := createScheduledTaskForTest(t, db, "192.168.10.20")
	run := createRunningTaskRun(t, db, task.ID, "2026-07-26T02:00:00Z")
	snapshot := model.ScanTaskRunSnapshot{
		RunID: run.ID,
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.10.20", IsActive: true}},
		Ports: []model.ScanTaskRunPort{{IP: "192.168.10.20", Port: 8080, ServiceType: "http", Product: "fixture"}},
		FingerprintMatches: []model.FingerprintRunMatch{{
			FingerprintImportID: fingerprintImport.ID, FingerprintSourceRuleID: sourceRuleID,
			IP: "192.168.10.20", Port: 8080, Protocol: "http", Product: "fixture", EvidenceSummary: "http status=200",
			Evidence: []model.FingerprintMatchEvidence{{MatcherID: 999999, EvidenceType: "http_body", Target: "body", Operator: "contains", ObservedSHA256: strings.Repeat("0", 64), ObservedLength: 7, Summary: "http_body body bytes=7"}},
		}},
	}
	if err := SaveScanTaskRunSnapshot(db, snapshot); err == nil {
		t.Fatal("invalid matcher evidence must fail snapshot finalization")
	}
	for _, table := range []string{"scan_task_run_hosts", "scan_task_run_ports", "asset_fingerprint_matches", "asset_fingerprint_conclusions"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE scan_task_run_id = ?`, run.ID).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s retained %d rows after rollback", table, count)
		}
	}
	var evidenceCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM asset_fingerprint_match_evidence AS evidence JOIN asset_fingerprint_matches AS match ON match.id = evidence.asset_fingerprint_match_id WHERE match.scan_task_run_id = ?`, run.ID).Scan(&evidenceCount); err != nil || evidenceCount != 0 {
		t.Fatalf("fingerprint evidence rows after rollback = %d, err=%v", evidenceCount, err)
	}
	var written sql.NullString
	if err := db.QueryRow(`SELECT snapshot_written_at FROM scan_task_runs WHERE id = ?`, run.ID).Scan(&written); err != nil || written.Valid {
		t.Fatalf("snapshot marker survived rollback: valid=%t err=%v", written.Valid, err)
	}
}

func TestSnapshotPersistsEndpointValidationAndAllTemplateProductRelations(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatal(err)
	}
	task := createScheduledTaskForTest(t, db, "192.168.74.0/24")
	run := createRunningTaskRun(t, db, task.ID, "2026-07-27T02:00:00Z")
	snapshot := model.ScanTaskRunSnapshot{RunID: run.ID,
		EndpointValidations: []model.ScanTaskRunEndpointValidation{{IP: "192.168.74.1", Port: 443, Protocol: "https", Enabled: true, Status: model.ScanTaskRunValidationSuccess, IdentifiedProductCount: 2, MappedProductCount: 2, CandidateTemplateCount: 1, ExecutedTemplateCount: 1, UnmappedProducts: []string{}}},
		TemplateCandidates: []model.ScanTaskRunTemplateCandidate{
			{TemplateID: "fixture", Path: "fixture.yaml", ProductKey: "nginx", Source: "fingerprint_mapping", Reason: "display text", IP: "192.168.74.1", Port: 443, Protocol: "https"},
			{TemplateID: "fixture", Path: "fixture.yaml", ProductKey: "php", Source: "fingerprint_mapping", Reason: "display text", IP: "192.168.74.1", Port: 443, Protocol: "https"},
			{TemplateID: "fixture", Path: "fixture.yaml", ProductKey: "openssh", Source: "fingerprint_mapping", Reason: "display text", IP: "192.168.74.1", Port: 443, Protocol: "tcp"},
		}}
	if err := SaveScanTaskRunSnapshot(db, snapshot); err != nil {
		t.Fatal(err)
	}
	loaded, err := GetScanTaskRunSnapshot(db, run.ID)
	if err != nil || len(loaded.TemplateCandidates) != 3 || len(loaded.EndpointValidations) != 1 || loaded.EndpointValidations[0].MappedProductCount != 2 {
		t.Fatalf("loaded candidates=%#v err=%v", loaded.TemplateCandidates, err)
	}
	products := []string{loaded.TemplateCandidates[0].ProductKey, loaded.TemplateCandidates[1].ProductKey, loaded.TemplateCandidates[2].ProductKey}
	if !reflect.DeepEqual(products, []string{"nginx", "php", "openssh"}) {
		t.Fatalf("template product relations=%#v", products)
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
