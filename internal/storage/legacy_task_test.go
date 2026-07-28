package storage

import (
	"testing"

	"golandproject/yscan/internal/model"
)

func TestLegacyTaskSummariesAreReadOnlyHistoricalData(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("initSQLiteSchema: %v", err)
	}

	legacyTaskID, err := CreateTask(db, model.TaskTypeScanIP, "192.168.10.10")
	if err != nil {
		t.Fatalf("create v1 task: %v", err)
	}
	if err := UpdateTaskStatus(db, legacyTaskID, model.TaskStatusRunning, ""); err != nil {
		t.Fatalf("start v1 task: %v", err)
	}
	if _, err := FinalizeTask(db, legacyTaskID, nil); err != nil {
		t.Fatalf("finalize v1 task: %v", err)
	}

	summaries, err := ListLegacyTaskSummaries(db)
	if err != nil {
		t.Fatalf("list legacy summaries: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("legacy summary count = %d, want 1", len(summaries))
	}
	summary := summaries[0]
	if summary.LegacyTaskID != legacyTaskID || !summary.IsHistorical || summary.ExactDiffAvailable {
		t.Fatalf("legacy summary = %#v", summary)
	}

	byID, err := GetLegacyTaskSummary(db, legacyTaskID)
	if err != nil {
		t.Fatalf("get legacy summary: %v", err)
	}
	if byID != summary {
		t.Fatalf("legacy summary by ID = %#v, want %#v", byID, summary)
	}

	var newTaskCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM scan_tasks`).Scan(&newTaskCount); err != nil {
		t.Fatalf("count new scan tasks: %v", err)
	}
	if newTaskCount != 0 {
		t.Fatalf("reading v1 history must not create M10 tasks, got %d", newTaskCount)
	}
}
