package schedule

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golandproject/yscan/internal/diff"
	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/report"
	"golandproject/yscan/internal/storage"
)

func parseTaskRunIDs(args []string, usage string) (int64, int64, error) {
	if len(args) < 3 {
		return 0, 0, errors.New(usage)
	}
	taskID, err := strconv.ParseInt(strings.TrimSpace(args[1]), 10, 64)
	if err != nil || taskID <= 0 {
		return 0, 0, errors.New("invalid scan task id")
	}
	runID, err := strconv.ParseInt(strings.TrimSpace(args[2]), 10, 64)
	if err != nil || runID <= 0 {
		return 0, 0, errors.New("invalid scan task run id")
	}
	return taskID, runID, nil
}

func ownedRun(db *sql.DB, taskID, runID int64) (model.ScanTaskRun, error) {
	run, err := storage.GetScanTaskRun(db, runID)
	if err != nil {
		return model.ScanTaskRun{}, err
	}
	if run.ScanTaskID != taskID {
		return model.ScanTaskRun{}, storage.ErrScanTaskRunNotFound
	}
	return run, nil
}

func writeJSONValue(output io.Writer, value interface{}) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func writeRunDetailJSON(output io.Writer, db *sql.DB, taskID, runID int64) error {
	run, err := ownedRun(db, taskID, runID)
	if err != nil {
		return err
	}
	return writeJSONValue(output, run)
}

func runChangesCommand(output io.Writer, db *sql.DB, args []string) error {
	taskID, runID, err := parseTaskRunIDs(args, "usage: yscan schedule changes <scan_task_id> <run_id> [baseline_run_id]")
	if err != nil {
		return writeCommandError(output, err)
	}
	if _, err := ownedRun(db, taskID, runID); err != nil {
		return err
	}
	var changes model.ScanTaskRunChanges
	if len(args) >= 4 {
		baselineID, parseErr := strconv.ParseInt(strings.TrimSpace(args[3]), 10, 64)
		if parseErr != nil || baselineID <= 0 {
			return errors.New("invalid baseline run id")
		}
		changes, err = diff.CompareScanTaskRuns(db, baselineID, runID)
	} else {
		changes, err = diff.CompareRunWithPreviousSuccess(db, runID)
	}
	if err != nil {
		return err
	}
	return writeJSONValue(output, changes)
}

func runFindingsCommand(output io.Writer, db *sql.DB, args []string) error {
	taskID, runID, err := parseTaskRunIDs(args, "usage: yscan schedule findings <scan_task_id> <run_id>")
	if err != nil {
		return writeCommandError(output, err)
	}
	if _, err := ownedRun(db, taskID, runID); err != nil {
		return err
	}
	snapshot, err := storage.GetScanTaskRunSnapshot(db, runID)
	if err != nil {
		return err
	}
	return writeJSONValue(output, struct {
		Validation model.ScanTaskRunValidation           `json:"validation"`
		Endpoints  []model.ScanTaskRunEndpointValidation `json:"endpoints"`
		Findings   []model.ScanTaskRunVulnerability      `json:"findings"`
	}{snapshot.Validation, snapshot.EndpointValidations, snapshot.Vulnerabilities})
}

func runReportCommand(output io.Writer, db *sql.DB, args []string) error {
	taskID, runID, err := parseTaskRunIDs(args, "usage: yscan schedule report <scan_task_id> <run_id> [--audit]")
	if err != nil {
		return writeCommandError(output, err)
	}
	if _, err := ownedRun(db, taskID, runID); err != nil {
		return err
	}
	var content []byte
	if len(args) == 4 && args[3] == "--audit" {
		content, err = report.ReadScanTaskRunAuditReport(report.DefaultDirectory, taskID, runID)
	} else if len(args) == 3 {
		content, err = report.ReadScanTaskRunReport(report.DefaultDirectory, taskID, runID)
	} else {
		return errors.New("usage: yscan schedule report <scan_task_id> <run_id> [--audit]")
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(output, string(content))
	return err
}

func writeAssetDetailJSON(output io.Writer, db *sql.DB, rawIP string) error {
	ip, err := NormalizeInternalScanTarget(model.ScanTypeIP, rawIP)
	if err != nil {
		return err
	}
	asset, err := storage.GetAssetDetail(db, ip)
	if err != nil {
		return err
	}
	return writeJSONValue(output, asset)
}
