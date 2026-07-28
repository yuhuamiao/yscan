package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golandproject/yscan/internal/model"
)

var (
	ErrScanTaskArchived   = errors.New("scan task is archived")
	ErrScanTaskNotEnabled = errors.New("scan task is not enabled")
)

func CreateScanTask(db *sql.DB, task model.ScanTask) (model.ScanTask, error) {
	if status := strings.TrimSpace(task.Status); status != "" && status != model.ScanTaskStatusEnabled {
		return model.ScanTask{}, errors.New("scan task must be created enabled")
	}
	prepared, configJSON, err := prepareScanTask(task, model.ScanTaskStatusEnabled)
	if err != nil {
		return model.ScanTask{}, err
	}

	result, err := db.Exec(`
		INSERT INTO scan_tasks
			(target, scan_type, mode, status, cron, timezone, config_json, config_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
		prepared.Target,
		prepared.ScanType,
		prepared.Mode,
		prepared.Status,
		nullIfEmpty(prepared.Cron),
		nullIfEmpty(prepared.Timezone),
		configJSON,
		prepared.ConfigHash,
	)
	if err != nil {
		return model.ScanTask{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return model.ScanTask{}, err
	}
	return GetScanTask(db, id)
}

func GetScanTask(db *sql.DB, taskID int64) (model.ScanTask, error) {
	return scanScanTask(db.QueryRow(`
		SELECT id, target, scan_type, mode, status, cron, timezone, config_json, config_hash, created_at, updated_at, archived_at
		FROM scan_tasks
		WHERE id = ?`, taskID))
}

func ListScanTasks(db *sql.DB) ([]model.ScanTask, error) {
	rows, err := db.Query(`
		SELECT id, target, scan_type, mode, status, cron, timezone, config_json, config_hash, created_at, updated_at, archived_at
		FROM scan_tasks
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tasks := make([]model.ScanTask, 0)
	for rows.Next() {
		task, err := scanScanTask(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tasks, nil
}

func UpdateScanTask(db *sql.DB, task model.ScanTask) (model.ScanTask, error) {
	if task.ID <= 0 {
		return model.ScanTask{}, errors.New("scan task ID is required")
	}
	current, err := GetScanTask(db, task.ID)
	if err != nil {
		return model.ScanTask{}, err
	}
	if current.Status == model.ScanTaskStatusArchived {
		return model.ScanTask{}, ErrScanTaskArchived
	}
	if task.Status != "" && task.Status != current.Status {
		return model.ScanTask{}, errors.New("use lifecycle operations to change scan task status")
	}

	prepared, configJSON, err := prepareScanTask(task, current.Status)
	if err != nil {
		return model.ScanTask{}, err
	}
	if prepared.Mode != current.Mode {
		var runCount int
		if err := db.QueryRow(`SELECT COUNT(1) FROM scan_task_runs WHERE scan_task_id = ?`, current.ID).Scan(&runCount); err != nil {
			return model.ScanTask{}, err
		}
		if runCount > 0 {
			return model.ScanTask{}, errors.New("cannot change scan task mode after runs exist")
		}
	}
	result, err := db.Exec(`
		UPDATE scan_tasks
		SET target = ?, scan_type = ?, mode = ?, cron = ?, timezone = ?, config_json = ?, config_hash = ?, updated_at = datetime('now')
		WHERE id = ? AND status = ?`,
		prepared.Target,
		prepared.ScanType,
		prepared.Mode,
		nullIfEmpty(prepared.Cron),
		nullIfEmpty(prepared.Timezone),
		configJSON,
		prepared.ConfigHash,
		prepared.ID,
		current.Status,
	)
	if err != nil {
		return model.ScanTask{}, err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return model.ScanTask{}, err
	}
	if updated == 0 {
		return model.ScanTask{}, errors.New("scan task changed concurrently")
	}
	return GetScanTask(db, prepared.ID)
}

func PauseScanTask(db *sql.DB, taskID int64) error {
	result, err := db.Exec(`
		UPDATE scan_tasks
		SET status = ?, updated_at = datetime('now')
		WHERE id = ? AND status = ?`,
		model.ScanTaskStatusPaused,
		taskID,
		model.ScanTaskStatusEnabled,
	)
	if err != nil {
		return err
	}
	return scanTaskLifecycleResult(db, taskID, result.RowsAffected, model.ScanTaskStatusPaused)
}

func ResumeScanTask(db *sql.DB, taskID int64) error {
	result, err := db.Exec(`
		UPDATE scan_tasks
		SET status = ?, updated_at = datetime('now')
		WHERE id = ? AND status = ?`,
		model.ScanTaskStatusEnabled,
		taskID,
		model.ScanTaskStatusPaused,
	)
	if err != nil {
		return err
	}
	return scanTaskLifecycleResult(db, taskID, result.RowsAffected, model.ScanTaskStatusEnabled)
}

func ArchiveScanTask(db *sql.DB, taskID int64) error {
	result, err := db.Exec(`
		UPDATE scan_tasks
		SET status = ?, archived_at = datetime('now'), updated_at = datetime('now')
		WHERE id = ? AND status IN (?, ?)`,
		model.ScanTaskStatusArchived,
		taskID,
		model.ScanTaskStatusEnabled,
		model.ScanTaskStatusPaused,
	)
	if err != nil {
		return err
	}
	return scanTaskLifecycleResult(db, taskID, result.RowsAffected, model.ScanTaskStatusArchived)
}

func scanTaskLifecycleResult(db *sql.DB, taskID int64, rowsAffected func() (int64, error), desired string) error {
	updated, err := rowsAffected()
	if err != nil {
		return err
	}
	if updated > 0 {
		return nil
	}

	task, err := GetScanTask(db, taskID)
	if err != nil {
		return err
	}
	if task.Status == desired {
		return nil
	}
	if task.Status == model.ScanTaskStatusArchived {
		return ErrScanTaskArchived
	}
	return fmt.Errorf("cannot transition scan task %d from %s to %s", taskID, task.Status, desired)
}

func prepareScanTask(task model.ScanTask, defaultStatus string) (model.ScanTask, string, error) {
	task.Target = strings.TrimSpace(task.Target)
	task.ScanType = strings.TrimSpace(task.ScanType)
	task.Mode = strings.TrimSpace(task.Mode)
	task.Status = strings.TrimSpace(task.Status)
	task.Cron = strings.TrimSpace(task.Cron)
	task.Timezone = strings.TrimSpace(task.Timezone)
	if task.Status == "" {
		task.Status = defaultStatus
	}
	if task.Mode == model.ScanTaskModeOnce && (task.Cron != "" || task.Timezone != "") {
		return model.ScanTask{}, "", errors.New("one-time scan task cannot configure cron or timezone")
	}
	if !task.Valid() {
		return model.ScanTask{}, "", errors.New("invalid scan task")
	}

	configJSON, err := json.Marshal(task.Config)
	if err != nil {
		return model.ScanTask{}, "", fmt.Errorf("marshal scan task config: %w", err)
	}
	hashSource, err := json.Marshal(struct {
		Target   string               `json:"target"`
		ScanType string               `json:"scan_type"`
		Mode     string               `json:"mode"`
		Cron     string               `json:"cron"`
		Timezone string               `json:"timezone"`
		Config   model.ScanTaskConfig `json:"config"`
	}{
		Target:   task.Target,
		ScanType: task.ScanType,
		Mode:     task.Mode,
		Cron:     task.Cron,
		Timezone: task.Timezone,
		Config:   task.Config,
	})
	if err != nil {
		return model.ScanTask{}, "", fmt.Errorf("marshal scan task hash input: %w", err)
	}
	sum := sha256.Sum256(hashSource)
	task.ConfigHash = hex.EncodeToString(sum[:])
	return task, string(configJSON), nil
}

type scanTaskScanner interface {
	Scan(dest ...interface{}) error
}

func scanScanTask(scanner scanTaskScanner) (model.ScanTask, error) {
	var task model.ScanTask
	var cron, timezone, configJSON, configHash, updatedAt, archivedAt sql.NullString
	if err := scanner.Scan(
		&task.ID,
		&task.Target,
		&task.ScanType,
		&task.Mode,
		&task.Status,
		&cron,
		&timezone,
		&configJSON,
		&configHash,
		&task.CreatedAt,
		&updatedAt,
		&archivedAt,
	); err != nil {
		return model.ScanTask{}, err
	}
	task.Cron = cron.String
	task.Timezone = timezone.String
	task.ConfigHash = configHash.String
	task.UpdatedAt = updatedAt.String
	task.ArchivedAt = archivedAt.String
	if configJSON.Valid && strings.TrimSpace(configJSON.String) != "" {
		if err := json.Unmarshal([]byte(configJSON.String), &task.Config); err != nil {
			return model.ScanTask{}, fmt.Errorf("decode scan task %d config: %w", task.ID, err)
		}
	}
	return task, nil
}

func nullIfEmpty(value string) interface{} {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
