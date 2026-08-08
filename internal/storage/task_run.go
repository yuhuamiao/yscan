package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golandproject/yscan/internal/model"
)

var (
	ErrScanTaskRunNotFound            = errors.New("scan task run not found")
	ErrScanTaskRunSnapshotWritten     = errors.New("scan task run snapshot already written")
	ErrScanTaskRunSnapshotUnavailable = errors.New("scan task run snapshot is unavailable")
	ErrScanTaskRunSnapshotNotWritable = errors.New("scan task run snapshot is not writable")
	ErrOneTimeScanTaskRunExists       = errors.New("one-time scan task already has a run")
	ErrScanTaskRunNotCancelable       = errors.New("scan task run cannot be canceled")
)

// CancelScanTaskRun atomically records a cancellation request only while the
// run can still be stopped. Terminal and skipped audit records are immutable.
func CancelScanTaskRun(db *sql.DB, scanTaskID, runID int64) error {
	result, err := db.Exec(`UPDATE scan_task_runs SET status = ?, updated_at = datetime('now') WHERE id = ? AND scan_task_id = ? AND status IN (?, ?)`, model.ScanTaskRunStatusCancelRequested, runID, scanTaskID, model.ScanTaskRunStatusQueued, model.ScanTaskRunStatusRunning)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 1 {
		return nil
	}
	var exists int
	if err := db.QueryRow(`SELECT 1 FROM scan_task_runs WHERE id = ? AND scan_task_id = ?`, runID, scanTaskID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return ErrScanTaskRunNotFound
	} else if err != nil {
		return err
	}
	return ErrScanTaskRunNotCancelable
}

// FinalizeQueuedCancellation turns an accepted request for work that never
// started into its terminal audit state.
func FinalizeQueuedCancellation(db *sql.DB) error {
	_, err := db.Exec(`UPDATE scan_task_runs SET status = ?, error_message = ?, finished_at = datetime('now'), updated_at = datetime('now') WHERE status = ? AND started_at IS NULL`, model.ScanTaskRunStatusCanceled, "canceled by request", model.ScanTaskRunStatusCancelRequested)
	return err
}

// FinalizeInterruptedScanTaskRuns is called once when the single-process
// scheduler starts. No in-memory worker survives a process restart, so active
// rows from a prior process must not retain the global execution slot.
func FinalizeInterruptedScanTaskRuns(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`UPDATE scan_task_runs SET status = ?, error_message = ?, finished_at = datetime('now'), updated_at = datetime('now') WHERE status = ?`, model.ScanTaskRunStatusCanceled, "canceled during service restart", model.ScanTaskRunStatusCancelRequested); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE scan_task_runs SET status = ?, error_message = ?, finished_at = datetime('now'), updated_at = datetime('now') WHERE status = ?`, model.ScanTaskRunStatusFailed, "interrupted by service restart", model.ScanTaskRunStatusRunning); err != nil {
		return err
	}
	if _, err := tx.Exec(`
		UPDATE scan_task_runs
		SET status = ?, error_message = ?, finished_at = datetime('now'), updated_at = datetime('now')
		WHERE status = ?
			AND scan_task_id IN (SELECT id FROM scan_tasks WHERE mode = ?)`,
		model.ScanTaskRunStatusSkippedMisfire, "skipped because service restarted before execution", model.ScanTaskRunStatusQueued, model.ScanTaskModeScheduled,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// ExpiredScanTaskRun is a terminal run eligible for retention cleanup. The
// report path is returned separately so filesystem cleanup can be coordinated
// by the scheduling layer without coupling storage to report generation.
type ExpiredScanTaskRun struct {
	ID              int64
	ReportPath      string
	AuditReportPath string
}

func CreateScanTaskRun(db *sql.DB, run model.ScanTaskRun) (model.ScanTaskRun, error) {
	if run.ScanTaskID <= 0 {
		return model.ScanTaskRun{}, errors.New("scan task ID is required")
	}
	scheduledFor, err := normalizeScheduledFor(run.ScheduledFor)
	if err != nil {
		return model.ScanTaskRun{}, err
	}
	run.Status = strings.TrimSpace(run.Status)
	if run.Status == "" {
		run.Status = model.ScanTaskRunStatusQueued
	}
	if !model.IsScanTaskRunStatus(run.Status) {
		return model.ScanTaskRun{}, fmt.Errorf("invalid scan task run status: %s", run.Status)
	}

	tx, err := db.Begin()
	if err != nil {
		return model.ScanTaskRun{}, err
	}
	defer func() { _ = tx.Rollback() }()

	task, err := scanScanTask(tx.QueryRow(`
		SELECT id, target, scan_type, mode, status, cron, timezone, config_json, config_hash, created_at, updated_at, archived_at
		FROM scan_tasks
		WHERE id = ?`, run.ScanTaskID))
	if err != nil {
		return model.ScanTaskRun{}, err
	}
	if task.Status != model.ScanTaskStatusEnabled {
		return model.ScanTaskRun{}, fmt.Errorf("%w: %s", ErrScanTaskNotEnabled, task.Status)
	}
	if task.Mode == model.ScanTaskModeOnce {
		var existingRuns int
		if err := tx.QueryRow(`SELECT COUNT(1) FROM scan_task_runs WHERE scan_task_id = ?`, run.ScanTaskID).Scan(&existingRuns); err != nil {
			return model.ScanTaskRun{}, err
		}
		if existingRuns > 0 {
			return model.ScanTaskRun{}, ErrOneTimeScanTaskRunExists
		}
	}

	if err := tx.QueryRow(`SELECT COALESCE(MAX(sequence), 0) + 1 FROM scan_task_runs WHERE scan_task_id = ?`, run.ScanTaskID).Scan(&run.Sequence); err != nil {
		return model.ScanTaskRun{}, err
	}
	configJSON, err := json.Marshal(task.Config)
	if err != nil {
		return model.ScanTaskRun{}, fmt.Errorf("marshal run config snapshot: %w", err)
	}
	run.ScheduledFor = scheduledFor
	run.Target = task.Target
	run.ScanType = task.ScanType
	run.Config = task.Config
	run.ConfigHash = task.ConfigHash
	if !run.Valid() {
		return model.ScanTaskRun{}, errors.New("invalid scan task run")
	}

	result, err := tx.Exec(`
		INSERT INTO scan_task_runs
			(scan_task_id, sequence, scheduled_for, status, target, scan_type, config_json, config_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))`,
		run.ScanTaskID,
		run.Sequence,
		run.ScheduledFor,
		run.Status,
		run.Target,
		run.ScanType,
		string(configJSON),
		run.ConfigHash,
	)
	if err != nil {
		return model.ScanTaskRun{}, err
	}
	run.ID, err = result.LastInsertId()
	if err != nil {
		return model.ScanTaskRun{}, err
	}
	if err := FreezeActiveFingerprintImportsTx(tx, run.ID); err != nil {
		return model.ScanTaskRun{}, fmt.Errorf("freeze active fingerprint imports: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return model.ScanTaskRun{}, err
	}
	return GetScanTaskRun(db, run.ID)
}

func GetScanTaskRun(db *sql.DB, runID int64) (model.ScanTaskRun, error) {
	run, err := scanScanTaskRun(db.QueryRow(scanTaskRunSelect+` WHERE id = ?`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return model.ScanTaskRun{}, ErrScanTaskRunNotFound
	}
	return run, err
}

func ListScanTaskRuns(db *sql.DB, scanTaskID int64) ([]model.ScanTaskRun, error) {
	rows, err := db.Query(scanTaskRunSelect+` WHERE scan_task_id = ? ORDER BY sequence ASC`, scanTaskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	runs := make([]model.ScanTaskRun, 0)
	for rows.Next() {
		run, err := scanScanTaskRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return runs, nil
}

// ClaimQueuedOneTimeScanTaskRun recovers one persisted once run after a
// process restart. The queued -> running transition is the claim token, so
// competing schedulers cannot execute the same recovered run.
func ClaimQueuedOneTimeScanTaskRun(db *sql.DB) (*model.ScanTaskRun, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var runID int64
	err = tx.QueryRow(`
		SELECT run.id
		FROM scan_task_runs AS run
		JOIN scan_tasks AS task ON task.id = run.scan_task_id
		WHERE run.status = ? AND task.mode = ? AND task.status = ?
			AND NOT EXISTS (
				SELECT 1 FROM scan_task_runs AS active
				WHERE active.id <> run.id AND active.status IN (?, ?)
			)
		ORDER BY run.created_at ASC, run.id ASC
		LIMIT 1`,
		model.ScanTaskRunStatusQueued, model.ScanTaskModeOnce, model.ScanTaskStatusEnabled,
		model.ScanTaskRunStatusRunning, model.ScanTaskRunStatusCancelRequested,
	).Scan(&runID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	result, err := tx.Exec(`UPDATE scan_task_runs SET status = ?, started_at = COALESCE(started_at, datetime('now')), updated_at = datetime('now') WHERE id = ? AND status = ?`, model.ScanTaskRunStatusRunning, runID, model.ScanTaskRunStatusQueued)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, nil
	}
	run, err := scanScanTaskRun(tx.QueryRow(scanTaskRunSelect+` WHERE id = ?`, runID))
	if err != nil {
		return nil, err
	}
	var frozenCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM scan_task_run_fingerprint_imports WHERE scan_task_run_id = ?`, runID).Scan(&frozenCount); err != nil && !isMissingFingerprintCatalogTable(err) {
		return nil, err
	}
	if frozenCount == 0 {
		if err := FreezeActiveFingerprintImportsTx(tx, runID); err != nil {
			return nil, fmt.Errorf("freeze recovered run fingerprint imports: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &run, nil
}

// ListExpiredTerminalScanTaskRuns returns terminal runs older than cutoff.
// The latest successful run of each logical task is retained as a Diff
// baseline even when it predates the normal retention window.
func ListExpiredTerminalScanTaskRuns(db *sql.DB, cutoff time.Time) ([]ExpiredScanTaskRun, error) {
	rows, err := db.Query(`
		SELECT run.id, COALESCE(run.report_path, ''), COALESCE(run.audit_report_path, '')
		FROM scan_task_runs AS run
		WHERE run.status IN (?, ?, ?, ?, ?)
			AND julianday(COALESCE(run.finished_at, run.scheduled_for, run.created_at)) < julianday(?)
			AND NOT (
				run.status = ?
				AND run.id = (
					SELECT latest.id
					FROM scan_task_runs AS latest
					WHERE latest.scan_task_id = run.scan_task_id
						AND latest.status = ?
					ORDER BY latest.sequence DESC, latest.id DESC
					LIMIT 1
				)
			)
		ORDER BY run.scan_task_id ASC, run.sequence ASC`,
		terminalScanTaskRunStatuses(cutoff)...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	runs := make([]ExpiredScanTaskRun, 0)
	for rows.Next() {
		var run ExpiredScanTaskRun
		if err := rows.Scan(&run.ID, &run.ReportPath, &run.AuditReportPath); err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return runs, nil
}

// DeleteExpiredTerminalScanTaskRun removes an already-expired terminal run
// and its immutable snapshots. The condition is checked again in the same
// transaction so concurrent cleanup cannot delete a run that became protected
// by a newer lifecycle decision.
func DeleteExpiredTerminalScanTaskRun(db *sql.DB, runID int64, cutoff time.Time) (bool, error) {
	if runID <= 0 {
		return false, errors.New("scan task run ID is required")
	}

	tx, err := db.Begin()
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	var eligible int
	arguments := append([]interface{}{runID}, terminalScanTaskRunStatuses(cutoff)...)
	err = tx.QueryRow(`
		SELECT 1
		FROM scan_task_runs AS run
		WHERE run.id = ?
			AND run.status IN (?, ?, ?, ?, ?)
			AND julianday(COALESCE(run.finished_at, run.scheduled_for, run.created_at)) < julianday(?)
			AND NOT (
				run.status = ?
				AND run.id = (
					SELECT latest.id
					FROM scan_task_runs AS latest
					WHERE latest.scan_task_id = run.scan_task_id
						AND latest.status = ?
					ORDER BY latest.sequence DESC, latest.id DESC
					LIMIT 1
				)
			)`, arguments...).Scan(&eligible)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	for _, table := range []string{"scan_task_run_hosts", "scan_task_run_ports", "scan_task_run_vulnerabilities"} {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE scan_task_run_id = ?`, runID); err != nil {
			return false, err
		}
	}
	result, err := tx.Exec(`DELETE FROM scan_task_runs WHERE id = ?`, runID)
	if err != nil {
		return false, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if deleted != 1 {
		return false, fmt.Errorf("delete expired scan task run %d: expected one row, deleted %d", runID, deleted)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func terminalScanTaskRunStatuses(cutoff time.Time) []interface{} {
	return []interface{}{
		model.ScanTaskRunStatusSuccess,
		model.ScanTaskRunStatusFailed,
		model.ScanTaskRunStatusCanceled,
		model.ScanTaskRunStatusSkippedOverlap,
		model.ScanTaskRunStatusSkippedMisfire,
		cutoff.UTC().Format(time.RFC3339Nano),
		model.ScanTaskRunStatusSuccess,
		model.ScanTaskRunStatusSuccess,
	}
}

func UpdateScanTaskRunReportPath(db *sql.DB, runID int64, path string) error {
	if runID <= 0 {
		return errors.New("scan task run ID is required")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("scan task run report path is required")
	}
	result, err := db.Exec(`UPDATE scan_task_runs SET report_path = ?, report_error = NULL, updated_at = datetime('now') WHERE id = ?`, path, runID)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 0 {
		return ErrScanTaskRunNotFound
	}
	return nil
}

func UpdateScanTaskRunReportPaths(db *sql.DB, runID int64, path, auditPath string) error {
	if runID <= 0 {
		return errors.New("scan task run ID is required")
	}
	path = strings.TrimSpace(path)
	auditPath = strings.TrimSpace(auditPath)
	if path == "" || auditPath == "" {
		return errors.New("scan task run user and audit report paths are required")
	}
	result, err := db.Exec(`
		UPDATE scan_task_runs
		SET report_path = ?, audit_report_path = ?, report_error = NULL, updated_at = datetime('now')
		WHERE id = ?`, path, auditPath, runID)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 0 {
		return ErrScanTaskRunNotFound
	}
	return nil
}

// UpdateScanTaskRunReportError persists report generation diagnostics without
// touching the already-finalized scan status or result snapshot.
func UpdateScanTaskRunReportError(db *sql.DB, runID int64, reportError string) error {
	if runID <= 0 {
		return errors.New("scan task run ID is required")
	}
	reportError = strings.TrimSpace(reportError)
	var (
		result sql.Result
		err    error
	)
	if reportError == "" {
		result, err = db.Exec(`UPDATE scan_task_runs SET report_error = NULL, updated_at = datetime('now') WHERE id = ?`, runID)
	} else {
		result, err = db.Exec(`UPDATE scan_task_runs SET report_error = ?, updated_at = datetime('now') WHERE id = ?`, reportError, runID)
	}
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 0 {
		return ErrScanTaskRunNotFound
	}
	return nil
}

func SaveScanTaskRunSnapshot(db *sql.DB, snapshot model.ScanTaskRunSnapshot) error {
	if snapshot.RunID <= 0 {
		return errors.New("scan task run ID is required")
	}
	if err := validateScanTaskRunSnapshot(snapshot); err != nil {
		return err
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	result, err := tx.Exec(`
		UPDATE scan_task_runs
		SET snapshot_written_at = datetime('now'), updated_at = datetime('now')
		WHERE id = ? AND status IN (?, ?) AND snapshot_written_at IS NULL`,
		snapshot.RunID,
		model.ScanTaskRunStatusRunning,
		model.ScanTaskRunStatusCancelRequested,
	)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 0 {
		return snapshotWriteError(tx, snapshot.RunID)
	}

	for _, host := range snapshot.Hosts {
		if _, err := tx.Exec(`
			INSERT INTO scan_task_run_hosts (scan_task_run_id, ip, is_active)
			VALUES (?, ?, ?)`, snapshot.RunID, host.IP, boolToInt(host.IsActive)); err != nil {
			return err
		}
	}
	for _, port := range snapshot.Ports {
		if _, err := tx.Exec(`
			INSERT INTO scan_task_run_ports (scan_task_run_id, ip, port, service_type, product, banner)
			VALUES (?, ?, ?, ?, ?, ?)`, snapshot.RunID, port.IP, port.Port, port.ServiceType, nullIfEmpty(port.Product), nullIfEmpty(port.Banner)); err != nil {
			return err
		}
	}
	for _, evidence := range snapshot.ProtocolEvidence {
		evidence.EvidenceType = normalizedProtocolEvidenceType(evidence)
		if _, err := tx.Exec(`
			INSERT INTO scan_task_run_protocol_evidence
				(scan_task_run_id, ip, port, evidence_type, probe_name, protocol, responded, outcome, diagnostic, status_code, server, title,
				 banner_captured_length, banner_sha256, banner_truncated,
				 header_captured_length, header_sha256, header_truncated,
				 body_captured_length, body_sha256, body_truncated)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			snapshot.RunID, evidence.IP, evidence.Port, evidence.EvidenceType, evidence.ProbeName, evidence.Protocol, boolToInt(evidence.Responded), normalizedProtocolEvidenceOutcome(evidence), evidence.Diagnostic, nullIfZero(evidence.StatusCode),
			nullIfEmpty(evidence.Server), nullIfEmpty(evidence.Title), evidence.BannerCapturedLength, nullIfEmpty(evidence.BannerSHA256), boolToInt(evidence.BannerTruncated),
			evidence.HeaderCapturedLength, nullIfEmpty(evidence.HeaderSHA256), boolToInt(evidence.HeaderTruncated), evidence.BodyCapturedLength, nullIfEmpty(evidence.BodySHA256), boolToInt(evidence.BodyTruncated)); err != nil {
			return err
		}
	}
	if snapshot.Validation.Status != "" {
		if _, err := tx.Exec(`
			INSERT INTO scan_task_run_validation
				(scan_task_run_id, status, candidate_endpoint_count, executed_endpoint_count, template_count, finding_count, started_at, finished_at, error_message)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, snapshot.RunID, snapshot.Validation.Status,
			snapshot.Validation.CandidateEndpointCount, snapshot.Validation.ExecutedEndpointCount, snapshot.Validation.TemplateCount, snapshot.Validation.FindingCount,
			nullIfEmpty(snapshot.Validation.StartedAt), nullIfEmpty(snapshot.Validation.FinishedAt), nullIfEmpty(snapshot.Validation.Error)); err != nil {
			return err
		}
	}
	for _, candidate := range snapshot.TemplateCandidates {
		mappingImportID := interface{}(nil)
		if candidate.MappingImportID > 0 {
			mappingImportID = candidate.MappingImportID
		}
		if _, err := tx.Exec(`INSERT INTO scan_task_run_template_candidates (scan_task_run_id, template_id, path, source, reason, template_sha256, template_set_revision, template_mapping_import_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(scan_task_run_id, template_id, path) DO UPDATE SET source = excluded.source, reason = excluded.reason, template_sha256 = excluded.template_sha256, template_set_revision = excluded.template_set_revision, template_mapping_import_id = excluded.template_mapping_import_id`, snapshot.RunID, candidate.TemplateID, candidate.Path, candidate.Source, candidate.Reason, nullIfEmpty(candidate.TemplateSHA256), nullIfEmpty(candidate.TemplateSetRevision), mappingImportID); err != nil {
			return err
		}
		if candidate.IP != "" && candidate.Port > 0 && candidate.Protocol != "" {
			if _, err := tx.Exec(`INSERT INTO scan_task_run_template_candidate_endpoints (scan_task_run_id, template_id, path, ip, port, protocol) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, snapshot.RunID, candidate.TemplateID, candidate.Path, candidate.IP, candidate.Port, candidate.Protocol); err != nil {
				return err
			}
		}
	}
	for _, finding := range snapshot.Vulnerabilities {
		if _, err := tx.Exec(`
			INSERT INTO scan_task_run_vulnerabilities
				(scan_task_run_id, finding_key, template_id, name, severity, target, target_ip, target_port, matched_at, description, evidence)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			snapshot.RunID,
			finding.FindingKey,
			nullIfEmpty(finding.TemplateID),
			nullIfEmpty(finding.Name),
			nullIfEmpty(finding.Severity),
			finding.Target,
			nullIfEmpty(finding.TargetIP),
			nullIfZero(finding.TargetPort),
			nullIfEmpty(finding.MatchedAt),
			nullIfEmpty(finding.Description),
			nullIfEmpty(finding.Evidence),
		); err != nil {
			return err
		}
	}
	if err := saveFingerprintRunMatchesTx(tx, snapshot.RunID, snapshot.FingerprintMatches); err != nil {
		return err
	}
	return tx.Commit()
}

func GetScanTaskRunSnapshot(db *sql.DB, runID int64) (model.ScanTaskRunSnapshot, error) {
	var writtenAt sql.NullString
	err := db.QueryRow(`SELECT snapshot_written_at FROM scan_task_runs WHERE id = ?`, runID).Scan(&writtenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ScanTaskRunSnapshot{}, ErrScanTaskRunNotFound
	}
	if err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if !writtenAt.Valid {
		return model.ScanTaskRunSnapshot{}, ErrScanTaskRunSnapshotUnavailable
	}

	snapshot := model.ScanTaskRunSnapshot{
		RunID:           runID,
		Hosts:           make([]model.ScanTaskRunHost, 0),
		Ports:           make([]model.ScanTaskRunPort, 0),
		Vulnerabilities: make([]model.ScanTaskRunVulnerability, 0),
	}
	if err := loadScanTaskRunHosts(db, &snapshot); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if err := loadScanTaskRunPorts(db, &snapshot); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if err := loadScanTaskRunProtocolEvidence(db, &snapshot); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if err := loadScanTaskRunValidation(db, &snapshot); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if err := loadScanTaskRunVulnerabilities(db, &snapshot); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	rows, err := db.Query(`
		SELECT candidate.template_id, candidate.path, candidate.source, candidate.reason,
			COALESCE(candidate.template_sha256, ''), COALESCE(candidate.template_set_revision, ''),
			COALESCE(candidate.template_mapping_import_id, 0), endpoint.ip, endpoint.port, endpoint.protocol
		FROM scan_task_run_template_candidates AS candidate
		JOIN scan_task_run_template_candidate_endpoints AS endpoint
			ON endpoint.scan_task_run_id = candidate.scan_task_run_id AND endpoint.template_id = candidate.template_id AND endpoint.path = candidate.path
		WHERE candidate.scan_task_run_id = ?
		ORDER BY candidate.template_id, candidate.path, endpoint.ip, endpoint.port, endpoint.protocol`, runID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such column") {
			if legacyErr := loadLegacyTemplateCandidates(db, &snapshot); legacyErr != nil {
				return model.ScanTaskRunSnapshot{}, legacyErr
			}
			return snapshot, nil
		}
		if strings.Contains(strings.ToLower(err.Error()), "no such table: scan_task_run_template_candidate_endpoints") {
			if legacyErr := loadLegacyTemplateCandidates(db, &snapshot); legacyErr != nil {
				return model.ScanTaskRunSnapshot{}, legacyErr
			}
			return snapshot, nil
		}
		if isMissingTemplateCandidateTable(err) {
			return snapshot, nil
		}
		return model.ScanTaskRunSnapshot{}, err
	}
	for rows.Next() {
		var candidate model.ScanTaskRunTemplateCandidate
		if err := rows.Scan(&candidate.TemplateID, &candidate.Path, &candidate.Source, &candidate.Reason, &candidate.TemplateSHA256, &candidate.TemplateSetRevision, &candidate.MappingImportID, &candidate.IP, &candidate.Port, &candidate.Protocol); err != nil {
			rows.Close()
			return model.ScanTaskRunSnapshot{}, err
		}
		snapshot.TemplateCandidates = append(snapshot.TemplateCandidates, candidate)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return model.ScanTaskRunSnapshot{}, err
	}
	if err := rows.Close(); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if len(snapshot.TemplateCandidates) == 0 {
		if err := loadLegacyTemplateCandidates(db, &snapshot); err != nil {
			return model.ScanTaskRunSnapshot{}, err
		}
	}
	return snapshot, nil
}

func loadLegacyTemplateCandidates(db *sql.DB, snapshot *model.ScanTaskRunSnapshot) error {
	rows, err := db.Query(`SELECT template_id, path, source, reason FROM scan_task_run_template_candidates WHERE scan_task_run_id = ? ORDER BY template_id, path`, snapshot.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var candidate model.ScanTaskRunTemplateCandidate
		if err := rows.Scan(&candidate.TemplateID, &candidate.Path, &candidate.Source, &candidate.Reason); err != nil {
			return err
		}
		snapshot.TemplateCandidates = append(snapshot.TemplateCandidates, candidate)
	}
	return rows.Err()
}

func isMissingTemplateCandidateTable(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "no such table: scan_task_run_template_candidates")
}

const scanTaskRunSelect = `
	SELECT id, scan_task_id, sequence, scheduled_for, status, target, scan_type, config_json, config_hash,
		error_message, report_path, audit_report_path, report_error, started_at, finished_at, snapshot_written_at, created_at, updated_at
	FROM scan_task_runs`

type scanTaskRunScanner interface {
	Scan(dest ...interface{}) error
}

func scanScanTaskRun(scanner scanTaskRunScanner) (model.ScanTaskRun, error) {
	var run model.ScanTaskRun
	var configJSON, configHash, errorMessage, reportPath, auditReportPath, reportError, startedAt, finishedAt, snapshotWrittenAt, updatedAt sql.NullString
	if err := scanner.Scan(
		&run.ID,
		&run.ScanTaskID,
		&run.Sequence,
		&run.ScheduledFor,
		&run.Status,
		&run.Target,
		&run.ScanType,
		&configJSON,
		&configHash,
		&errorMessage,
		&reportPath,
		&auditReportPath,
		&reportError,
		&startedAt,
		&finishedAt,
		&snapshotWrittenAt,
		&run.CreatedAt,
		&updatedAt,
	); err != nil {
		return model.ScanTaskRun{}, err
	}
	run.ConfigHash = configHash.String
	run.ErrorMessage = errorMessage.String
	run.ReportPath = reportPath.String
	run.AuditReportPath = auditReportPath.String
	run.ReportError = reportError.String
	run.StartedAt = startedAt.String
	run.FinishedAt = finishedAt.String
	run.SnapshotWrittenAt = snapshotWrittenAt.String
	run.UpdatedAt = updatedAt.String
	if configJSON.Valid && strings.TrimSpace(configJSON.String) != "" {
		if err := json.Unmarshal([]byte(configJSON.String), &run.Config); err != nil {
			return model.ScanTaskRun{}, fmt.Errorf("decode scan task run %d config: %w", run.ID, err)
		}
	}
	return run, nil
}

func normalizeScheduledFor(value string) (string, error) {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("scheduled_for must be RFC3339: %w", err)
	}
	return parsed.UTC().Format(time.RFC3339Nano), nil
}

func snapshotWriteError(tx *sql.Tx, runID int64) error {
	var status string
	var writtenAt sql.NullString
	err := tx.QueryRow(`SELECT status, snapshot_written_at FROM scan_task_runs WHERE id = ?`, runID).Scan(&status, &writtenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrScanTaskRunNotFound
	}
	if err != nil {
		return err
	}
	if writtenAt.Valid {
		return ErrScanTaskRunSnapshotWritten
	}
	return fmt.Errorf("%w: status %s", ErrScanTaskRunSnapshotNotWritable, status)
}

func validateScanTaskRunSnapshot(snapshot model.ScanTaskRunSnapshot) error {
	for _, host := range snapshot.Hosts {
		if net.ParseIP(strings.TrimSpace(host.IP)) == nil {
			return fmt.Errorf("invalid snapshot host IP: %s", host.IP)
		}
	}
	for _, port := range snapshot.Ports {
		if net.ParseIP(strings.TrimSpace(port.IP)) == nil || port.Port < 1 || port.Port > 65535 || strings.TrimSpace(port.ServiceType) == "" {
			return fmt.Errorf("invalid snapshot port: %s:%d", port.IP, port.Port)
		}
	}
	for _, evidence := range snapshot.ProtocolEvidence {
		evidenceType := normalizedProtocolEvidenceType(evidence)
		if net.ParseIP(strings.TrimSpace(evidence.IP)) == nil || evidence.Port < 1 || evidence.Port > 65535 || strings.TrimSpace(evidence.Protocol) == "" || !validProtocolEvidenceIdentity(evidenceType, evidence.Protocol, evidence.ProbeName) || !validProtocolEvidenceOutcome(evidenceType, normalizedProtocolEvidenceOutcome(evidence), evidence.Diagnostic) || evidence.StatusCode < 0 || evidence.StatusCode > 999 || evidence.BannerCapturedLength < 0 || evidence.HeaderCapturedLength < 0 || evidence.BodyCapturedLength < 0 {
			return fmt.Errorf("invalid snapshot protocol evidence: %s:%d/%s", evidence.IP, evidence.Port, evidence.Protocol)
		}
		for _, digest := range []string{evidence.BannerSHA256, evidence.HeaderSHA256, evidence.BodySHA256} {
			if err := validateProtocolEvidenceDigest(digest); err != nil {
				return err
			}
		}
	}
	if snapshot.Validation.Status != "" {
		if !isScanTaskRunValidationStatus(snapshot.Validation.Status) || snapshot.Validation.CandidateEndpointCount < 0 || snapshot.Validation.ExecutedEndpointCount < 0 || snapshot.Validation.TemplateCount < 0 || snapshot.Validation.FindingCount < 0 || snapshot.Validation.ExecutedEndpointCount > snapshot.Validation.CandidateEndpointCount || snapshot.Validation.FindingCount != len(snapshot.Vulnerabilities) {
			return errors.New("invalid snapshot validation state")
		}
	}
	for _, finding := range snapshot.Vulnerabilities {
		if strings.TrimSpace(finding.FindingKey) == "" || strings.TrimSpace(finding.Target) == "" {
			return errors.New("snapshot vulnerability requires finding key and target")
		}
	}
	for _, candidate := range snapshot.TemplateCandidates {
		if strings.TrimSpace(candidate.TemplateID) == "" || strings.TrimSpace(candidate.Path) == "" || strings.TrimSpace(candidate.Source) == "" || strings.TrimSpace(candidate.Reason) == "" {
			return errors.New("invalid snapshot template candidate")
		}
		if candidate.IP != "" || candidate.Port != 0 || candidate.Protocol != "" {
			if net.ParseIP(candidate.IP) == nil || candidate.Port < 1 || candidate.Port > 65535 || strings.TrimSpace(candidate.Protocol) == "" {
				return errors.New("invalid snapshot template candidate endpoint")
			}
		}
	}
	return nil
}

func loadScanTaskRunHosts(db *sql.DB, snapshot *model.ScanTaskRunSnapshot) error {
	rows, err := db.Query(`
		SELECT ip, is_active
		FROM scan_task_run_hosts
		WHERE scan_task_run_id = ?
		ORDER BY ip ASC`, snapshot.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var host model.ScanTaskRunHost
		var isActive int
		if err := rows.Scan(&host.IP, &isActive); err != nil {
			return err
		}
		host.IsActive = isActive != 0
		snapshot.Hosts = append(snapshot.Hosts, host)
	}
	return rows.Err()
}

func loadScanTaskRunPorts(db *sql.DB, snapshot *model.ScanTaskRunSnapshot) error {
	rows, err := db.Query(`
		SELECT ip, port, service_type, product, banner
		FROM scan_task_run_ports
		WHERE scan_task_run_id = ?
		ORDER BY ip ASC, port ASC`, snapshot.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var port model.ScanTaskRunPort
		var product, banner sql.NullString
		if err := rows.Scan(&port.IP, &port.Port, &port.ServiceType, &product, &banner); err != nil {
			return err
		}
		port.Product = product.String
		port.Banner = banner.String
		snapshot.Ports = append(snapshot.Ports, port)
	}
	return rows.Err()
}

func loadScanTaskRunProtocolEvidence(db *sql.DB, snapshot *model.ScanTaskRunSnapshot) error {
	rows, err := db.Query(`
		SELECT ip, port, evidence_type, probe_name, protocol, responded, outcome, diagnostic, COALESCE(status_code, 0), COALESCE(server, ''), COALESCE(title, ''),
			banner_captured_length, COALESCE(banner_sha256, ''), banner_truncated,
			header_captured_length, COALESCE(header_sha256, ''), header_truncated,
			body_captured_length, COALESCE(body_sha256, ''), body_truncated
		FROM scan_task_run_protocol_evidence
		WHERE scan_task_run_id = ?
		ORDER BY ip, port, evidence_type, protocol, probe_name`, snapshot.RunID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table: scan_task_run_protocol_evidence") {
			return nil
		}
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var evidence model.ScanTaskRunProtocolEvidence
		var responded, bannerTruncated, headerTruncated, bodyTruncated int
		if err := rows.Scan(&evidence.IP, &evidence.Port, &evidence.EvidenceType, &evidence.ProbeName, &evidence.Protocol, &responded, &evidence.Outcome, &evidence.Diagnostic, &evidence.StatusCode, &evidence.Server, &evidence.Title,
			&evidence.BannerCapturedLength, &evidence.BannerSHA256, &bannerTruncated,
			&evidence.HeaderCapturedLength, &evidence.HeaderSHA256, &headerTruncated,
			&evidence.BodyCapturedLength, &evidence.BodySHA256, &bodyTruncated); err != nil {
			return err
		}
		evidence.Responded = responded != 0
		evidence.BannerTruncated = bannerTruncated != 0
		evidence.HeaderTruncated = headerTruncated != 0
		evidence.BodyTruncated = bodyTruncated != 0
		snapshot.ProtocolEvidence = append(snapshot.ProtocolEvidence, evidence)
	}
	return rows.Err()
}

func loadScanTaskRunValidation(db *sql.DB, snapshot *model.ScanTaskRunSnapshot) error {
	var startedAt, finishedAt, errorMessage sql.NullString
	err := db.QueryRow(`
		SELECT status, candidate_endpoint_count, executed_endpoint_count, template_count, finding_count,
			started_at, finished_at, error_message
		FROM scan_task_run_validation WHERE scan_task_run_id = ?`, snapshot.RunID).Scan(
		&snapshot.Validation.Status, &snapshot.Validation.CandidateEndpointCount, &snapshot.Validation.ExecutedEndpointCount,
		&snapshot.Validation.TemplateCount, &snapshot.Validation.FindingCount, &startedAt, &finishedAt, &errorMessage,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such table: scan_task_run_validation") {
			return nil
		}
		return err
	}
	snapshot.Validation.StartedAt = startedAt.String
	snapshot.Validation.FinishedAt = finishedAt.String
	snapshot.Validation.Error = errorMessage.String
	return nil
}

func isScanTaskRunValidationStatus(status string) bool {
	switch status {
	case model.ScanTaskRunValidationDisabled, model.ScanTaskRunValidationNotStarted, model.ScanTaskRunValidationNoCandidates, model.ScanTaskRunValidationSuccess, model.ScanTaskRunValidationFailed:
		return true
	default:
		return false
	}
}

func normalizedProtocolEvidenceType(evidence model.ScanTaskRunProtocolEvidence) string {
	evidenceType := strings.ToLower(strings.TrimSpace(evidence.EvidenceType))
	if evidenceType != "" {
		return evidenceType
	}
	protocol := strings.ToLower(strings.TrimSpace(evidence.Protocol))
	if protocol == "http" || protocol == "https" {
		return model.ProtocolEvidenceWeb
	}
	return model.ProtocolEvidencePassiveBanner
}

func validProtocolEvidenceIdentity(evidenceType, protocol, probeName string) bool {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	probeName = strings.TrimSpace(probeName)
	switch evidenceType {
	case model.ProtocolEvidencePassiveBanner:
		return protocol == "tcp" && probeName == ""
	case model.ProtocolEvidenceActiveProbe:
		return protocol == "tcp" && probeName != ""
	case model.ProtocolEvidenceWeb:
		return (protocol == "http" || protocol == "https") && probeName == ""
	default:
		return false
	}
}

func normalizedProtocolEvidenceOutcome(evidence model.ScanTaskRunProtocolEvidence) string {
	outcome := strings.ToLower(strings.TrimSpace(evidence.Outcome))
	if outcome != "" {
		return outcome
	}
	if evidence.Responded {
		return model.ProtocolProbeOutcomeResponded
	}
	return model.ProtocolProbeOutcomeNoResponse
}

func validProtocolEvidenceOutcome(evidenceType, outcome, diagnostic string) bool {
	if evidenceType != model.ProtocolEvidenceActiveProbe {
		return diagnostic == "" && (outcome == model.ProtocolProbeOutcomeResponded || outcome == model.ProtocolProbeOutcomeNoResponse)
	}
	switch outcome {
	case model.ProtocolProbeOutcomeResponded, model.ProtocolProbeOutcomeNoResponse,
		model.ProtocolProbeOutcomeConnectFailed, model.ProtocolProbeOutcomeConnectTimeout,
		model.ProtocolProbeOutcomeWriteFailed, model.ProtocolProbeOutcomeReadFailed,
		model.ProtocolProbeOutcomeReadTimeout, model.ProtocolProbeOutcomeBudgetTimeout,
		model.ProtocolProbeOutcomeCanceled:
		return diagnostic == "" || diagnostic == outcome
	default:
		return false
	}
}

func validateProtocolEvidenceDigest(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if len(value) != sha256.Size*2 {
		return errors.New("invalid protocol evidence SHA-256")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return errors.New("invalid protocol evidence SHA-256")
	}
	return nil
}

func loadScanTaskRunVulnerabilities(db *sql.DB, snapshot *model.ScanTaskRunSnapshot) error {
	rows, err := db.Query(`
		SELECT finding_key, template_id, name, severity, target, target_ip, target_port, matched_at, description, evidence
		FROM scan_task_run_vulnerabilities
		WHERE scan_task_run_id = ?
		ORDER BY finding_key ASC`, snapshot.RunID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var finding model.ScanTaskRunVulnerability
		var templateID, name, severity, targetIP, matchedAt, description, evidence sql.NullString
		var targetPort sql.NullInt64
		if err := rows.Scan(&finding.FindingKey, &templateID, &name, &severity, &finding.Target, &targetIP, &targetPort, &matchedAt, &description, &evidence); err != nil {
			return err
		}
		finding.TemplateID = templateID.String
		finding.Name = name.String
		finding.Severity = severity.String
		finding.TargetIP = targetIP.String
		finding.TargetPort = int(targetPort.Int64)
		finding.MatchedAt = matchedAt.String
		finding.Description = description.String
		finding.Evidence = evidence.String
		snapshot.Vulnerabilities = append(snapshot.Vulnerabilities, finding)
	}
	return rows.Err()
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
