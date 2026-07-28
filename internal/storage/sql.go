package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golandproject/yscan/internal/assist"
	"golandproject/yscan/internal/model"
)

const sqliteFile = "asm.db"

func InitDB() (*sql.DB, error) {
	dbExists := fileExists(sqliteFile)

	db, err := sql.Open("sqlite3", sqliteFile)
	if err != nil {
		return nil, fmt.Errorf("打开 SQLite 数据库失败: %v", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("SQLite 连接测试失败: %v", err)
	}

	if !dbExists {
		log.Printf("检测到不存在 %s，正在初始化数据库结构...", sqliteFile)
	}

	if err := initSQLiteSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化 SQLite 表结构失败: %v", err)
	}

	if !dbExists {
		log.Println("SQLite 数据库初始化完成")
	}

	if err := resetSequencesIfEmpty(db); err != nil {
		log.Printf("重置自增序列失败: %v", err)
	}

	return db, nil
}

func resetSequencesIfEmpty(db *sql.DB) error {
	tables := []string{"banner", "scan_results", "domain_info", "domain_ips", "host_inventory", "tasks", "scan_tasks", "scan_task_runs", "pocs", "vulnerabilities"}
	for _, tbl := range tables {
		var cnt int
		if err := db.QueryRow(fmt.Sprintf("SELECT COUNT(1) FROM %s", tbl)).Scan(&cnt); err != nil {
			return err
		}
		if cnt == 0 {
			if _, err := db.Exec("DELETE FROM sqlite_sequence WHERE name = ?", tbl); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureSQLiteMigrations(db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS host_inventory (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL UNIQUE,
			source TEXT,
			first_seen DATETIME NOT NULL DEFAULT (datetime('now')),
			last_seen DATETIME NOT NULL DEFAULT (datetime('now')),
			last_scan DATETIME,
			is_active INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS host_inventory_scopes (
			scope TEXT NOT NULL,
			ip TEXT NOT NULL,
			first_seen DATETIME NOT NULL DEFAULT (datetime('now')),
			last_seen DATETIME NOT NULL DEFAULT (datetime('now')),
			last_checked DATETIME NOT NULL DEFAULT (datetime('now')),
			is_active INTEGER NOT NULL DEFAULT 1,
			PRIMARY KEY (scope, ip)
		)`,
		`CREATE TABLE IF NOT EXISTS host_inventory_scope_ports (
			scope TEXT NOT NULL,
			ip TEXT NOT NULL,
			port INTEGER NOT NULL,
			service_type TEXT NOT NULL,
			first_seen DATETIME NOT NULL DEFAULT (datetime('now')),
			last_seen DATETIME NOT NULL DEFAULT (datetime('now')),
			last_checked DATETIME NOT NULL DEFAULT (datetime('now')),
			is_active INTEGER NOT NULL DEFAULT 1,
			PRIMARY KEY (scope, ip, port)
		)`,
		`CREATE TABLE IF NOT EXISTS task_change_summaries (
			task_id INTEGER PRIMARY KEY,
			target TEXT NOT NULL,
			summary_json TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS scan_tasks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,
			scan_type TEXT NOT NULL CHECK (scan_type IN ('ip', 'subnet')),
			mode TEXT NOT NULL CHECK (mode IN ('once', 'scheduled')),
			status TEXT NOT NULL CHECK (status IN ('enabled', 'paused', 'archived')),
			cron TEXT,
			timezone TEXT,
			config_json TEXT NOT NULL DEFAULT '{}',
			config_hash TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
			archived_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS scan_task_runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_task_id INTEGER NOT NULL REFERENCES scan_tasks(id),
			sequence INTEGER NOT NULL,
			scheduled_for DATETIME NOT NULL,
			status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'cancel_requested', 'success', 'failed', 'canceled', 'skipped_overlap', 'skipped_misfire')),
			target TEXT NOT NULL,
			scan_type TEXT NOT NULL CHECK (scan_type IN ('ip', 'subnet')),
			config_json TEXT NOT NULL DEFAULT '{}',
			config_hash TEXT NOT NULL DEFAULT '',
			error_message TEXT,
			report_path TEXT,
			started_at DATETIME,
			finished_at DATETIME,
			snapshot_written_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(scan_task_id, sequence),
			UNIQUE(scan_task_id, scheduled_for)
		)`,
		`CREATE TABLE IF NOT EXISTS scan_task_run_hosts (
			scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id),
			ip TEXT NOT NULL,
			is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
			PRIMARY KEY (scan_task_run_id, ip)
		)`,
		`CREATE TABLE IF NOT EXISTS scan_task_run_ports (
			scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id),
			ip TEXT NOT NULL,
			port INTEGER NOT NULL,
			service_type TEXT NOT NULL,
			product TEXT,
			banner TEXT,
			PRIMARY KEY (scan_task_run_id, ip, port)
		)`,
		`CREATE TABLE IF NOT EXISTS scan_task_run_vulnerabilities (
			scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id),
			finding_key TEXT NOT NULL,
			template_id TEXT,
			name TEXT,
			severity TEXT,
			target TEXT NOT NULL,
			target_ip TEXT,
			target_port INTEGER,
			matched_at TEXT,
			evidence TEXT,
			PRIMARY KEY (scan_task_run_id, finding_key)
		)`,
		`CREATE TABLE IF NOT EXISTS asset_fingerprints (
			ip TEXT NOT NULL,
			port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
			protocol TEXT NOT NULL CHECK (protocol IN ('http', 'https', 'tcp', 'tls')),
			rule_id TEXT NOT NULL,
			source_id TEXT NOT NULL,
			vendor TEXT,
			product TEXT NOT NULL,
			version TEXT,
			cpe TEXT,
			confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
			evidence_json TEXT NOT NULL,
			first_seen DATETIME NOT NULL DEFAULT (datetime('now')),
			last_seen DATETIME NOT NULL DEFAULT (datetime('now')),
			PRIMARY KEY (ip, port, protocol, rule_id, source_id)
		)`,
		`CREATE TABLE IF NOT EXISTS scan_task_run_template_candidates (
			scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id), template_id TEXT NOT NULL, path TEXT NOT NULL, source TEXT NOT NULL, reason TEXT NOT NULL,
			PRIMARY KEY (scan_task_run_id, template_id, path)
		)`,
		`ALTER TABLE banner ADD COLUMN match_type TEXT NOT NULL DEFAULT 'contains'`,
		`ALTER TABLE banner ADD COLUMN protocol TEXT`,
		`ALTER TABLE banner ADD COLUMN port INTEGER`,
		`ALTER TABLE domain_info ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE domain_info ADD COLUMN last_seen DATETIME`,
		`ALTER TABLE domain_ips ADD COLUMN first_seen DATETIME`,
		`ALTER TABLE domain_ips ADD COLUMN last_seen DATETIME`,
		`ALTER TABLE domain_ips ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE tasks ADD COLUMN report_error TEXT`,
		`ALTER TABLE scan_task_runs ADD COLUMN report_error TEXT`,
		`ALTER TABLE scan_task_runs ADD COLUMN snapshot_written_at DATETIME`,
		`UPDATE domain_info SET last_seen = COALESCE(last_seen, first_seen, datetime('now'))`,
		`UPDATE domain_info SET is_active = COALESCE(is_active, 1)`,
		`UPDATE domain_ips SET first_seen = COALESCE(first_seen, datetime('now'))`,
		`UPDATE domain_ips SET last_seen = COALESCE(last_seen, datetime('now'))`,
		`UPDATE domain_ips SET is_active = COALESCE(is_active, 1)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_banner_service_pattern ON banner(service_name, banner_pattern)`,
		`CREATE INDEX IF NOT EXISTS idx_domain_info_subdomain_active ON domain_info(subdomain, is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_domain_ips_ip_active ON domain_ips(ip, is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_host_inventory_ip_active ON host_inventory(ip, is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_host_inventory_source_active ON host_inventory(source, is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_host_inventory_scopes_scope_active ON host_inventory_scopes(scope, is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_host_inventory_scopes_ip_active ON host_inventory_scopes(ip, is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_host_inventory_scope_ports_scope_ip_active ON host_inventory_scope_ports(scope, ip, is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_host_inventory_scope_ports_ip_port_active ON host_inventory_scope_ports(ip, port, is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_task_change_summaries_target ON task_change_summaries(target)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_tasks_status ON scan_tasks(status)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_task_runs_task_sequence ON scan_task_runs(scan_task_id, sequence)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_task_runs_status_scheduled_for ON scan_task_runs(status, scheduled_for)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_task_run_hosts_run ON scan_task_run_hosts(scan_task_run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_task_run_ports_run ON scan_task_run_ports(scan_task_run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_task_run_vulnerabilities_run ON scan_task_run_vulnerabilities(scan_task_run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_asset_fingerprints_ip_port ON asset_fingerprints(ip, port)`,
		`CREATE INDEX IF NOT EXISTS idx_asset_fingerprints_product ON asset_fingerprints(product)`,
	}

	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil && !isIgnorableSQLiteMigrationError(err) {
			return err
		}
	}
	return backfillLegacyHostInventoryScopes(db)
}

// backfillLegacyHostInventoryScopes preserves the scope meaning of historical
// subnet scans before source became a compatibility-only field. Legacy port
// results have no scan-scope provenance, so the migration intentionally does
// not turn them into scope-port baselines.
func backfillLegacyHostInventoryScopes(db *sql.DB) error {
	if _, err := db.Exec(`
		INSERT INTO host_inventory_scopes
			(scope, ip, first_seen, last_seen, last_checked, is_active)
		SELECT
			TRIM(source),
			ip,
			COALESCE(first_seen, datetime('now')),
			COALESCE(last_seen, first_seen, datetime('now')),
			COALESCE(last_scan, last_seen, first_seen, datetime('now')),
			COALESCE(is_active, 1)
		FROM host_inventory
		WHERE source IS NOT NULL AND TRIM(source) LIKE 'subnet:%'
		ON CONFLICT(scope, ip) DO NOTHING`); err != nil {
		return err
	}

	return nil
}

func isIgnorableSQLiteMigrationError(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate column name")
}

func initSQLiteSchema(db *sql.DB) error {
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return err
	}

	schema := `
CREATE TABLE IF NOT EXISTS banner (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name   TEXT    NOT NULL,
    banner_pattern TEXT    NOT NULL,
    match_type     TEXT    NOT NULL DEFAULT 'contains',
    protocol       TEXT,
    port           INTEGER,
    description    TEXT
);

CREATE TABLE IF NOT EXISTS scan_results (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT    NOT NULL,
    port         INTEGER NOT NULL,
    service_id   INTEGER,
    service_type TEXT    NOT NULL,
    scan_time    DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(ip, port)
);

CREATE TABLE IF NOT EXISTS domain_info (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT    NOT NULL,
    subdomain   TEXT    NOT NULL,
    is_wildcard INTEGER NOT NULL DEFAULT 0,
    is_active   INTEGER NOT NULL DEFAULT 1,
    title       TEXT,
    first_seen  DATETIME NOT NULL,
    last_seen   DATETIME NOT NULL DEFAULT (datetime('now')),
    last_scan   DATETIME,
    source      TEXT,
    UNIQUE(subdomain)
);

CREATE TABLE IF NOT EXISTS domain_ips (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id  INTEGER NOT NULL,
    subdomain  TEXT    NOT NULL,
    ip         TEXT    NOT NULL,
    ports      TEXT,
    first_seen DATETIME NOT NULL DEFAULT (datetime('now')),
    last_seen  DATETIME NOT NULL DEFAULT (datetime('now')),
    is_active  INTEGER NOT NULL DEFAULT 1,
    UNIQUE(domain_id, ip)
);

CREATE TABLE IF NOT EXISTS host_inventory (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT    NOT NULL UNIQUE,
    source     TEXT,
    first_seen DATETIME NOT NULL DEFAULT (datetime('now')),
    last_seen  DATETIME NOT NULL DEFAULT (datetime('now')),
    last_scan  DATETIME,
    is_active  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS host_inventory_scopes (
    scope        TEXT    NOT NULL,
    ip           TEXT    NOT NULL,
    first_seen   DATETIME NOT NULL DEFAULT (datetime('now')),
    last_seen    DATETIME NOT NULL DEFAULT (datetime('now')),
    last_checked DATETIME NOT NULL DEFAULT (datetime('now')),
    is_active    INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (scope, ip)
);

CREATE TABLE IF NOT EXISTS host_inventory_scope_ports (
    scope        TEXT    NOT NULL,
    ip           TEXT    NOT NULL,
    port         INTEGER NOT NULL,
    service_type TEXT    NOT NULL,
    first_seen   DATETIME NOT NULL DEFAULT (datetime('now')),
    last_seen    DATETIME NOT NULL DEFAULT (datetime('now')),
    last_checked DATETIME NOT NULL DEFAULT (datetime('now')),
    is_active    INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (scope, ip, port)
);

CREATE TABLE IF NOT EXISTS task_change_summaries (
    task_id      INTEGER PRIMARY KEY,
    target       TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at   DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    scan_type   TEXT NOT NULL CHECK (scan_type IN ('ip', 'subnet')),
    mode        TEXT NOT NULL CHECK (mode IN ('once', 'scheduled')),
    status      TEXT NOT NULL CHECK (status IN ('enabled', 'paused', 'archived')),
    cron        TEXT,
    timezone    TEXT,
    config_json TEXT NOT NULL DEFAULT '{}',
    config_hash TEXT NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    archived_at DATETIME
);

CREATE TABLE IF NOT EXISTS scan_task_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_task_id  INTEGER NOT NULL REFERENCES scan_tasks(id),
    sequence      INTEGER NOT NULL,
    scheduled_for DATETIME NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('queued', 'running', 'cancel_requested', 'success', 'failed', 'canceled', 'skipped_overlap', 'skipped_misfire')),
    target        TEXT NOT NULL,
    scan_type     TEXT NOT NULL CHECK (scan_type IN ('ip', 'subnet')),
    config_json   TEXT NOT NULL DEFAULT '{}',
	config_hash   TEXT NOT NULL DEFAULT '',
	error_message TEXT,
	report_path   TEXT,
	report_error  TEXT,
	started_at    DATETIME,
    finished_at   DATETIME,
    snapshot_written_at DATETIME,
    created_at    DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at    DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(scan_task_id, sequence),
    UNIQUE(scan_task_id, scheduled_for)
);

CREATE TABLE IF NOT EXISTS scan_task_run_hosts (
    scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id),
    ip               TEXT NOT NULL,
    is_active        INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    PRIMARY KEY (scan_task_run_id, ip)
);

CREATE TABLE IF NOT EXISTS scan_task_run_ports (
    scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id),
    ip               TEXT NOT NULL,
    port             INTEGER NOT NULL,
    service_type     TEXT NOT NULL,
    product          TEXT,
    banner           TEXT,
    PRIMARY KEY (scan_task_run_id, ip, port)
);

CREATE TABLE IF NOT EXISTS scan_task_run_vulnerabilities (
    scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id),
    finding_key      TEXT NOT NULL,
    template_id      TEXT,
    name             TEXT,
    severity         TEXT,
    target           TEXT NOT NULL,
    target_ip        TEXT,
    target_port      INTEGER,
    matched_at       TEXT,
    evidence         TEXT,
    PRIMARY KEY (scan_task_run_id, finding_key)
);

CREATE TABLE IF NOT EXISTS scan_task_run_template_candidates (
    scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id),
    template_id TEXT NOT NULL, path TEXT NOT NULL, source TEXT NOT NULL, reason TEXT NOT NULL,
    PRIMARY KEY (scan_task_run_id, template_id, path)
);

CREATE TABLE IF NOT EXISTS asset_fingerprints (
    ip            TEXT NOT NULL,
    port          INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol      TEXT NOT NULL CHECK (protocol IN ('http', 'https', 'tcp', 'tls')),
    rule_id       TEXT NOT NULL,
    source_id     TEXT NOT NULL,
    vendor        TEXT,
    product       TEXT NOT NULL,
    version       TEXT,
    cpe           TEXT,
    confidence    INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    evidence_json TEXT NOT NULL,
    first_seen    DATETIME NOT NULL DEFAULT (datetime('now')),
    last_seen     DATETIME NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (ip, port, protocol, rule_id, source_id)
);

CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_type   TEXT    NOT NULL,
    target      TEXT    NOT NULL,
    status      TEXT    NOT NULL,
    progress    INTEGER NOT NULL DEFAULT 0,
    error_msg   TEXT,
    report_error TEXT,
    started_at  DATETIME,
    finished_at DATETIME,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id TEXT    NOT NULL UNIQUE,
    name        TEXT,
    severity    TEXT,
    tags        TEXT,
    description TEXT,
    updated_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id        INTEGER NOT NULL,
    scan_result_id INTEGER,
    poc_id         INTEGER,
    template_id    TEXT,
    vuln_type      TEXT,
    name           TEXT,
    severity       TEXT,
    target         TEXT,
    target_ip      TEXT,
    target_port    INTEGER,
    matched_at     TEXT,
    evidence       TEXT,
    scan_time      DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(task_id, template_id, target, matched_at)
);

CREATE INDEX IF NOT EXISTS idx_vuln_task_id ON vulnerabilities(task_id);
CREATE INDEX IF NOT EXISTS idx_vuln_scan_result_id ON vulnerabilities(scan_result_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_banner_service_pattern ON banner(service_name, banner_pattern);
CREATE INDEX IF NOT EXISTS idx_host_inventory_ip_active ON host_inventory(ip, is_active);
CREATE INDEX IF NOT EXISTS idx_host_inventory_source_active ON host_inventory(source, is_active);
CREATE INDEX IF NOT EXISTS idx_host_inventory_scopes_scope_active ON host_inventory_scopes(scope, is_active);
CREATE INDEX IF NOT EXISTS idx_host_inventory_scopes_ip_active ON host_inventory_scopes(ip, is_active);
CREATE INDEX IF NOT EXISTS idx_host_inventory_scope_ports_scope_ip_active ON host_inventory_scope_ports(scope, ip, is_active);
CREATE INDEX IF NOT EXISTS idx_host_inventory_scope_ports_ip_port_active ON host_inventory_scope_ports(ip, port, is_active);
CREATE INDEX IF NOT EXISTS idx_task_change_summaries_target ON task_change_summaries(target);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_status ON scan_tasks(status);
CREATE INDEX IF NOT EXISTS idx_scan_task_runs_task_sequence ON scan_task_runs(scan_task_id, sequence);
CREATE INDEX IF NOT EXISTS idx_scan_task_runs_status_scheduled_for ON scan_task_runs(status, scheduled_for);
CREATE INDEX IF NOT EXISTS idx_scan_task_run_hosts_run ON scan_task_run_hosts(scan_task_run_id);
CREATE INDEX IF NOT EXISTS idx_scan_task_run_ports_run ON scan_task_run_ports(scan_task_run_id);
CREATE INDEX IF NOT EXISTS idx_scan_task_run_vulnerabilities_run ON scan_task_run_vulnerabilities(scan_task_run_id);
CREATE INDEX IF NOT EXISTS idx_asset_fingerprints_ip_port ON asset_fingerprints(ip, port);
CREATE INDEX IF NOT EXISTS idx_asset_fingerprints_product ON asset_fingerprints(product);
`
	_, err := db.Exec(schema)
	if err != nil {
		return err
	}

	if err := ensureSQLiteMigrations(db); err != nil {
		return err
	}

	return seedBuiltinFingerprints(db)
}

func SaveNucleiFindings(db *sql.DB, taskID int64, findings []model.NucleiFinding) error {
	if len(findings) == 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	for _, f := range findings {
		pocID, err2 := upsertPOC(tx, f)
		if err2 != nil {
			err = err2
			return err
		}

		scanResultID, err2 := getScanResultID(tx, f.TargetIP, f.TargetPort)
		if err2 != nil {
			err = err2
			return err
		}

		_, err2 = tx.Exec(`
			INSERT INTO vulnerabilities
			(task_id, scan_result_id, poc_id, template_id, vuln_type, name, severity, target, target_ip, target_port, matched_at, evidence, scan_time)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
			ON CONFLICT(task_id, template_id, target, matched_at) DO UPDATE SET
				scan_result_id = excluded.scan_result_id,
				poc_id         = excluded.poc_id,
				vuln_type      = excluded.vuln_type,
				name           = excluded.name,
				severity       = excluded.severity,
				target_ip      = excluded.target_ip,
				target_port    = excluded.target_port,
				evidence       = excluded.evidence,
				scan_time      = datetime('now')`,
			taskID,
			scanResultID,
			pocID,
			f.TemplateID,
			f.VulnType,
			f.Name,
			f.Severity,
			f.Target,
			f.TargetIP,
			f.TargetPort,
			f.MatchedAt,
			f.Evidence,
		)
		if err2 != nil {
			err = err2
			return err
		}
	}

	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func ListVulnerabilitiesByTask(db *sql.DB, taskID int64) ([]model.Vulnerability, error) {
	return ListVulnerabilitiesByTaskWithSeverity(db, taskID, "")
}

func ListVulnerabilitiesByTaskWithSeverity(db *sql.DB, taskID int64, severity string) ([]model.Vulnerability, error) {
	severity = strings.ToLower(strings.TrimSpace(severity))

	query := `
		SELECT id, task_id, scan_result_id, poc_id, template_id, vuln_type, name, severity, target, target_ip, target_port, matched_at, scan_time
		FROM vulnerabilities
		WHERE task_id = ?`
	args := []interface{}{taskID}
	if severity != "" {
		query += ` AND LOWER(severity) = ?`
		args = append(args, severity)
	}
	query += ` ORDER BY id DESC`

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.Vulnerability, 0)
	for rows.Next() {
		var v model.Vulnerability
		var scanResultID, pocID sql.NullInt64
		if err := rows.Scan(
			&v.ID,
			&v.TaskID,
			&scanResultID,
			&pocID,
			&v.TemplateID,
			&v.VulnType,
			&v.Name,
			&v.Severity,
			&v.Target,
			&v.TargetIP,
			&v.TargetPort,
			&v.MatchedAt,
			&v.ScanTime,
		); err != nil {
			return nil, err
		}
		if scanResultID.Valid {
			v.ScanResultID = scanResultID.Int64
		}
		if pocID.Valid {
			v.PocID = pocID.Int64
		}
		out = append(out, v)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func upsertPOC(tx *sql.Tx, f model.NucleiFinding) (int64, error) {
	if strings.TrimSpace(f.TemplateID) == "" {
		return 0, nil
	}

	_, err := tx.Exec(`
		INSERT INTO pocs (template_id, name, severity, tags, description, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(template_id) DO UPDATE SET
			name        = excluded.name,
			severity    = excluded.severity,
			tags        = excluded.tags,
			description = excluded.description,
			updated_at  = datetime('now')`,
		f.TemplateID,
		f.Name,
		f.Severity,
		f.Tags,
		f.Description,
	)
	if err != nil {
		return 0, err
	}

	var pocID int64
	err = tx.QueryRow(`SELECT id FROM pocs WHERE template_id = ?`, f.TemplateID).Scan(&pocID)
	if err != nil {
		return 0, err
	}
	return pocID, nil
}

func getScanResultID(tx *sql.Tx, ip string, port int) (sql.NullInt64, error) {
	var id sql.NullInt64
	if strings.TrimSpace(ip) == "" || port <= 0 {
		return id, nil
	}

	err := tx.QueryRow(`SELECT id FROM scan_results WHERE ip = ? AND port = ? LIMIT 1`, ip, port).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return sql.NullInt64{}, nil
		}
		return sql.NullInt64{}, err
	}
	return id, nil
}

func CreateTask(db *sql.DB, taskType, target string) (int64, error) {
	res, err := db.Exec(`
		INSERT INTO tasks (task_type, target, status, progress, created_at, updated_at)
		VALUES (?, ?, ?, 0, datetime('now'), datetime('now'))`,
		taskType,
		target,
		model.TaskStatusQueued,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func GetTaskStatus(db *sql.DB, taskID int64) (string, error) {
	var status string
	err := db.QueryRow(`SELECT status FROM tasks WHERE id = ?`, taskID).Scan(&status)
	if err != nil {
		return "", err
	}
	return status, nil
}

func GetTaskByID(db *sql.DB, taskID int64) (model.Task, error) {
	var t model.Task
	var startedAt, finishedAt, errorMsg, reportError, updatedAt sql.NullString

	err := db.QueryRow(`
		SELECT id, task_type, target, status, progress, error_msg, report_error, started_at, finished_at, created_at, updated_at
		FROM tasks
		WHERE id = ?`, taskID).Scan(
		&t.ID,
		&t.TaskType,
		&t.Target,
		&t.Status,
		&t.Progress,
		&errorMsg,
		&reportError,
		&startedAt,
		&finishedAt,
		&t.CreatedAt,
		&updatedAt,
	)
	if err != nil {
		return model.Task{}, err
	}

	applyNullableTaskFields(&t, errorMsg, reportError, startedAt, finishedAt, updatedAt)

	return t, nil
}

func ListTasks(db *sql.DB) ([]model.Task, error) {
	rows, err := db.Query(`
		SELECT id, task_type, target, status, progress, error_msg, report_error, started_at, finished_at, created_at, updated_at
		FROM tasks
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tasks := make([]model.Task, 0)
	for rows.Next() {
		var t model.Task
		var startedAt, finishedAt, errorMsg, reportError, updatedAt sql.NullString
		if err := rows.Scan(
			&t.ID,
			&t.TaskType,
			&t.Target,
			&t.Status,
			&t.Progress,
			&errorMsg,
			&reportError,
			&startedAt,
			&finishedAt,
			&t.CreatedAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		applyNullableTaskFields(&t, errorMsg, reportError, startedAt, finishedAt, updatedAt)
		tasks = append(tasks, t)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tasks, nil
}

// ListLegacyTaskSummaries returns v1 executions as read-only historical data.
// M10 Diff queries must only read ScanTaskRun snapshots, never this list.
func ListLegacyTaskSummaries(db *sql.DB) ([]model.LegacyTaskSummary, error) {
	rows, err := db.Query(`
		SELECT id, task_type, target, status, started_at, finished_at, created_at
		FROM tasks
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	summaries := make([]model.LegacyTaskSummary, 0)
	for rows.Next() {
		summary, err := scanLegacyTaskSummary(rows)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return summaries, nil
}

func GetLegacyTaskSummary(db *sql.DB, legacyTaskID int64) (model.LegacyTaskSummary, error) {
	row := db.QueryRow(`
		SELECT id, task_type, target, status, started_at, finished_at, created_at
		FROM tasks
		WHERE id = ?`, legacyTaskID)
	return scanLegacyTaskSummary(row)
}

type legacyTaskSummaryScanner interface {
	Scan(dest ...interface{}) error
}

func scanLegacyTaskSummary(scanner legacyTaskSummaryScanner) (model.LegacyTaskSummary, error) {
	var summary model.LegacyTaskSummary
	var startedAt, finishedAt sql.NullString
	if err := scanner.Scan(
		&summary.LegacyTaskID,
		&summary.TaskType,
		&summary.Target,
		&summary.Status,
		&startedAt,
		&finishedAt,
		&summary.CreatedAt,
	); err != nil {
		return model.LegacyTaskSummary{}, err
	}
	summary.StartedAt = startedAt.String
	summary.FinishedAt = finishedAt.String
	summary.IsHistorical = true
	summary.ExactDiffAvailable = false
	return summary, nil
}

func applyNullableTaskFields(t *model.Task, errorMsg, reportError, startedAt, finishedAt, updatedAt sql.NullString) {
	if errorMsg.Valid {
		t.ErrorMsg = errorMsg.String
	}
	if reportError.Valid {
		t.ReportError = reportError.String
	}
	if startedAt.Valid {
		t.StartedAt = startedAt.String
	}
	if finishedAt.Valid {
		t.FinishedAt = finishedAt.String
	}
	if updatedAt.Valid {
		t.UpdatedAt = updatedAt.String
	}
}

// UpdateTaskReportError records a report-generation diagnostic without changing
// the task's terminal scan state or its collected results.
func UpdateTaskReportError(db *sql.DB, taskID int64, reportError string) error {
	reportError = strings.TrimSpace(reportError)
	if reportError == "" {
		_, err := db.Exec(`
			UPDATE tasks
			SET report_error = NULL, updated_at = datetime('now')
			WHERE id = ?`, taskID)
		return err
	}

	_, err := db.Exec(`
		UPDATE tasks
		SET report_error = ?, updated_at = datetime('now')
		WHERE id = ?`, reportError, taskID)
	return err
}

func UpdateTaskStatus(db *sql.DB, taskID int64, toStatus string, errorMsg string) error {
	fromStatus, err := GetTaskStatus(db, taskID)
	if err != nil {
		return err
	}

	if !isValidTaskTransition(fromStatus, toStatus) {
		return fmt.Errorf("invalid task transition: %s -> %s", fromStatus, toStatus)
	}

	switch toStatus {
	case model.TaskStatusRunning:
		_, err = db.Exec(`
			UPDATE tasks
			SET status = ?, started_at = datetime('now'), updated_at = datetime('now')
			WHERE id = ?`,
			toStatus,
			taskID,
		)
	case model.TaskStatusSuccess:
		_, err = db.Exec(`
			UPDATE tasks
			SET status = ?, progress = 100, finished_at = datetime('now'), error_msg = NULL, updated_at = datetime('now')
			WHERE id = ?`,
			toStatus,
			taskID,
		)
	case model.TaskStatusFailed:
		_, err = db.Exec(`
			UPDATE tasks
			SET status = ?, finished_at = datetime('now'), error_msg = ?, updated_at = datetime('now')
			WHERE id = ?`,
			toStatus,
			errorMsg,
			taskID,
		)
	case model.TaskStatusCanceled:
		_, err = db.Exec(`
			UPDATE tasks
			SET status = ?, finished_at = datetime('now'), updated_at = datetime('now')
			WHERE id = ?`,
			toStatus,
			taskID,
		)
	default:
		_, err = db.Exec(`
			UPDATE tasks
			SET status = ?, updated_at = datetime('now')
			WHERE id = ?`,
			toStatus,
			taskID,
		)
	}

	return err
}

func UpdateTaskProgress(db *sql.DB, taskID int64, progress int) error {
	if progress < 0 {
		progress = 0
	}
	if progress > 100 {
		progress = 100
	}
	_, err := db.Exec(`
		UPDATE tasks
		SET progress = ?, updated_at = datetime('now')
		WHERE id = ?`,
		progress,
		taskID,
	)
	return err
}

func CancelTask(db *sql.DB, taskID int64) error {
	result, err := db.Exec(`
		UPDATE tasks
		SET status = ?, updated_at = datetime('now')
		WHERE id = ? AND status IN (?, ?)`,
		model.TaskStatusCancelRequested,
		taskID,
		model.TaskStatusQueued,
		model.TaskStatusRunning,
	)
	if err != nil {
		return err
	}

	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated > 0 {
		return nil
	}

	status, err := GetTaskStatus(db, taskID)
	if err != nil {
		return err
	}
	if status == model.TaskStatusCancelRequested {
		return nil
	}
	return fmt.Errorf("task %d cannot be canceled in status %s", taskID, status)
}

func IsTaskCanceled(db *sql.DB, taskID int64) (bool, error) {
	status, err := GetTaskStatus(db, taskID)
	if err != nil {
		return false, err
	}
	return status == model.TaskStatusCancelRequested || status == model.TaskStatusCanceled, nil
}

// FinalizeTask is the only transition from an executing task to a terminal state.
// Its conditional update is the linearization point between a completed scan and
// a concurrent cancellation request.
func FinalizeTask(db *sql.DB, taskID int64, executionErr error) (string, error) {
	finalStatus := model.TaskStatusSuccess
	if executionErr != nil {
		finalStatus = model.TaskStatusFailed
	}

	result, err := updateTaskTerminalStatus(db, taskID, finalStatus, executionErr)
	if err != nil {
		return "", err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if updated > 0 {
		return finalStatus, nil
	}

	result, err = db.Exec(`
		UPDATE tasks
		SET status = ?, finished_at = datetime('now'), error_msg = NULL, updated_at = datetime('now')
		WHERE id = ? AND status = ?`,
		model.TaskStatusCanceled,
		taskID,
		model.TaskStatusCancelRequested,
	)
	if err != nil {
		return "", err
	}
	updated, err = result.RowsAffected()
	if err != nil {
		return "", err
	}
	if updated > 0 {
		return model.TaskStatusCanceled, nil
	}

	status, err := GetTaskStatus(db, taskID)
	if err != nil {
		return "", err
	}
	return "", fmt.Errorf("task %d is already terminal or cannot be finalized from status %s", taskID, status)
}

func updateTaskTerminalStatus(db *sql.DB, taskID int64, finalStatus string, executionErr error) (sql.Result, error) {
	if finalStatus == model.TaskStatusSuccess {
		return db.Exec(`
			UPDATE tasks
			SET status = ?, progress = 100, finished_at = datetime('now'), error_msg = NULL, updated_at = datetime('now')
			WHERE id = ? AND status IN (?, ?)`,
			finalStatus,
			taskID,
			model.TaskStatusQueued,
			model.TaskStatusRunning,
		)
	}

	return db.Exec(`
		UPDATE tasks
		SET status = ?, finished_at = datetime('now'), error_msg = ?, updated_at = datetime('now')
		WHERE id = ? AND status IN (?, ?)`,
		finalStatus,
		executionErr.Error(),
		taskID,
		model.TaskStatusQueued,
		model.TaskStatusRunning,
	)
}

func isValidTaskTransition(fromStatus, toStatus string) bool {
	if fromStatus == toStatus {
		return true
	}

	allowed := map[string]map[string]bool{
		model.TaskStatusQueued: {
			model.TaskStatusRunning:         true,
			model.TaskStatusCancelRequested: true,
		},
		model.TaskStatusRunning: {
			model.TaskStatusCancelRequested: true,
		},
		model.TaskStatusCancelRequested: {
			model.TaskStatusCanceled: true,
		},
		model.TaskStatusSuccess:  {},
		model.TaskStatusFailed:   {},
		model.TaskStatusCanceled: {},
	}

	next, ok := allowed[fromStatus]
	if !ok {
		return false
	}
	return next[toStatus]
}

func fileExists(name string) bool {
	info, err := os.Stat(name)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

type builtinFingerprint struct {
	ServiceName   string
	BannerPattern string
	MatchType     string
	Protocol      string
	Port          int
	Description   string
}

func seedBuiltinFingerprints(db *sql.DB) error {
	rules := []builtinFingerprint{
		{ServiceName: "nginx", BannerPattern: "nginx", MatchType: "contains", Protocol: "http", Description: "Nginx HTTP server"},
		{ServiceName: "apache", BannerPattern: "apache", MatchType: "contains", Protocol: "http", Description: "Apache HTTP Server"},
		{ServiceName: "iis", BannerPattern: "microsoft-iis", MatchType: "contains", Protocol: "http", Description: "Microsoft IIS"},
		{ServiceName: "caddy", BannerPattern: "caddy", MatchType: "contains", Protocol: "http", Description: "Caddy web server"},
		{ServiceName: "lighttpd", BannerPattern: "lighttpd", MatchType: "contains", Protocol: "http", Description: "Lighttpd web server"},
		{ServiceName: "jetty", BannerPattern: "jetty", MatchType: "contains", Protocol: "http", Description: "Jetty web server"},
		{ServiceName: "grafana", BannerPattern: "grafana", MatchType: "contains", Protocol: "http", Description: "Grafana dashboard"},
		{ServiceName: "jenkins", BannerPattern: "x-jenkins", MatchType: "contains", Protocol: "http", Description: "Jenkins CI"},
		{ServiceName: "harbor", BannerPattern: "harbor", MatchType: "contains", Protocol: "http", Description: "Harbor registry"},
		{ServiceName: "kibana", BannerPattern: "kibana", MatchType: "contains", Protocol: "http", Description: "Kibana"},
		{ServiceName: "elasticsearch", BannerPattern: "elasticsearch", MatchType: "contains", Protocol: "http", Description: "Elasticsearch"},
		{ServiceName: "docker-api", BannerPattern: "docker", MatchType: "contains", Protocol: "http", Port: 2375, Description: "Docker Remote API"},
		{ServiceName: "kubernetes-api", BannerPattern: "kubernetes", MatchType: "contains", Protocol: "http", Port: 6443, Description: "Kubernetes API Server"},
		{ServiceName: "redis", BannerPattern: "redis_version", MatchType: "contains", Protocol: "tcp", Port: 6379, Description: "Redis server"},
		{ServiceName: "mysql", BannerPattern: "mysql", MatchType: "contains", Protocol: "tcp", Port: 3306, Description: "MySQL server"},
		{ServiceName: "postgresql", BannerPattern: "postgresql", MatchType: "contains", Protocol: "tcp", Port: 5432, Description: "PostgreSQL server"},
		{ServiceName: "mongodb", BannerPattern: "mongodb", MatchType: "contains", Protocol: "tcp", Port: 27017, Description: "MongoDB server"},
		{ServiceName: "openssh", BannerPattern: "openssh", MatchType: "contains", Protocol: "tcp", Port: 22, Description: "OpenSSH server"},
		{ServiceName: "pure-ftpd", BannerPattern: "pure-ftpd", MatchType: "contains", Protocol: "tcp", Port: 21, Description: "Pure-FTPd server"},
		{ServiceName: "vsftpd", BannerPattern: "vsftpd", MatchType: "contains", Protocol: "tcp", Port: 21, Description: "vsftpd server"},
		{ServiceName: "vmware-auth", BannerPattern: "vmware", MatchType: "contains", Protocol: "tcp", Description: "VMware auth daemon"},
		{ServiceName: "rdp", BannerPattern: "ms-wbt-server", MatchType: "contains", Protocol: "tcp", Port: 3389, Description: "Remote Desktop Protocol"},
	}

	for _, rule := range rules {
		if _, err := db.Exec(`
            INSERT INTO banner (service_name, banner_pattern, match_type, protocol, port, description)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(service_name, banner_pattern) DO NOTHING`,
			rule.ServiceName,
			rule.BannerPattern,
			rule.MatchType,
			rule.Protocol,
			nullIfZero(rule.Port),
			rule.Description,
		); err != nil {
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "on conflict clause does not match") {
				if _, err2 := db.Exec(`
                    INSERT OR IGNORE INTO banner (service_name, banner_pattern, match_type, protocol, port, description)
                    VALUES (?, ?, ?, ?, ?, ?)`,
					rule.ServiceName,
					rule.BannerPattern,
					rule.MatchType,
					rule.Protocol,
					nullIfZero(rule.Port),
					rule.Description,
				); err2 != nil {
					return err2
				}
				continue
			}
			return err
		}
	}

	return nil
}

func nullIfZero(v int) interface{} {
	if v == 0 {
		return nil
	}
	return v
}

func SaveResult(db *sql.DB, result model.ScanResult) error {
	record, err := normalizeScanResult(db, result)
	if err != nil {
		return err
	}
	return upsertScanResult(db, record)
}

type scanResultRecord struct {
	ip          string
	port        int
	serviceType string
}

type sqlExecer interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
}

func normalizeScanResult(db *sql.DB, result model.ScanResult) (scanResultRecord, error) {
	if !result.Open {
		return scanResultRecord{}, fmt.Errorf("skip: port is not open")
	}

	ip, portStr, err := net.SplitHostPort(result.Address)
	if err != nil {
		return scanResultRecord{}, fmt.Errorf("解析地址失败: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return scanResultRecord{}, fmt.Errorf("端口转换失败: %s", portStr)
	}

	serviceType := strings.TrimSpace(strings.ToLower(result.Product))
	if serviceType == "" {
		serviceType = MatchFingerprint(db, result.Banner)
	}
	if serviceType == "" {
		serviceType = strings.TrimSpace(strings.ToLower(result.Service))
	}
	if serviceType == "" || serviceType == "none_unknown" {
		serviceType = "unknown"
	}
	if strings.HasPrefix(serviceType, "http") {
		serviceType = "http-unknown"
	}
	if len(serviceType) > 255 {
		serviceType = serviceType[:255]
	}

	return scanResultRecord{ip: ip, port: port, serviceType: serviceType}, nil
}

func upsertScanResult(execer sqlExecer, record scanResultRecord) error {
	_, err := execer.Exec(`
        INSERT INTO scan_results (ip, port, service_id, service_type, scan_time)
        VALUES (?, ?, (SELECT id FROM banner WHERE service_name = ? LIMIT 1), ?, datetime('now'))
		ON CONFLICT(ip, port) DO UPDATE SET
            service_id   = excluded.service_id,
            service_type = excluded.service_type,
            scan_time    = datetime('now')`,
		record.ip,
		record.port,
		record.serviceType,
		record.serviceType,
	)
	return err
}

// SyncOpenPorts updates one host's current port inventory and removes ports
// that were not observed in the current scan.
func SyncOpenPorts(db *sql.DB, ip string, results []model.ScanResult) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid host IP: %s", ip)
	}

	recordsByPort := make(map[int]scanResultRecord)
	for _, result := range results {
		if !result.Open {
			continue
		}
		record, err := normalizeScanResult(db, result)
		if err != nil {
			return err
		}
		if record.ip != ip {
			return fmt.Errorf("scan result IP %s does not match host %s", record.ip, ip)
		}
		recordsByPort[record.port] = record
	}

	ports := make([]int, 0, len(recordsByPort))
	for port := range recordsByPort {
		ports = append(ports, port)
	}
	sort.Ints(ports)

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	for _, port := range ports {
		if err = upsertScanResult(tx, recordsByPort[port]); err != nil {
			return err
		}
	}

	statement := `DELETE FROM scan_results WHERE ip = ?`
	args := []interface{}{ip}
	if len(ports) > 0 {
		statement += ` AND port NOT IN (` + sqlPlaceholders(len(ports)) + `)`
		for _, port := range ports {
			args = append(args, port)
		}
	}
	if _, err = tx.Exec(statement, args...); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

// SyncScopeOpenPorts updates one host's port membership inside one scan scope.
// It intentionally does not alter another scope's port rows or the global
// scan_results cache used for latest service profiling.
func SyncScopeOpenPorts(db *sql.DB, scope, ip string, results []model.ScanResult) error {
	scope = strings.TrimSpace(scope)
	ip = strings.TrimSpace(ip)
	if scope == "" {
		return errors.New("scan scope is required")
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid host IP: %s", ip)
	}

	recordsByPort := make(map[int]scanResultRecord)
	for _, result := range results {
		if !result.Open {
			continue
		}
		record, err := normalizeScanResult(db, result)
		if err != nil {
			return err
		}
		if record.ip != ip {
			return fmt.Errorf("scan result IP %s does not match host %s", record.ip, ip)
		}
		recordsByPort[record.port] = record
	}

	ports := make([]int, 0, len(recordsByPort))
	for port := range recordsByPort {
		ports = append(ports, port)
	}
	sort.Ints(ports)

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, port := range ports {
		record := recordsByPort[port]
		if _, err := tx.Exec(`
			INSERT INTO host_inventory_scope_ports
				(scope, ip, port, service_type, first_seen, last_seen, last_checked, is_active)
			VALUES (?, ?, ?, ?, datetime('now'), datetime('now'), datetime('now'), 1)
			ON CONFLICT(scope, ip, port) DO UPDATE SET
				service_type = excluded.service_type,
				last_seen = datetime('now'),
				last_checked = datetime('now'),
				is_active = 1`,
			scope,
			ip,
			record.port,
			record.serviceType,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	statement := `
		UPDATE host_inventory_scope_ports
		SET is_active = 0, last_checked = datetime('now')
		WHERE scope = ? AND ip = ?`
	args := []interface{}{scope, ip}
	if len(ports) > 0 {
		statement += ` AND port NOT IN (` + sqlPlaceholders(len(ports)) + `)`
		for _, port := range ports {
			args = append(args, port)
		}
	}
	if _, err := tx.Exec(statement, args...); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

// DeactivateScopePortsForInactiveHosts keeps scope port membership consistent
// with the scope's host membership after a discovery run marks hosts inactive.
func DeactivateScopePortsForInactiveHosts(db *sql.DB, scope string) error {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return errors.New("scan scope is required")
	}
	_, err := db.Exec(`
		UPDATE host_inventory_scope_ports AS scope_ports
		SET is_active = 0, last_checked = datetime('now')
		WHERE scope_ports.scope = ?
			AND scope_ports.is_active = 1
			AND EXISTS (
				SELECT 1
				FROM host_inventory_scopes AS scope_hosts
				WHERE scope_hosts.scope = scope_ports.scope
					AND scope_hosts.ip = scope_ports.ip
					AND scope_hosts.is_active = 0
			)`, scope)
	return err
}

// ListScopeActivePorts returns the active port snapshot for exactly one scope.
func ListScopeActivePorts(db *sql.DB, scope string) (map[string][]int, error) {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return nil, errors.New("scan scope is required")
	}

	rows, err := db.Query(`
		SELECT ip, port
		FROM host_inventory_scope_ports
		WHERE scope = ? AND is_active = 1
		ORDER BY ip ASC, port ASC`, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	snapshot := make(map[string][]int)
	for rows.Next() {
		var ip string
		var port int
		if err := rows.Scan(&ip, &port); err != nil {
			return nil, err
		}
		snapshot[ip] = append(snapshot[ip], port)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func MatchFingerprint(db *sql.DB, banner string) string {
	return MatchFingerprintWithHint(db, banner, "", 0)
}

func MatchFingerprintWithHint(db *sql.DB, banner string, protocol string, port int) string {
	var serviceName string

	cleaned := regexp.MustCompile(`[^\x09\x0A\x0D\x20-\x7E]+`).ReplaceAllString(banner, " ")
	cleaned = strings.TrimSpace(cleaned)
	cleaned = regexp.MustCompile(`\s+`).ReplaceAllString(cleaned, " ")

	if cleaned == "" {
		return ""
	}

	protocol = strings.TrimSpace(strings.ToLower(protocol))
	rows, err := db.Query(`
        SELECT service_name, banner_pattern, match_type, protocol, port
        FROM banner
        WHERE banner_pattern <> '' AND service_name <> 'unknown'
        ORDER BY LENGTH(banner_pattern) DESC`)
	if err != nil {
		return ""
	}
	defer rows.Close()

	for rows.Next() {
		var s, p, matchType string
		var ruleProtocol sql.NullString
		var rulePort sql.NullInt64
		if err := rows.Scan(&s, &p, &matchType, &ruleProtocol, &rulePort); err != nil {
			continue
		}

		if ruleProtocol.Valid && protocol != "" && strings.ToLower(ruleProtocol.String) != protocol {
			continue
		}
		if rulePort.Valid && port > 0 && int(rulePort.Int64) != port {
			continue
		}

		if fingerprintRuleMatches(cleaned, p, matchType) {
			return s
		}
	}

	if strings.Contains(cleaned, "HTTP/") {
		if server := assist.ExtractHeader(cleaned, "Server"); server != "" {
			server = strings.TrimSpace(server)
			serverRows, err := db.Query(`
                SELECT service_name, banner_pattern, match_type
                FROM banner
                WHERE banner_pattern <> '' AND service_name <> 'unknown'
                ORDER BY LENGTH(banner_pattern) DESC`)
			if err == nil {
				for serverRows.Next() {
					var s, p, matchType string
					if err := serverRows.Scan(&s, &p, &matchType); err != nil {
						continue
					}
					if fingerprintRuleMatches(server, p, matchType) {
						_ = serverRows.Close()
						return s
					}
				}
				_ = serverRows.Close()
			}
		}
	}

	return serviceName
}

func fingerprintRuleMatches(target string, pattern string, matchType string) bool {
	target = strings.TrimSpace(target)
	pattern = strings.TrimSpace(pattern)
	matchType = strings.TrimSpace(strings.ToLower(matchType))
	if target == "" || pattern == "" {
		return false
	}

	switch matchType {
	case "regexp", "regex":
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(target)
	case "like":
		quoted := regexp.QuoteMeta(pattern)
		quoted = strings.ReplaceAll(quoted, "%", ".*")
		quoted = strings.ReplaceAll(quoted, "_", ".")
		re, err := regexp.Compile("^" + quoted + "$")
		if err != nil {
			return false
		}
		return re.MatchString(target)
	default:
		return strings.Contains(strings.ToLower(target), strings.ToLower(pattern))
	}
}

func SaveDomainScanResult(db *sql.DB, ip string, openPorts []model.ScanResult) error {
	var ports []int
	var title string

	for _, result := range openPorts {
		_, portStr, _ := net.SplitHostPort(result.Address)
		port, _ := strconv.Atoi(portStr)
		ports = append(ports, port)

		if title == "" && strings.HasPrefix(result.Service, "http") {
			title = extractTitleFromBanner(result.Banner)
			if title == "" {
				title = assist.GetWebsiteTitle(ip, port)
			}
		}
	}

	_, err := db.Exec(`
        UPDATE domain_ips 
        SET ports = ?,
            is_active = 1,
            last_seen = datetime('now'),
            subdomain = (SELECT subdomain FROM domain_info WHERE id = domain_id LIMIT 1)
        WHERE ip = ?`,
		toJSON(ports),
		ip)
	if err != nil {
		return fmt.Errorf("更新端口信息失败: %v", err)
	}

	if title != "" {
		_, err = db.Exec(`
            UPDATE domain_info 
            SET title = ?, last_scan = datetime('now'), last_seen = datetime('now'), is_active = 1
            WHERE id = (SELECT domain_id FROM domain_ips WHERE ip = ? LIMIT 1)`,
			title, ip)
		if err != nil {
			return fmt.Errorf("更新标题失败: %v", err)
		}
	} else {
		_, err = db.Exec(`
            UPDATE domain_info
            SET last_scan = datetime('now'), last_seen = datetime('now'), is_active = 1
            WHERE id = (SELECT domain_id FROM domain_ips WHERE ip = ? LIMIT 1)`,
			ip)
		if err != nil {
			return fmt.Errorf("更新域名活跃状态失败: %v", err)
		}
	}

	return nil
}

// SyncHostInventory synchronizes a scan scope and then derives the IP-level
// inventory aggregate from all of that IP's scope memberships. The legacy
// source column is preserved as a compatibility hint only; it never decides
// which scope membership should become inactive.
func SyncHostInventory(db *sql.DB, scope string, aliveIPs []string) error {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	affectedIPs, err := syncHostScopeInventoryTx(tx, scope, aliveIPs)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, ip := range affectedIPs {
		if err := refreshHostInventoryAggregateTx(tx, ip, scope); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

// SyncHostScopeInventory updates one scope without modifying the IP-level
// aggregate. It remains available for callers that only need to maintain the
// explicit membership relation.
func SyncHostScopeInventory(db *sql.DB, scope string, aliveIPs []string) error {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	if _, err := syncHostScopeInventoryTx(tx, scope, aliveIPs); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func syncHostScopeInventoryTx(tx *sql.Tx, scope string, aliveIPs []string) ([]string, error) {
	existingIPs, err := listScopeIPsTx(tx, scope)
	if err != nil {
		return nil, err
	}
	uniqueIPs := normalizedHostIPs(scope, aliveIPs)
	affected := make(map[string]struct{}, len(existingIPs)+len(uniqueIPs))
	for _, ip := range existingIPs {
		affected[ip] = struct{}{}
	}
	for _, ip := range uniqueIPs {
		affected[ip] = struct{}{}
		if _, err := tx.Exec(`
			INSERT INTO host_inventory_scopes (scope, ip, first_seen, last_seen, last_checked, is_active)
			VALUES (?, ?, datetime('now'), datetime('now'), datetime('now'), 1)
			ON CONFLICT(scope, ip) DO UPDATE SET
				last_seen = datetime('now'),
				last_checked = datetime('now'),
				is_active = 1`,
			scope,
			ip,
		); err != nil {
			return nil, err
		}
	}

	query := `
		UPDATE host_inventory_scopes
		SET is_active = 0, last_checked = datetime('now')
		WHERE scope = ?`
	args := []interface{}{scope}
	if len(uniqueIPs) > 0 {
		query += ` AND ip NOT IN (` + sqlPlaceholders(len(uniqueIPs)) + `)`
		for _, ip := range uniqueIPs {
			args = append(args, ip)
		}
	}
	if _, err := tx.Exec(query, args...); err != nil {
		return nil, err
	}

	result := make([]string, 0, len(affected))
	for ip := range affected {
		result = append(result, ip)
	}
	sort.Strings(result)
	return result, nil
}

func listScopeIPsTx(tx *sql.Tx, scope string) ([]string, error) {
	rows, err := tx.Query(`SELECT ip FROM host_inventory_scopes WHERE scope = ?`, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ips := make([]string, 0)
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func normalizedHostIPs(scope string, aliveIPs []string) []string {
	seen := make(map[string]struct{}, len(aliveIPs))
	uniqueIPs := make([]string, 0, len(aliveIPs))
	for _, ip := range aliveIPs {
		member := model.HostScopeMembership{Scope: scope, IP: strings.TrimSpace(ip)}
		if !member.Valid() {
			continue
		}
		if _, ok := seen[member.IP]; ok {
			continue
		}
		seen[member.IP] = struct{}{}
		uniqueIPs = append(uniqueIPs, member.IP)
	}
	sort.Strings(uniqueIPs)
	return uniqueIPs
}

func refreshHostInventoryAggregateTx(tx *sql.Tx, ip, fallbackSource string) error {
	var firstSeen, lastSeen, lastChecked string
	var isActive int
	if err := tx.QueryRow(`
		SELECT MIN(first_seen), MAX(last_seen), MAX(last_checked), MAX(is_active)
		FROM host_inventory_scopes
		WHERE ip = ?`, ip).Scan(&firstSeen, &lastSeen, &lastChecked, &isActive); err != nil {
		return err
	}

	_, err := tx.Exec(`
		INSERT INTO host_inventory (ip, source, first_seen, last_seen, last_scan, is_active)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			first_seen = CASE
				WHEN host_inventory.first_seen <= excluded.first_seen THEN host_inventory.first_seen
				ELSE excluded.first_seen
			END,
			last_seen = excluded.last_seen,
			last_scan = excluded.last_scan,
			is_active = excluded.is_active`,
		ip,
		fallbackSource,
		firstSeen,
		lastSeen,
		lastChecked,
		isActive,
	)
	return err
}

type HostScopeMembershipQuery struct {
	Scope    string
	IP       string
	IsActive *bool
}

func ListHostScopeMemberships(db *sql.DB, query HostScopeMembershipQuery) ([]model.HostScopeMembership, error) {
	clauses := make([]string, 0, 3)
	args := make([]interface{}, 0, 3)
	if scope := strings.TrimSpace(query.Scope); scope != "" {
		clauses = append(clauses, "scope = ?")
		args = append(args, scope)
	}
	if ip := strings.TrimSpace(query.IP); ip != "" {
		clauses = append(clauses, "ip = ?")
		args = append(args, ip)
	}
	if query.IsActive != nil {
		clauses = append(clauses, "is_active = ?")
		args = append(args, *query.IsActive)
	}

	statement := `
		SELECT scope, ip, first_seen, last_seen, last_checked, is_active
		FROM host_inventory_scopes`
	if len(clauses) > 0 {
		statement += " WHERE " + strings.Join(clauses, " AND ")
	}
	statement += " ORDER BY scope ASC, ip ASC"

	rows, err := db.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	memberships := make([]model.HostScopeMembership, 0)
	for rows.Next() {
		var membership model.HostScopeMembership
		if err := rows.Scan(
			&membership.Scope,
			&membership.IP,
			&membership.FirstSeen,
			&membership.LastSeen,
			&membership.LastChecked,
			&membership.IsActive,
		); err != nil {
			return nil, err
		}
		memberships = append(memberships, membership)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return memberships, nil
}

type HostInventoryQuery struct {
	Scope    string
	Source   string
	IsActive *bool
}

func ListHostInventory(db *sql.DB, query HostInventoryQuery) ([]model.HostInventory, error) {
	clauses := make([]string, 0, 2)
	args := make([]interface{}, 0, 2)

	scope := strings.TrimSpace(query.Scope)
	if scope == "" {
		// source remains a one-version compatibility alias for scope.
		scope = strings.TrimSpace(query.Source)
	}
	if scope != "" {
		clauses = append(clauses, `EXISTS (
			SELECT 1
			FROM host_inventory_scopes AS scope_filter
			WHERE scope_filter.ip = host_inventory.ip AND scope_filter.scope = ?
		)`)
		args = append(args, scope)
	}
	if query.IsActive != nil {
		clauses = append(clauses, "host_inventory.is_active = ?")
		if *query.IsActive {
			args = append(args, 1)
		} else {
			args = append(args, 0)
		}
	}

	statement := `
		SELECT host_inventory.id,
			host_inventory.ip,
			host_inventory.source,
			host_inventory.first_seen,
			host_inventory.last_seen,
			host_inventory.last_scan,
			host_inventory.is_active,
			COUNT(scope_members.scope) AS scope_count
		FROM host_inventory
		LEFT JOIN host_inventory_scopes AS scope_members ON scope_members.ip = host_inventory.ip`
	if len(clauses) > 0 {
		statement += " WHERE " + strings.Join(clauses, " AND ")
	}
	statement += `
		GROUP BY host_inventory.id
		ORDER BY host_inventory.ip ASC`

	rows, err := db.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	hosts := make([]model.HostInventory, 0)
	for rows.Next() {
		var host model.HostInventory
		var source, lastScan sql.NullString
		var isActive int
		if err := rows.Scan(
			&host.ID,
			&host.IP,
			&source,
			&host.FirstSeen,
			&host.LastSeen,
			&lastScan,
			&isActive,
			&host.ScopeCount,
		); err != nil {
			return nil, err
		}
		host.Source = source.String
		host.LastScan = lastScan.String
		host.IsActive = isActive != 0
		hosts = append(hosts, host)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return hosts, nil
}

func GetAssetDetail(db *sql.DB, ip string) (model.AssetDetail, error) {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return model.AssetDetail{}, fmt.Errorf("invalid host IP: %s", ip)
	}

	var detail model.AssetDetail
	var source, lastScan sql.NullString
	var isActive int
	err := db.QueryRow(`
		SELECT host_inventory.id,
			host_inventory.ip,
			host_inventory.source,
			host_inventory.first_seen,
			host_inventory.last_seen,
			host_inventory.last_scan,
			host_inventory.is_active,
			COUNT(scope_members.scope) AS scope_count
		FROM host_inventory
		LEFT JOIN host_inventory_scopes AS scope_members ON scope_members.ip = host_inventory.ip
		WHERE host_inventory.ip = ?
		GROUP BY host_inventory.id`, ip).Scan(
		&detail.Host.ID,
		&detail.Host.IP,
		&source,
		&detail.Host.FirstSeen,
		&detail.Host.LastSeen,
		&lastScan,
		&isActive,
		&detail.Host.ScopeCount,
	)
	if err != nil {
		return model.AssetDetail{}, err
	}
	detail.Host.Source = source.String
	detail.Host.LastScan = lastScan.String
	detail.Host.IsActive = isActive != 0
	detail.Scopes, err = ListHostScopeMemberships(db, HostScopeMembershipQuery{IP: ip})
	if err != nil {
		return model.AssetDetail{}, err
	}

	rows, err := db.Query(`
		SELECT port, service_type, scan_time
		FROM scan_results
		WHERE ip = ?
		ORDER BY port ASC`, ip)
	if err != nil {
		return model.AssetDetail{}, err
	}
	defer rows.Close()

	detail.Ports = make([]model.AssetPort, 0)
	for rows.Next() {
		var port model.AssetPort
		if err := rows.Scan(&port.Port, &port.Service, &port.LastSeenAt); err != nil {
			return model.AssetDetail{}, err
		}
		detail.Ports = append(detail.Ports, port)
	}
	if err := rows.Err(); err != nil {
		return model.AssetDetail{}, err
	}
	return detail, nil
}

func SaveTaskChangeSummary(db *sql.DB, summary model.TaskChangeSummary) error {
	if summary.TaskID <= 0 {
		return fmt.Errorf("invalid task ID: %d", summary.TaskID)
	}
	summary.Target = strings.TrimSpace(summary.Target)
	if summary.Target == "" {
		return fmt.Errorf("task change summary target is required")
	}

	payload, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	_, err = db.Exec(`
		INSERT INTO task_change_summaries (task_id, target, summary_json, created_at, updated_at)
		VALUES (?, ?, ?, datetime('now'), datetime('now'))
		ON CONFLICT(task_id) DO UPDATE SET
			target = excluded.target,
			summary_json = excluded.summary_json,
			updated_at = datetime('now')`,
		summary.TaskID,
		summary.Target,
		string(payload),
	)
	return err
}

func GetTaskChangeSummary(db *sql.DB, taskID int64) (model.TaskChangeSummary, error) {
	var payload string
	var generatedAt string
	err := db.QueryRow(`
		SELECT summary_json, updated_at
		FROM task_change_summaries
		WHERE task_id = ?`, taskID).Scan(&payload, &generatedAt)
	if err != nil {
		return model.TaskChangeSummary{}, err
	}

	var summary model.TaskChangeSummary
	if err := json.Unmarshal([]byte(payload), &summary); err != nil {
		return model.TaskChangeSummary{}, err
	}
	summary.GeneratedAt = generatedAt
	return summary, nil
}

func extractTitleFromBanner(banner string) string {
	if !strings.Contains(banner, "HTTP/") {
		return ""
	}

	re := regexp.MustCompile(`(?is)<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		title = strings.ReplaceAll(title, "\n", " ")
		title = strings.Join(strings.Fields(title), " ")
		if len(title) > 250 {
			title = title[:250] + "..."
		}
		return title
	}
	return ""
}

func toJSON(data interface{}) string {
	b, _ := json.Marshal(data)
	return string(b)
}

func SaveDomainInfo(db *sql.DB, mainDomain, subdomain string, isWildcard bool, title string, source string, firstSeen time.Time) (int64, error) {
	log.Printf("保存子域名：%s（来源：%s）", subdomain, source)

	existingSources := make(map[string]bool)
	if existing, err := db.Query("SELECT source FROM domain_info WHERE subdomain = ?", subdomain); err == nil {
		for existing.Next() {
			var oldSource string
			if err := existing.Scan(&oldSource); err == nil {
				for _, s := range strings.Split(oldSource, ",") {
					existingSources[s] = true
				}
			}
		}
		existing.Close()
	}

	if !existingSources[source] {
		existingSources[source] = true
	}

	var uniqueSources []string
	for s := range existingSources {
		uniqueSources = append(uniqueSources, s)
	}
	newSource := strings.Join(uniqueSources, ",")

	if len(newSource) > 255 {
		newSource = newSource[:255]
	}

	firstSeenValue := sqliteTimeOrNow(firstSeen)

	res, err := db.Exec(`
        INSERT INTO domain_info 
        (domain, subdomain, is_wildcard, is_active, title, first_seen, last_seen, last_scan, source)
        VALUES (?, ?, ?, 1, ?, ?, datetime('now'), datetime('now'), ?)`,
		mainDomain,
		subdomain,
		isWildcard,
		title,
		firstSeenValue,
		newSource,
	)
	if err == nil {
		id, _ := res.LastInsertId()
		return id, nil
	}

	_, err = db.Exec(`
        UPDATE domain_info
        SET 
            title     = CASE WHEN ? <> '' THEN ? ELSE title END,
            source    = ?,
            is_wildcard = CASE WHEN ? THEN 1 ELSE is_wildcard END,
            first_seen = CASE
                WHEN first_seen IS NULL OR first_seen = '' THEN ?
                WHEN ? < first_seen THEN ?
                ELSE first_seen
            END,
            is_active = 1,
            last_seen = datetime('now'),
            last_scan = datetime('now')
        WHERE subdomain = ?`,
		title, title,
		newSource,
		isWildcard,
		firstSeenValue,
		firstSeenValue,
		firstSeenValue,
		subdomain,
	)
	if err != nil {
		return 0, err
	}

	var id int64
	if err := db.QueryRow(`SELECT id FROM domain_info WHERE subdomain = ?`, subdomain).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func sqliteTimeOrNow(t time.Time) string {
	if t.IsZero() {
		return time.Now().UTC().Format("2006-01-02 15:04:05")
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}

func SaveDomainIP(db *sql.DB, domainID int64, ip string, subdomain string, ports []int) error {
	portsJSON, _ := json.Marshal(ports)
	_, err := db.Exec(`
        INSERT INTO domain_ips
        (domain_id, subdomain, ip, ports, first_seen, last_seen, is_active)
        VALUES (?, ?, ?, ?, datetime('now'), datetime('now'), 1)
        ON CONFLICT(domain_id, ip) DO UPDATE SET
            subdomain = excluded.subdomain,
            ports     = CASE WHEN excluded.ports <> 'null' THEN excluded.ports ELSE domain_ips.ports END,
            last_seen = datetime('now'),
            is_active = 1`,
		domainID,
		subdomain,
		ip,
		string(portsJSON),
	)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
        UPDATE domain_info
        SET is_active = 1, last_seen = datetime('now')
        WHERE id = ?`,
		domainID,
	)
	return err
}

func SyncDomainIPs(db *sql.DB, domainID int64, subdomain string, ips []string, ports []int) error {
	subdomain = strings.TrimSpace(subdomain)
	if domainID <= 0 || subdomain == "" {
		return nil
	}

	seen := make(map[string]struct{}, len(ips))
	uniqueIPs := make([]string, 0, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		uniqueIPs = append(uniqueIPs, ip)
		if err := SaveDomainIP(db, domainID, ip, subdomain, ports); err != nil {
			return err
		}
	}

	query := `
        UPDATE domain_ips
        SET is_active = 0
        WHERE domain_id = ? AND subdomain = ?`
	args := []interface{}{domainID, subdomain}

	if len(uniqueIPs) > 0 {
		query += ` AND ip NOT IN (` + sqlPlaceholders(len(uniqueIPs)) + `)`
		for _, ip := range uniqueIPs {
			args = append(args, ip)
		}
	}

	_, err := db.Exec(query, args...)
	return err
}

func MarkDomainInactive(db *sql.DB, subdomain string) error {
	subdomain = strings.TrimSpace(subdomain)
	if subdomain == "" {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.Exec(`
        UPDATE domain_info
        SET is_active = 0, last_scan = datetime('now')
        WHERE subdomain = ?`,
		subdomain,
	); err != nil {
		return err
	}

	if _, err = tx.Exec(`
        UPDATE domain_ips
        SET is_active = 0
        WHERE subdomain = ?`,
		subdomain,
	); err != nil {
		return err
	}

	return tx.Commit()
}

func sqlPlaceholders(n int) string {
	if n <= 0 {
		return ""
	}

	parts := make([]string, n)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ",")
}

func ListOpenPortsByIP(db *sql.DB, ip string) ([]int, error) {
	rows, err := db.Query(`
		SELECT port
		FROM scan_results
		WHERE ip = ?
		ORDER BY port ASC`, strings.TrimSpace(ip))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []int
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		if p > 0 {
			ports = append(ports, p)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return ports, nil
}

func ListKnownSubdomains(db *sql.DB, mainDomain string) ([]string, error) {
	mainDomain = strings.TrimSpace(strings.ToLower(mainDomain))
	if mainDomain == "" {
		return nil, nil
	}

	rows, err := db.Query(`
        SELECT subdomain
        FROM domain_info
        WHERE domain = ? OR subdomain = ? OR subdomain LIKE ?
        ORDER BY subdomain ASC`,
		mainDomain,
		mainDomain,
		"%."+mainDomain,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subdomains []string
	for rows.Next() {
		var subdomain string
		if err := rows.Scan(&subdomain); err != nil {
			return nil, err
		}
		subdomain = strings.TrimSpace(strings.ToLower(subdomain))
		if subdomain != "" {
			subdomains = append(subdomains, subdomain)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return subdomains, nil
}
