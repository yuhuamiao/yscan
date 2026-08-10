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

const t320FrozenProductRolesMigration = "t320-frozen-product-roles-v2"

func InitDB() (*sql.DB, error) {
	return InitDBAt(sqliteFile)
}

// InitDBAt applies the production schema and migrations to an explicit SQLite
// file. It is used by isolated upgrade verification and never changes the
// default asm.db location used by InitDB.
func InitDBAt(databasePath string) (*sql.DB, error) {
	databasePath = strings.TrimSpace(databasePath)
	if databasePath == "" {
		return nil, errors.New("SQLite database path is required")
	}
	dbExists := fileExists(databasePath)

	db, err := sql.Open("sqlite3", databasePath)
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
		log.Printf("检测到不存在 %s，正在初始化数据库结构...", databasePath)
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
	hadConclusionEvidenceStatus, err := sqliteTableHasColumn(db, "asset_fingerprint_conclusions", "version_source_count")
	if err != nil {
		return err
	}
	hadRunTrigger, err := sqliteTableHasColumn(db, "scan_task_runs", "trigger")
	if err != nil {
		return err
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			name TEXT PRIMARY KEY,
			applied_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
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
			trigger TEXT NOT NULL DEFAULT 'scheduled',
			stage TEXT NOT NULL DEFAULT 'queued',
			progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
			target TEXT NOT NULL,
			scan_type TEXT NOT NULL CHECK (scan_type IN ('ip', 'subnet')),
			config_json TEXT NOT NULL DEFAULT '{}',
			config_hash TEXT NOT NULL DEFAULT '',
			error_message TEXT,
			report_path TEXT,
			audit_report_path TEXT,
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
		`CREATE TABLE IF NOT EXISTS scan_task_run_protocol_evidence (
			scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id) ON DELETE CASCADE,
			ip TEXT NOT NULL, port INTEGER NOT NULL, evidence_type TEXT NOT NULL,
			probe_name TEXT NOT NULL DEFAULT '', protocol TEXT NOT NULL,
			responded INTEGER NOT NULL DEFAULT 0 CHECK (responded IN (0, 1)), status_code INTEGER,
			outcome TEXT NOT NULL DEFAULT '', diagnostic TEXT NOT NULL DEFAULT '',
			server TEXT, title TEXT,
			banner_captured_length INTEGER NOT NULL DEFAULT 0, banner_sha256 TEXT,
			banner_truncated INTEGER NOT NULL DEFAULT 0 CHECK (banner_truncated IN (0, 1)),
			header_captured_length INTEGER NOT NULL DEFAULT 0, header_sha256 TEXT,
			header_truncated INTEGER NOT NULL DEFAULT 0 CHECK (header_truncated IN (0, 1)),
			body_captured_length INTEGER NOT NULL DEFAULT 0, body_sha256 TEXT,
			body_truncated INTEGER NOT NULL DEFAULT 0 CHECK (body_truncated IN (0, 1)),
			PRIMARY KEY (scan_task_run_id, ip, port, evidence_type, protocol, probe_name)
		)`,
		`CREATE TABLE IF NOT EXISTS scan_task_run_validation (
			scan_task_run_id INTEGER PRIMARY KEY REFERENCES scan_task_runs(id) ON DELETE CASCADE,
			status TEXT NOT NULL CHECK (status IN ('disabled', 'not_started', 'no_candidates', 'success', 'failed')),
			identified_product_count INTEGER NOT NULL DEFAULT 0,
			mapped_product_count INTEGER NOT NULL DEFAULT 0,
			unmapped_products_json TEXT NOT NULL DEFAULT '[]',
			candidate_endpoint_count INTEGER NOT NULL DEFAULT 0,
			executed_endpoint_count INTEGER NOT NULL DEFAULT 0,
			template_count INTEGER NOT NULL DEFAULT 0,
			executed_template_count INTEGER NOT NULL DEFAULT 0,
			finding_count INTEGER NOT NULL DEFAULT 0,
			started_at TEXT, finished_at TEXT, error_message TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS scan_task_run_endpoint_validation (
			scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id) ON DELETE CASCADE,
			ip TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
			status TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			identified_product_count INTEGER NOT NULL DEFAULT 0,
			mapped_product_count INTEGER NOT NULL DEFAULT 0,
			unmapped_products_json TEXT NOT NULL DEFAULT '[]',
			candidate_template_count INTEGER NOT NULL DEFAULT 0,
			executed_template_count INTEGER NOT NULL DEFAULT 0,
			finding_count INTEGER NOT NULL DEFAULT 0,
			started_at TEXT,
			finished_at TEXT,
			error_message TEXT,
			PRIMARY KEY (scan_task_run_id, ip, port, protocol)
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
			description TEXT,
			evidence TEXT,
			PRIMARY KEY (scan_task_run_id, finding_key)
		)`,
		`CREATE TABLE IF NOT EXISTS scan_task_run_template_candidates (
			scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id), template_id TEXT NOT NULL, path TEXT NOT NULL, source TEXT NOT NULL, reason TEXT NOT NULL,
			template_sha256 TEXT, template_set_revision TEXT, template_mapping_import_id INTEGER,
			PRIMARY KEY (scan_task_run_id, template_id, path)
		)`,
		`CREATE TABLE IF NOT EXISTS scan_task_run_template_candidate_endpoints (
			scan_task_run_id INTEGER NOT NULL,
			template_id TEXT NOT NULL,
			path TEXT NOT NULL,
			ip TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			product_key TEXT NOT NULL DEFAULT '',
			executed INTEGER NOT NULL DEFAULT 0 CHECK (executed IN (0, 1)),
			PRIMARY KEY (scan_task_run_id, template_id, path, ip, port, protocol),
			FOREIGN KEY (scan_task_run_id, template_id, path)
				REFERENCES scan_task_run_template_candidates(scan_task_run_id, template_id, path) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS scan_task_run_template_candidate_products (
			scan_task_run_id INTEGER NOT NULL,
			template_id TEXT NOT NULL,
			path TEXT NOT NULL,
			ip TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			product_key TEXT NOT NULL,
			PRIMARY KEY (scan_task_run_id, template_id, path, ip, port, protocol, product_key),
			FOREIGN KEY (scan_task_run_id, template_id, path, ip, port, protocol)
				REFERENCES scan_task_run_template_candidate_endpoints(scan_task_run_id, template_id, path, ip, port, protocol) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_sources (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			source_key TEXT NOT NULL UNIQUE,
			repository_url TEXT NOT NULL,
			license TEXT,
			status TEXT NOT NULL DEFAULT 'enabled',
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_source_bootstrap_diagnostics (
			source_key TEXT PRIMARY KEY,
			last_error TEXT NOT NULL DEFAULT '',
			last_failed_at DATETIME,
			resolved_at DATETIME,
			updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_imports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fingerprint_source_id INTEGER NOT NULL REFERENCES fingerprint_sources(id) ON DELETE CASCADE,
			commit_hash TEXT NOT NULL,
			content_sha256 TEXT NOT NULL,
			upstream_content_sha256 TEXT NOT NULL DEFAULT '',
			adapter_version TEXT NOT NULL DEFAULT 'legacy-v1',
			projection_sha256 TEXT NOT NULL DEFAULT '',
			manifest_json TEXT NOT NULL,
			rule_total INTEGER NOT NULL DEFAULT 0,
			executable_total INTEGER NOT NULL DEFAULT 0,
			unsupported_total INTEGER NOT NULL DEFAULT 0,
			import_error_total INTEGER NOT NULL DEFAULT 0,
			error_summary TEXT,
			is_active INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)),
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(fingerprint_source_id, commit_hash, content_sha256)
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_source_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fingerprint_import_id INTEGER NOT NULL REFERENCES fingerprint_imports(id) ON DELETE CASCADE,
			source_rule_id TEXT,
			source_path TEXT NOT NULL,
			content_sha256 TEXT NOT NULL,
			raw_content TEXT NOT NULL,
			raw_structure TEXT,
			import_status TEXT NOT NULL CHECK (import_status IN ('executable', 'unsupported', 'import_error')),
			import_error TEXT,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(fingerprint_import_id, source_path, content_sha256)
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_products (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			canonical_name TEXT NOT NULL UNIQUE,
			vendor TEXT,
			aliases_json TEXT,
			cpe TEXT,
			product_role TEXT NOT NULL DEFAULT 'application',
			exclusive_group TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fingerprint_source_rule_id INTEGER NOT NULL UNIQUE REFERENCES fingerprint_source_rules(id) ON DELETE CASCADE,
			fingerprint_product_id INTEGER NOT NULL REFERENCES fingerprint_products(id),
			source_product_name TEXT NOT NULL DEFAULT '',
			protocol TEXT NOT NULL,
			soft_match INTEGER NOT NULL DEFAULT 0 CHECK (soft_match IN (0, 1)),
			version_template TEXT,
			cpe TEXT,
			tags_json TEXT NOT NULL DEFAULT '[]',
			product_role TEXT NOT NULL DEFAULT 'application',
			exclusive_group TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL CHECK (status IN ('executable', 'unsupported', 'disabled'))
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_match_groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fingerprint_rule_id INTEGER NOT NULL REFERENCES fingerprint_rules(id) ON DELETE CASCADE,
			parent_id INTEGER REFERENCES fingerprint_match_groups(id) ON DELETE CASCADE,
			operator TEXT NOT NULL CHECK (operator IN ('all', 'any')),
			position INTEGER NOT NULL,
			UNIQUE(fingerprint_rule_id, parent_id, position)
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_matchers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fingerprint_match_group_id INTEGER NOT NULL REFERENCES fingerprint_match_groups(id) ON DELETE CASCADE,
			evidence_type TEXT NOT NULL,
			target TEXT,
			operator TEXT NOT NULL,
			value TEXT NOT NULL,
			version_capture TEXT,
			position INTEGER NOT NULL,
			UNIQUE(fingerprint_match_group_id, position)
		)`,
		`CREATE TABLE IF NOT EXISTS scan_task_run_fingerprint_imports (
			scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id) ON DELETE CASCADE,
			fingerprint_import_id INTEGER NOT NULL REFERENCES fingerprint_imports(id),
			PRIMARY KEY (scan_task_run_id, fingerprint_import_id)
		)`,
		`CREATE TABLE IF NOT EXISTS asset_fingerprint_matches (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id) ON DELETE CASCADE,
			fingerprint_import_id INTEGER NOT NULL REFERENCES fingerprint_imports(id),
			fingerprint_source_rule_id INTEGER NOT NULL REFERENCES fingerprint_source_rules(id),
			ip TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			product_key TEXT NOT NULL DEFAULT '',
			source_product_name TEXT NOT NULL DEFAULT '',
			product_role TEXT NOT NULL DEFAULT 'application',
			exclusive_group TEXT NOT NULL DEFAULT '',
			version TEXT,
			cpe TEXT,
			tags_json TEXT NOT NULL DEFAULT '[]',
			is_soft INTEGER NOT NULL DEFAULT 0 CHECK (is_soft IN (0, 1)),
			evidence_summary TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(scan_task_run_id, ip, port, fingerprint_source_rule_id, evidence_summary)
		)`,
		`CREATE TABLE IF NOT EXISTS asset_fingerprint_match_evidence (
			asset_fingerprint_match_id INTEGER NOT NULL REFERENCES asset_fingerprint_matches(id) ON DELETE CASCADE,
			fingerprint_matcher_id INTEGER NOT NULL REFERENCES fingerprint_matchers(id),
			evidence_type TEXT NOT NULL,
			target TEXT,
			operator TEXT NOT NULL,
			observed_sha256 TEXT NOT NULL,
			observed_length INTEGER NOT NULL,
			truncated INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0, 1)),
			summary TEXT NOT NULL,
			PRIMARY KEY (asset_fingerprint_match_id, fingerprint_matcher_id)
		)`,
		`CREATE TABLE IF NOT EXISTS asset_fingerprint_conclusions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id) ON DELETE CASCADE,
			ip TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			product_key TEXT NOT NULL,
			product_role TEXT NOT NULL DEFAULT 'application',
			exclusive_group TEXT NOT NULL DEFAULT '',
			version TEXT,
			cpe TEXT,
			tags_json TEXT NOT NULL DEFAULT '[]',
			conclusion_status TEXT NOT NULL CHECK (conclusion_status IN ('matched', 'corroborated', 'conflicted')),
			product_status TEXT NOT NULL DEFAULT 'matched' CHECK (product_status IN ('matched', 'corroborated', 'conflicted')),
			product_source_count INTEGER NOT NULL DEFAULT 1,
			version_status TEXT NOT NULL DEFAULT 'unobserved' CHECK (version_status IN ('unobserved', 'matched', 'corroborated', 'conflicted')),
			version_source_count INTEGER NOT NULL DEFAULT 0,
			cpe_status TEXT NOT NULL DEFAULT 'unobserved' CHECK (cpe_status IN ('unobserved', 'matched', 'corroborated', 'conflicted')),
			cpe_source_count INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(scan_task_run_id, ip, port, protocol, product_key)
		)`,
		`CREATE TABLE IF NOT EXISTS template_mapping_imports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			revision TEXT NOT NULL,
			content_sha256 TEXT NOT NULL UNIQUE,
			manifest_json TEXT NOT NULL,
			is_active INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)),
			created_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS fingerprint_template_mappings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			template_mapping_import_id INTEGER NOT NULL REFERENCES template_mapping_imports(id) ON DELETE CASCADE,
			product_key TEXT NOT NULL,
			source_key TEXT,
			source_rule_id TEXT,
			template_id TEXT NOT NULL,
			template_path TEXT NOT NULL,
			template_sha256 TEXT NOT NULL,
			template_set_revision TEXT NOT NULL,
			side_effect TEXT NOT NULL,
			review_status TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			disabled_at DATETIME,
			UNIQUE(template_mapping_import_id, product_key, source_rule_id, template_id, template_path)
		)`,
		`ALTER TABLE banner ADD COLUMN match_type TEXT NOT NULL DEFAULT 'contains'`,
		`ALTER TABLE banner ADD COLUMN protocol TEXT`,
		`ALTER TABLE banner ADD COLUMN port INTEGER`,
		`ALTER TABLE domain_info ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE domain_info ADD COLUMN last_seen DATETIME`,
		`ALTER TABLE domain_ips ADD COLUMN first_seen DATETIME`,
		`ALTER TABLE domain_ips ADD COLUMN last_seen DATETIME`,
		`ALTER TABLE domain_ips ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE fingerprint_rules ADD COLUMN soft_match INTEGER NOT NULL DEFAULT 0 CHECK (soft_match IN (0, 1))`,
		`ALTER TABLE fingerprint_rules ADD COLUMN version_template TEXT`,
		`ALTER TABLE fingerprint_rules ADD COLUMN cpe TEXT`,
		`ALTER TABLE fingerprint_rules ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE fingerprint_rules ADD COLUMN source_product_name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE fingerprint_rules ADD COLUMN product_role TEXT NOT NULL DEFAULT 'application'`,
		`ALTER TABLE fingerprint_rules ADD COLUMN exclusive_group TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE fingerprint_products ADD COLUMN product_role TEXT NOT NULL DEFAULT 'application'`,
		`ALTER TABLE fingerprint_products ADD COLUMN exclusive_group TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE fingerprint_imports ADD COLUMN upstream_content_sha256 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE fingerprint_imports ADD COLUMN adapter_version TEXT NOT NULL DEFAULT 'legacy-v1'`,
		`ALTER TABLE fingerprint_imports ADD COLUMN projection_sha256 TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE asset_fingerprint_matches ADD COLUMN product_key TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE asset_fingerprint_matches ADD COLUMN source_product_name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE asset_fingerprint_matches ADD COLUMN product_role TEXT NOT NULL DEFAULT 'application'`,
		`ALTER TABLE asset_fingerprint_matches ADD COLUMN exclusive_group TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE asset_fingerprint_matches ADD COLUMN version TEXT`,
		`ALTER TABLE asset_fingerprint_matches ADD COLUMN cpe TEXT`,
		`ALTER TABLE asset_fingerprint_matches ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE asset_fingerprint_matches ADD COLUMN is_soft INTEGER NOT NULL DEFAULT 0 CHECK (is_soft IN (0, 1))`,
		`ALTER TABLE asset_fingerprint_conclusions ADD COLUMN version TEXT`,
		`ALTER TABLE asset_fingerprint_conclusions ADD COLUMN cpe TEXT`,
		`ALTER TABLE asset_fingerprint_conclusions ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE asset_fingerprint_conclusions ADD COLUMN product_role TEXT NOT NULL DEFAULT 'application'`,
		`ALTER TABLE asset_fingerprint_conclusions ADD COLUMN exclusive_group TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE asset_fingerprint_conclusions ADD COLUMN product_status TEXT NOT NULL DEFAULT 'matched' CHECK (product_status IN ('matched', 'corroborated', 'conflicted'))`,
		`ALTER TABLE asset_fingerprint_conclusions ADD COLUMN product_source_count INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE asset_fingerprint_conclusions ADD COLUMN version_status TEXT NOT NULL DEFAULT 'unobserved' CHECK (version_status IN ('unobserved', 'matched', 'corroborated', 'conflicted'))`,
		`ALTER TABLE asset_fingerprint_conclusions ADD COLUMN version_source_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE asset_fingerprint_conclusions ADD COLUMN cpe_status TEXT NOT NULL DEFAULT 'unobserved' CHECK (cpe_status IN ('unobserved', 'matched', 'corroborated', 'conflicted'))`,
		`ALTER TABLE asset_fingerprint_conclusions ADD COLUMN cpe_source_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE tasks ADD COLUMN report_error TEXT`,
		`ALTER TABLE scan_task_runs ADD COLUMN report_error TEXT`,
		`ALTER TABLE scan_task_runs ADD COLUMN audit_report_path TEXT`,
		`ALTER TABLE scan_task_runs ADD COLUMN snapshot_written_at DATETIME`,
		`ALTER TABLE scan_task_runs ADD COLUMN stage TEXT NOT NULL DEFAULT 'queued'`,
		`ALTER TABLE scan_task_runs ADD COLUMN progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100)`,
		`ALTER TABLE scan_task_runs ADD COLUMN trigger TEXT NOT NULL DEFAULT 'scheduled'`,
		`ALTER TABLE scan_task_run_vulnerabilities ADD COLUMN description TEXT`,
		`ALTER TABLE scan_task_run_protocol_evidence ADD COLUMN outcome TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE scan_task_run_protocol_evidence ADD COLUMN diagnostic TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE scan_task_run_template_candidates ADD COLUMN template_sha256 TEXT`,
		`ALTER TABLE scan_task_run_template_candidates ADD COLUMN template_set_revision TEXT`,
		`ALTER TABLE scan_task_run_template_candidates ADD COLUMN template_mapping_import_id INTEGER`,
		`ALTER TABLE scan_task_run_template_candidate_endpoints ADD COLUMN product_key TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE scan_task_run_template_candidate_endpoints ADD COLUMN executed INTEGER NOT NULL DEFAULT 0 CHECK (executed IN (0, 1))`,
		`ALTER TABLE scan_task_run_validation ADD COLUMN identified_product_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE scan_task_run_validation ADD COLUMN mapped_product_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE scan_task_run_validation ADD COLUMN unmapped_products_json TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE scan_task_run_validation ADD COLUMN executed_template_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE fingerprint_template_mappings ADD COLUMN source_key TEXT`,
		`UPDATE domain_info SET last_seen = COALESCE(last_seen, first_seen, datetime('now'))`,
		`UPDATE domain_info SET is_active = COALESCE(is_active, 1)`,
		`UPDATE domain_ips SET first_seen = COALESCE(first_seen, datetime('now'))`,
		`UPDATE domain_ips SET last_seen = COALESCE(last_seen, datetime('now'))`,
		`UPDATE domain_ips SET is_active = COALESCE(is_active, 1)`,
		`UPDATE fingerprint_imports SET upstream_content_sha256 = content_sha256 WHERE upstream_content_sha256 = ''`,
		`UPDATE fingerprint_imports SET projection_sha256 = content_sha256 WHERE projection_sha256 = ''`,
		`UPDATE scan_task_runs SET audit_report_path = CASE WHEN report_path LIKE '%.md' THEN SUBSTR(report_path, 1, LENGTH(report_path) - 3) || '-audit.md' ELSE report_path || '-audit.md' END WHERE COALESCE(report_path, '') <> '' AND COALESCE(audit_report_path, '') = ''`,
		`UPDATE scan_task_run_protocol_evidence SET outcome = CASE WHEN responded = 1 THEN 'responded' ELSE 'no_response' END WHERE COALESCE(outcome, '') = ''`,
		`INSERT INTO scan_task_run_template_candidate_products (scan_task_run_id, template_id, path, ip, port, protocol, product_key)
		 SELECT scan_task_run_id, template_id, path, ip, port, protocol, product_key
		 FROM scan_task_run_template_candidate_endpoints WHERE COALESCE(product_key, '') <> ''
		 ON CONFLICT DO NOTHING`,
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
		`CREATE INDEX IF NOT EXISTS idx_scan_task_run_protocol_evidence_run ON scan_task_run_protocol_evidence(scan_task_run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_task_run_vulnerabilities_run ON scan_task_run_vulnerabilities(scan_task_run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_task_run_endpoint_validation_run ON scan_task_run_endpoint_validation(scan_task_run_id, ip, port)`,
		`CREATE INDEX IF NOT EXISTS idx_template_candidate_endpoints_run ON scan_task_run_template_candidate_endpoints(scan_task_run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_template_candidate_products_run ON scan_task_run_template_candidate_products(scan_task_run_id, ip, port, protocol)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprint_imports_source_active ON fingerprint_imports(fingerprint_source_id, is_active)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_fingerprint_imports_one_active_per_source ON fingerprint_imports(fingerprint_source_id) WHERE is_active = 1`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprint_source_rules_import ON fingerprint_source_rules(fingerprint_import_id)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_product ON fingerprint_rules(fingerprint_product_id)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprint_match_groups_rule ON fingerprint_match_groups(fingerprint_rule_id)`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprint_matchers_group ON fingerprint_matchers(fingerprint_match_group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_run_fingerprint_imports_import ON scan_task_run_fingerprint_imports(fingerprint_import_id)`,
		`CREATE INDEX IF NOT EXISTS idx_asset_fingerprint_matches_run ON asset_fingerprint_matches(scan_task_run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_asset_fingerprint_match_evidence_match ON asset_fingerprint_match_evidence(asset_fingerprint_match_id)`,
		`CREATE INDEX IF NOT EXISTS idx_asset_fingerprint_conclusions_run ON asset_fingerprint_conclusions(scan_task_run_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_template_mapping_imports_one_active ON template_mapping_imports(is_active) WHERE is_active = 1`,
		`CREATE INDEX IF NOT EXISTS idx_fingerprint_template_mappings_product ON fingerprint_template_mappings(product_key, enabled)`,
	}

	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil && !isIgnorableSQLiteMigrationError(err) {
			return err
		}
	}
	if !hadRunTrigger {
		if err := backfillScanTaskRunLifecycle(db); err != nil {
			return err
		}
	}
	if err := migrateProtocolEvidenceSchema(db); err != nil {
		return err
	}
	if err := migrateRunValidationSchema(db); err != nil {
		return err
	}
	if !hadConclusionEvidenceStatus {
		if err := backfillFingerprintConclusionEvidenceStatus(db); err != nil {
			return err
		}
	}
	if err := migrateFingerprintRuleProjectionRoles(db); err != nil {
		return err
	}
	if err := backfillLegacyHostInventoryScopes(db); err != nil {
		return err
	}
	return nil
}

func backfillScanTaskRunLifecycle(db *sql.DB) error {
	_, err := db.Exec(`
		UPDATE scan_task_runs
		SET trigger = CASE
				WHEN scan_task_id IN (SELECT id FROM scan_tasks WHERE mode = 'once') THEN 'initial'
				ELSE 'scheduled'
			END,
			stage = CASE status
				WHEN 'running' THEN 'profiling'
				WHEN 'success' THEN 'completed'
				WHEN 'failed' THEN 'failed'
				WHEN 'canceled' THEN 'canceled'
				WHEN 'skipped_overlap' THEN 'completed'
				WHEN 'skipped_misfire' THEN 'completed'
				ELSE 'queued'
			END,
			progress = CASE
				WHEN status IN ('success', 'skipped_overlap', 'skipped_misfire') THEN 100
				WHEN status = 'running' THEN 1
				ELSE 0
			END`)
	return err
}

func backfillFingerprintConclusionEvidenceStatus(db *sql.DB) error {
	if _, err := db.Exec(`UPDATE asset_fingerprint_conclusions AS conclusion SET
		product_source_count = MAX(1, (SELECT COUNT(DISTINCT fingerprint_import_id) FROM asset_fingerprint_matches AS match WHERE match.scan_task_run_id = conclusion.scan_task_run_id AND match.ip = conclusion.ip AND match.port = conclusion.port AND match.protocol = conclusion.protocol AND match.product_key = conclusion.product_key AND match.is_soft = 0)),
		version_source_count = (SELECT COUNT(DISTINCT fingerprint_import_id) FROM asset_fingerprint_matches AS match WHERE match.scan_task_run_id = conclusion.scan_task_run_id AND match.ip = conclusion.ip AND match.port = conclusion.port AND match.protocol = conclusion.protocol AND match.product_key = conclusion.product_key AND match.is_soft = 0 AND COALESCE(match.version, '') <> ''),
		cpe_source_count = (SELECT COUNT(DISTINCT fingerprint_import_id) FROM asset_fingerprint_matches AS match WHERE match.scan_task_run_id = conclusion.scan_task_run_id AND match.ip = conclusion.ip AND match.port = conclusion.port AND match.protocol = conclusion.protocol AND match.product_key = conclusion.product_key AND match.is_soft = 0 AND COALESCE(match.cpe, '') <> ''),
		version = CASE WHEN (SELECT COUNT(DISTINCT version) FROM asset_fingerprint_matches AS match WHERE match.scan_task_run_id = conclusion.scan_task_run_id AND match.ip = conclusion.ip AND match.port = conclusion.port AND match.protocol = conclusion.protocol AND match.product_key = conclusion.product_key AND match.is_soft = 0 AND COALESCE(match.version, '') <> '') = 1 THEN (SELECT MIN(version) FROM asset_fingerprint_matches AS match WHERE match.scan_task_run_id = conclusion.scan_task_run_id AND match.ip = conclusion.ip AND match.port = conclusion.port AND match.protocol = conclusion.protocol AND match.product_key = conclusion.product_key AND match.is_soft = 0 AND COALESCE(match.version, '') <> '') ELSE NULL END,
		cpe = CASE WHEN (SELECT COUNT(DISTINCT cpe) FROM asset_fingerprint_matches AS match WHERE match.scan_task_run_id = conclusion.scan_task_run_id AND match.ip = conclusion.ip AND match.port = conclusion.port AND match.protocol = conclusion.protocol AND match.product_key = conclusion.product_key AND match.is_soft = 0 AND COALESCE(match.cpe, '') <> '') = 1 THEN (SELECT MIN(cpe) FROM asset_fingerprint_matches AS match WHERE match.scan_task_run_id = conclusion.scan_task_run_id AND match.ip = conclusion.ip AND match.port = conclusion.port AND match.protocol = conclusion.protocol AND match.product_key = conclusion.product_key AND match.is_soft = 0 AND COALESCE(match.cpe, '') <> '') ELSE NULL END`); err != nil {
		return err
	}
	if _, err := db.Exec(`UPDATE asset_fingerprint_conclusions AS conclusion SET
		product_status = CASE WHEN (SELECT COUNT(DISTINCT product_key) FROM asset_fingerprint_matches AS match WHERE match.scan_task_run_id = conclusion.scan_task_run_id AND match.ip = conclusion.ip AND match.port = conclusion.port AND match.protocol = conclusion.protocol AND match.is_soft = 0) > 1 THEN 'conflicted' WHEN product_source_count > 1 THEN 'corroborated' ELSE 'matched' END,
		version_status = CASE WHEN (SELECT COUNT(DISTINCT version) FROM asset_fingerprint_matches AS match WHERE match.scan_task_run_id = conclusion.scan_task_run_id AND match.ip = conclusion.ip AND match.port = conclusion.port AND match.protocol = conclusion.protocol AND match.product_key = conclusion.product_key AND match.is_soft = 0 AND COALESCE(match.version, '') <> '') > 1 THEN 'conflicted' WHEN version_source_count > 1 THEN 'corroborated' WHEN version_source_count = 1 THEN 'matched' ELSE 'unobserved' END,
		cpe_status = CASE WHEN (SELECT COUNT(DISTINCT cpe) FROM asset_fingerprint_matches AS match WHERE match.scan_task_run_id = conclusion.scan_task_run_id AND match.ip = conclusion.ip AND match.port = conclusion.port AND match.protocol = conclusion.protocol AND match.product_key = conclusion.product_key AND match.is_soft = 0 AND COALESCE(match.cpe, '') <> '') > 1 THEN 'conflicted' WHEN cpe_source_count > 1 THEN 'corroborated' WHEN cpe_source_count = 1 THEN 'matched' ELSE 'unobserved' END`); err != nil {
		return err
	}
	_, err := db.Exec(`UPDATE asset_fingerprint_conclusions SET conclusion_status = product_status`)
	return err
}

func migrateFingerprintRuleProjectionRoles(db *sql.DB) error {
	var applied int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, t320FrozenProductRolesMigration).Scan(&applied); err != nil {
		return err
	}
	if applied > 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT rule.id, product.id, product.canonical_name, rule.tags_json,
		COALESCE(rule.product_role, 'application'), COALESCE(rule.exclusive_group, '')
		FROM fingerprint_rules AS rule
		JOIN fingerprint_products AS product ON product.id = rule.fingerprint_product_id`)
	if err != nil {
		return err
	}
	type roleUpdate struct {
		ruleID, productID int64
		role, group       string
	}
	updates := make([]roleUpdate, 0)
	for rows.Next() {
		var update roleUpdate
		var name, tagsJSON, currentRole, currentGroup string
		if err := rows.Scan(&update.ruleID, &update.productID, &name, &tagsJSON, &currentRole, &currentGroup); err != nil {
			rows.Close()
			return err
		}
		var tags []string
		_ = json.Unmarshal([]byte(tagsJSON), &tags)
		classifiedRole, classifiedGroup := model.FingerprintProductClassification(name, tags)
		update.role, update.group = strings.TrimSpace(currentRole), strings.TrimSpace(currentGroup)
		if update.role == "" || (update.role == "application" && update.group == "") {
			update.role, update.group = classifiedRole, classifiedGroup
		}
		updates = append(updates, update)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, update := range updates {
		if _, err := tx.Exec(`UPDATE fingerprint_rules SET product_role = ?, exclusive_group = ? WHERE id = ?`, update.role, update.group, update.ruleID); err != nil {
			return err
		}
		if update.role != "application" || update.group != "" {
			if _, err := tx.Exec(`UPDATE fingerprint_products SET product_role = ?, exclusive_group = ?
				WHERE id = ? AND product_role = 'application' AND exclusive_group = ''`, update.role, update.group, update.productID); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`UPDATE asset_fingerprint_matches AS match SET
		product_role = COALESCE((SELECT rule.product_role FROM fingerprint_rules AS rule WHERE rule.fingerprint_source_rule_id = match.fingerprint_source_rule_id), match.product_role),
		exclusive_group = COALESCE((SELECT rule.exclusive_group FROM fingerprint_rules AS rule WHERE rule.fingerprint_source_rule_id = match.fingerprint_source_rule_id), match.exclusive_group)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE asset_fingerprint_conclusions AS conclusion SET
		product_role = COALESCE((SELECT MIN(match.product_role) FROM asset_fingerprint_matches AS match WHERE match.scan_task_run_id = conclusion.scan_task_run_id AND match.ip = conclusion.ip AND match.port = conclusion.port AND match.protocol = conclusion.protocol AND match.product_key = conclusion.product_key AND match.is_soft = 0), conclusion.product_role),
		exclusive_group = COALESCE((SELECT MIN(match.exclusive_group) FROM asset_fingerprint_matches AS match WHERE match.scan_task_run_id = conclusion.scan_task_run_id AND match.ip = conclusion.ip AND match.port = conclusion.port AND match.protocol = conclusion.protocol AND match.product_key = conclusion.product_key AND match.is_soft = 0), conclusion.exclusive_group)`); err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE asset_fingerprint_conclusions AS conclusion SET
		product_status = CASE
			WHEN conclusion.exclusive_group <> '' AND EXISTS (
				SELECT 1 FROM asset_fingerprint_matches AS other
				WHERE other.scan_task_run_id = conclusion.scan_task_run_id AND other.ip = conclusion.ip
					AND other.port = conclusion.port AND other.protocol = conclusion.protocol AND other.is_soft = 0
					AND other.exclusive_group = conclusion.exclusive_group AND other.product_key <> conclusion.product_key
			) THEN 'conflicted'
			WHEN conclusion.product_source_count > 1 THEN 'corroborated'
			ELSE 'matched' END`)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`UPDATE asset_fingerprint_conclusions SET conclusion_status = product_status`); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO schema_migrations (name) VALUES (?)`, t320FrozenProductRolesMigration); err != nil {
		return err
	}
	return tx.Commit()
}

func sqliteTableHasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue interface{}
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func migrateProtocolEvidenceSchema(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(scan_task_run_protocol_evidence)`)
	if err != nil {
		return err
	}
	columns := make(map[string]bool)
	primaryKey := make(map[int]string)
	for rows.Next() {
		var cid, notNull, primaryKeyPosition int
		var name, columnType string
		var defaultValue interface{}
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKeyPosition); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
		if primaryKeyPosition > 0 {
			primaryKey[primaryKeyPosition] = name
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	wantedPrimaryKey := []string{"scan_task_run_id", "ip", "port", "evidence_type", "protocol", "probe_name"}
	current := columns["evidence_type"] && columns["probe_name"] && columns["outcome"] && columns["diagnostic"] && len(primaryKey) == len(wantedPrimaryKey)
	for index, name := range wantedPrimaryKey {
		current = current && primaryKey[index+1] == name
	}
	if current {
		return nil
	}

	evidenceTypeExpression := `CASE WHEN protocol IN ('http', 'https') THEN 'web' ELSE 'passive_banner' END`
	if columns["evidence_type"] {
		evidenceTypeExpression = `COALESCE(NULLIF(evidence_type, ''), ` + evidenceTypeExpression + `)`
	}
	probeNameExpression := `''`
	if columns["probe_name"] {
		probeNameExpression = `COALESCE(probe_name, '')`
	}
	outcomeExpression := `CASE WHEN responded = 1 THEN 'responded' ELSE 'no_response' END`
	if columns["outcome"] {
		outcomeExpression = `COALESCE(NULLIF(outcome, ''), ` + outcomeExpression + `)`
	}
	diagnosticExpression := `''`
	if columns["diagnostic"] {
		diagnosticExpression = `COALESCE(diagnostic, '')`
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DROP INDEX IF EXISTS idx_scan_task_run_protocol_evidence_run`); err != nil {
		return err
	}
	if _, err := tx.Exec(`ALTER TABLE scan_task_run_protocol_evidence RENAME TO scan_task_run_protocol_evidence_t319_legacy`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE scan_task_run_protocol_evidence (
		scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id) ON DELETE CASCADE,
		ip TEXT NOT NULL, port INTEGER NOT NULL, evidence_type TEXT NOT NULL,
		probe_name TEXT NOT NULL DEFAULT '', protocol TEXT NOT NULL,
		responded INTEGER NOT NULL DEFAULT 0 CHECK (responded IN (0, 1)), status_code INTEGER,
		outcome TEXT NOT NULL DEFAULT '', diagnostic TEXT NOT NULL DEFAULT '',
		server TEXT, title TEXT,
		banner_captured_length INTEGER NOT NULL DEFAULT 0, banner_sha256 TEXT,
		banner_truncated INTEGER NOT NULL DEFAULT 0 CHECK (banner_truncated IN (0, 1)),
		header_captured_length INTEGER NOT NULL DEFAULT 0, header_sha256 TEXT,
		header_truncated INTEGER NOT NULL DEFAULT 0 CHECK (header_truncated IN (0, 1)),
		body_captured_length INTEGER NOT NULL DEFAULT 0, body_sha256 TEXT,
		body_truncated INTEGER NOT NULL DEFAULT 0 CHECK (body_truncated IN (0, 1)),
		PRIMARY KEY (scan_task_run_id, ip, port, evidence_type, protocol, probe_name)
	)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO scan_task_run_protocol_evidence
			(scan_task_run_id, ip, port, evidence_type, probe_name, protocol, responded, outcome, diagnostic, status_code, server, title,
		 banner_captured_length, banner_sha256, banner_truncated, header_captured_length, header_sha256,
		 header_truncated, body_captured_length, body_sha256, body_truncated)
		SELECT scan_task_run_id, ip, port, ` + evidenceTypeExpression + `, ` + probeNameExpression + `, protocol, responded, ` + outcomeExpression + `, ` + diagnosticExpression + `, status_code, server, title,
		       banner_captured_length, banner_sha256, banner_truncated, header_captured_length, header_sha256,
		       header_truncated, body_captured_length, body_sha256, body_truncated
		FROM scan_task_run_protocol_evidence_t319_legacy`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE scan_task_run_protocol_evidence_t319_legacy`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE INDEX idx_scan_task_run_protocol_evidence_run ON scan_task_run_protocol_evidence(scan_task_run_id)`); err != nil {
		return err
	}
	return tx.Commit()
}

func migrateRunValidationSchema(db *sql.DB) error {
	var definition string
	err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'scan_task_run_validation'`).Scan(&definition)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil || strings.Contains(definition, "'not_started'") {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE scan_task_run_validation RENAME TO scan_task_run_validation_t321_legacy`); err != nil {
		return err
	}
	if _, err := tx.Exec(`CREATE TABLE scan_task_run_validation (
		scan_task_run_id INTEGER PRIMARY KEY REFERENCES scan_task_runs(id) ON DELETE CASCADE,
		status TEXT NOT NULL CHECK (status IN ('disabled', 'not_started', 'no_candidates', 'success', 'failed')),
		identified_product_count INTEGER NOT NULL DEFAULT 0,
		mapped_product_count INTEGER NOT NULL DEFAULT 0,
		unmapped_products_json TEXT NOT NULL DEFAULT '[]',
		candidate_endpoint_count INTEGER NOT NULL DEFAULT 0,
		executed_endpoint_count INTEGER NOT NULL DEFAULT 0,
		template_count INTEGER NOT NULL DEFAULT 0,
		executed_template_count INTEGER NOT NULL DEFAULT 0,
		finding_count INTEGER NOT NULL DEFAULT 0,
		started_at TEXT, finished_at TEXT, error_message TEXT
	)`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO scan_task_run_validation
		(scan_task_run_id, status, identified_product_count, mapped_product_count, unmapped_products_json,
		 candidate_endpoint_count, executed_endpoint_count, template_count, executed_template_count, finding_count, started_at, finished_at, error_message)
		SELECT scan_task_run_id, status, identified_product_count, mapped_product_count, unmapped_products_json,
		       candidate_endpoint_count, executed_endpoint_count, template_count, executed_template_count, finding_count, started_at, finished_at, error_message
		FROM scan_task_run_validation_t321_legacy`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DROP TABLE scan_task_run_validation_t321_legacy`); err != nil {
		return err
	}
	return tx.Commit()
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

-- v1 compatibility history. V2 current inventory deliberately uses the
-- separate table below so stale legacy rows cannot affect asset views.
CREATE TABLE IF NOT EXISTS current_port_inventory (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT    NOT NULL,
    port         INTEGER NOT NULL,
    service_type TEXT    NOT NULL,
    last_seen    DATETIME NOT NULL DEFAULT (datetime('now')),
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
    trigger       TEXT NOT NULL DEFAULT 'scheduled',
    stage         TEXT NOT NULL DEFAULT 'queued',
    progress      INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    target        TEXT NOT NULL,
    scan_type     TEXT NOT NULL CHECK (scan_type IN ('ip', 'subnet')),
    config_json   TEXT NOT NULL DEFAULT '{}',
	config_hash   TEXT NOT NULL DEFAULT '',
	error_message TEXT,
    report_path   TEXT,
    audit_report_path TEXT,
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

CREATE TABLE IF NOT EXISTS scan_task_run_protocol_evidence (
    scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id) ON DELETE CASCADE,
    ip TEXT NOT NULL, port INTEGER NOT NULL, evidence_type TEXT NOT NULL,
	probe_name TEXT NOT NULL DEFAULT '', protocol TEXT NOT NULL,
	responded INTEGER NOT NULL DEFAULT 0 CHECK (responded IN (0, 1)), status_code INTEGER,
	outcome TEXT NOT NULL DEFAULT '', diagnostic TEXT NOT NULL DEFAULT '',
    server TEXT, title TEXT,
    banner_captured_length INTEGER NOT NULL DEFAULT 0, banner_sha256 TEXT,
    banner_truncated INTEGER NOT NULL DEFAULT 0 CHECK (banner_truncated IN (0, 1)),
    header_captured_length INTEGER NOT NULL DEFAULT 0, header_sha256 TEXT,
    header_truncated INTEGER NOT NULL DEFAULT 0 CHECK (header_truncated IN (0, 1)),
    body_captured_length INTEGER NOT NULL DEFAULT 0, body_sha256 TEXT,
    body_truncated INTEGER NOT NULL DEFAULT 0 CHECK (body_truncated IN (0, 1)),
    PRIMARY KEY (scan_task_run_id, ip, port, evidence_type, protocol, probe_name)
);

CREATE TABLE IF NOT EXISTS scan_task_run_validation (
    scan_task_run_id INTEGER PRIMARY KEY REFERENCES scan_task_runs(id) ON DELETE CASCADE,
	status TEXT NOT NULL CHECK (status IN ('disabled', 'not_started', 'no_candidates', 'success', 'failed')),
	identified_product_count INTEGER NOT NULL DEFAULT 0,
	mapped_product_count INTEGER NOT NULL DEFAULT 0,
	unmapped_products_json TEXT NOT NULL DEFAULT '[]',
    candidate_endpoint_count INTEGER NOT NULL DEFAULT 0,
    executed_endpoint_count INTEGER NOT NULL DEFAULT 0,
    template_count INTEGER NOT NULL DEFAULT 0,
	executed_template_count INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    finished_at TEXT,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS scan_task_run_endpoint_validation (
    scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    status TEXT NOT NULL CHECK (status IN ('disabled', 'not_started', 'no_candidates', 'success', 'failed')),
    reason TEXT NOT NULL DEFAULT '',
    identified_product_count INTEGER NOT NULL DEFAULT 0,
    mapped_product_count INTEGER NOT NULL DEFAULT 0,
    unmapped_products_json TEXT NOT NULL DEFAULT '[]',
    candidate_template_count INTEGER NOT NULL DEFAULT 0,
    executed_template_count INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    finished_at TEXT,
    error_message TEXT,
    PRIMARY KEY (scan_task_run_id, ip, port, protocol)
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
    description      TEXT,
    evidence         TEXT,
    PRIMARY KEY (scan_task_run_id, finding_key)
);

CREATE TABLE IF NOT EXISTS scan_task_run_template_candidates (
    scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id),
    template_id TEXT NOT NULL, path TEXT NOT NULL, source TEXT NOT NULL, reason TEXT NOT NULL,
    template_sha256 TEXT, template_set_revision TEXT, template_mapping_import_id INTEGER,
    PRIMARY KEY (scan_task_run_id, template_id, path)
);

CREATE TABLE IF NOT EXISTS scan_task_run_template_candidate_endpoints (
    scan_task_run_id INTEGER NOT NULL,
    template_id TEXT NOT NULL,
    path TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
	product_key TEXT NOT NULL DEFAULT '',
	executed INTEGER NOT NULL DEFAULT 0 CHECK (executed IN (0, 1)),
    PRIMARY KEY (scan_task_run_id, template_id, path, ip, port, protocol),
    FOREIGN KEY (scan_task_run_id, template_id, path)
        REFERENCES scan_task_run_template_candidates(scan_task_run_id, template_id, path) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_task_run_template_candidate_products (
    scan_task_run_id INTEGER NOT NULL,
    template_id TEXT NOT NULL,
    path TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    product_key TEXT NOT NULL,
    PRIMARY KEY (scan_task_run_id, template_id, path, ip, port, protocol, product_key),
    FOREIGN KEY (scan_task_run_id, template_id, path, ip, port, protocol)
        REFERENCES scan_task_run_template_candidate_endpoints(scan_task_run_id, template_id, path, ip, port, protocol) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS fingerprint_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_key TEXT NOT NULL UNIQUE,
    repository_url TEXT NOT NULL,
    license TEXT,
    status TEXT NOT NULL DEFAULT 'enabled',
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS fingerprint_source_bootstrap_diagnostics (
    source_key TEXT PRIMARY KEY,
    last_error TEXT NOT NULL DEFAULT '',
    last_failed_at DATETIME,
    resolved_at DATETIME,
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS fingerprint_imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_source_id INTEGER NOT NULL REFERENCES fingerprint_sources(id) ON DELETE CASCADE,
    commit_hash TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    upstream_content_sha256 TEXT NOT NULL DEFAULT '',
    adapter_version TEXT NOT NULL DEFAULT 'legacy-v1',
    projection_sha256 TEXT NOT NULL DEFAULT '',
    manifest_json TEXT NOT NULL,
    rule_total INTEGER NOT NULL DEFAULT 0,
    executable_total INTEGER NOT NULL DEFAULT 0,
    unsupported_total INTEGER NOT NULL DEFAULT 0,
    import_error_total INTEGER NOT NULL DEFAULT 0,
    error_summary TEXT,
    is_active INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)),
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(fingerprint_source_id, commit_hash, content_sha256)
);

CREATE TABLE IF NOT EXISTS fingerprint_source_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_import_id INTEGER NOT NULL REFERENCES fingerprint_imports(id) ON DELETE CASCADE,
    source_rule_id TEXT,
    source_path TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    raw_content TEXT NOT NULL,
    raw_structure TEXT,
    import_status TEXT NOT NULL CHECK (import_status IN ('executable', 'unsupported', 'import_error')),
    import_error TEXT,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(fingerprint_import_id, source_path, content_sha256)
);

CREATE TABLE IF NOT EXISTS fingerprint_products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    canonical_name TEXT NOT NULL UNIQUE,
    vendor TEXT,
    aliases_json TEXT,
    cpe TEXT,
    product_role TEXT NOT NULL DEFAULT 'application',
    exclusive_group TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS fingerprint_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_source_rule_id INTEGER NOT NULL UNIQUE REFERENCES fingerprint_source_rules(id) ON DELETE CASCADE,
    fingerprint_product_id INTEGER NOT NULL REFERENCES fingerprint_products(id),
    source_product_name TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL,
    soft_match INTEGER NOT NULL DEFAULT 0 CHECK (soft_match IN (0, 1)),
    version_template TEXT,
    cpe TEXT,
    tags_json TEXT NOT NULL DEFAULT '[]',
    product_role TEXT NOT NULL DEFAULT 'application',
    exclusive_group TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('executable', 'unsupported', 'disabled'))
);

CREATE TABLE IF NOT EXISTS fingerprint_match_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_rule_id INTEGER NOT NULL REFERENCES fingerprint_rules(id) ON DELETE CASCADE,
    parent_id INTEGER REFERENCES fingerprint_match_groups(id) ON DELETE CASCADE,
    operator TEXT NOT NULL CHECK (operator IN ('all', 'any')),
    position INTEGER NOT NULL,
    UNIQUE(fingerprint_rule_id, parent_id, position)
);

CREATE TABLE IF NOT EXISTS fingerprint_matchers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint_match_group_id INTEGER NOT NULL REFERENCES fingerprint_match_groups(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL,
    target TEXT,
    operator TEXT NOT NULL,
    value TEXT NOT NULL,
    version_capture TEXT,
    position INTEGER NOT NULL,
    UNIQUE(fingerprint_match_group_id, position)
);

CREATE TABLE IF NOT EXISTS scan_task_run_fingerprint_imports (
    scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id) ON DELETE CASCADE,
    fingerprint_import_id INTEGER NOT NULL REFERENCES fingerprint_imports(id),
    PRIMARY KEY (scan_task_run_id, fingerprint_import_id)
);

CREATE TABLE IF NOT EXISTS asset_fingerprint_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id) ON DELETE CASCADE,
    fingerprint_import_id INTEGER NOT NULL REFERENCES fingerprint_imports(id),
    fingerprint_source_rule_id INTEGER NOT NULL REFERENCES fingerprint_source_rules(id),
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    product_key TEXT NOT NULL DEFAULT '',
    source_product_name TEXT NOT NULL DEFAULT '',
    product_role TEXT NOT NULL DEFAULT 'application',
    exclusive_group TEXT NOT NULL DEFAULT '',
    version TEXT,
    cpe TEXT,
    tags_json TEXT NOT NULL DEFAULT '[]',
    is_soft INTEGER NOT NULL DEFAULT 0 CHECK (is_soft IN (0, 1)),
    evidence_summary TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(scan_task_run_id, ip, port, fingerprint_source_rule_id, evidence_summary)
);

CREATE TABLE IF NOT EXISTS asset_fingerprint_match_evidence (
    asset_fingerprint_match_id INTEGER NOT NULL REFERENCES asset_fingerprint_matches(id) ON DELETE CASCADE,
    fingerprint_matcher_id INTEGER NOT NULL REFERENCES fingerprint_matchers(id),
    evidence_type TEXT NOT NULL,
    target TEXT,
    operator TEXT NOT NULL,
    observed_sha256 TEXT NOT NULL,
    observed_length INTEGER NOT NULL,
    truncated INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0, 1)),
    summary TEXT NOT NULL,
    PRIMARY KEY (asset_fingerprint_match_id, fingerprint_matcher_id)
);

CREATE TABLE IF NOT EXISTS asset_fingerprint_conclusions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_task_run_id INTEGER NOT NULL REFERENCES scan_task_runs(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    product_key TEXT NOT NULL,
    product_role TEXT NOT NULL DEFAULT 'application',
    exclusive_group TEXT NOT NULL DEFAULT '',
    version TEXT,
    cpe TEXT,
    tags_json TEXT NOT NULL DEFAULT '[]',
    conclusion_status TEXT NOT NULL CHECK (conclusion_status IN ('matched', 'corroborated', 'conflicted')),
    product_status TEXT NOT NULL DEFAULT 'matched' CHECK (product_status IN ('matched', 'corroborated', 'conflicted')),
    product_source_count INTEGER NOT NULL DEFAULT 1,
    version_status TEXT NOT NULL DEFAULT 'unobserved' CHECK (version_status IN ('unobserved', 'matched', 'corroborated', 'conflicted')),
    version_source_count INTEGER NOT NULL DEFAULT 0,
    cpe_status TEXT NOT NULL DEFAULT 'unobserved' CHECK (cpe_status IN ('unobserved', 'matched', 'corroborated', 'conflicted')),
    cpe_source_count INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(scan_task_run_id, ip, port, protocol, product_key)
);

CREATE TABLE IF NOT EXISTS template_mapping_imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    revision TEXT NOT NULL,
    content_sha256 TEXT NOT NULL UNIQUE,
    manifest_json TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)),
    created_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS fingerprint_template_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_mapping_import_id INTEGER NOT NULL REFERENCES template_mapping_imports(id) ON DELETE CASCADE,
    product_key TEXT NOT NULL,
    source_key TEXT,
    source_rule_id TEXT,
    template_id TEXT NOT NULL,
    template_path TEXT NOT NULL,
    template_sha256 TEXT NOT NULL,
    template_set_revision TEXT NOT NULL,
    side_effect TEXT NOT NULL,
    review_status TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    disabled_at DATETIME,
    UNIQUE(template_mapping_import_id, product_key, source_rule_id, template_id, template_path)
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
CREATE INDEX IF NOT EXISTS idx_scan_task_run_protocol_evidence_run ON scan_task_run_protocol_evidence(scan_task_run_id);
CREATE INDEX IF NOT EXISTS idx_scan_task_run_vulnerabilities_run ON scan_task_run_vulnerabilities(scan_task_run_id);
CREATE INDEX IF NOT EXISTS idx_scan_task_run_endpoint_validation_run ON scan_task_run_endpoint_validation(scan_task_run_id, ip, port);
CREATE INDEX IF NOT EXISTS idx_template_candidate_endpoints_run ON scan_task_run_template_candidate_endpoints(scan_task_run_id);
CREATE INDEX IF NOT EXISTS idx_template_candidate_products_run ON scan_task_run_template_candidate_products(scan_task_run_id, ip, port, protocol);
CREATE INDEX IF NOT EXISTS idx_fingerprint_imports_source_active ON fingerprint_imports(fingerprint_source_id, is_active);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fingerprint_imports_one_active_per_source ON fingerprint_imports(fingerprint_source_id) WHERE is_active = 1;
CREATE INDEX IF NOT EXISTS idx_fingerprint_source_rules_import ON fingerprint_source_rules(fingerprint_import_id);
CREATE INDEX IF NOT EXISTS idx_fingerprint_rules_product ON fingerprint_rules(fingerprint_product_id);
CREATE INDEX IF NOT EXISTS idx_fingerprint_match_groups_rule ON fingerprint_match_groups(fingerprint_rule_id);
CREATE INDEX IF NOT EXISTS idx_fingerprint_matchers_group ON fingerprint_matchers(fingerprint_match_group_id);
CREATE INDEX IF NOT EXISTS idx_run_fingerprint_imports_import ON scan_task_run_fingerprint_imports(fingerprint_import_id);
CREATE INDEX IF NOT EXISTS idx_asset_fingerprint_matches_run ON asset_fingerprint_matches(scan_task_run_id);
CREATE INDEX IF NOT EXISTS idx_asset_fingerprint_match_evidence_match ON asset_fingerprint_match_evidence(asset_fingerprint_match_id);
CREATE INDEX IF NOT EXISTS idx_asset_fingerprint_conclusions_run ON asset_fingerprint_conclusions(scan_task_run_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_template_mapping_imports_one_active ON template_mapping_imports(is_active) WHERE is_active = 1;
CREATE INDEX IF NOT EXISTS idx_fingerprint_template_mappings_product ON fingerprint_template_mappings(product_key, enabled);
`
	_, err := db.Exec(schema)
	if err != nil {
		return err
	}

	if err := ensureSQLiteMigrations(db); err != nil {
		return err
	}

	if err := seedBuiltinFingerprints(db); err != nil {
		return err
	}
	return MigrateLegacyBannerFingerprintRules(db)
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

func upsertCurrentPort(execer sqlExecer, record scanResultRecord) error {
	_, err := execer.Exec(`
		INSERT INTO current_port_inventory (ip, port, service_type, last_seen)
		VALUES (?, ?, ?, datetime('now'))
		ON CONFLICT(ip, port) DO UPDATE SET
			service_type = excluded.service_type,
			last_seen = datetime('now')`,
		record.ip,
		record.port,
		record.serviceType,
	)
	return err
}

// PortScanCoverage describes exactly which ports a scan attempted. Full and
// Ports are mutually exclusive; an empty selected set observes nothing.
type PortScanCoverage struct {
	Full  bool
	Ports []int
}

func FullPortScanCoverage() PortScanCoverage {
	return PortScanCoverage{Full: true}
}

func SelectedPortScanCoverage(ports []int) PortScanCoverage {
	return PortScanCoverage{Ports: append([]int(nil), ports...)}
}

// SyncOpenPorts updates only the V2 ports covered by this scan. The optional
// argument defaults to full coverage for compatibility with older callers.
// Production workflows always pass their coverage explicitly.
func SyncOpenPorts(db *sql.DB, ip string, results []model.ScanResult, values ...PortScanCoverage) error {
	if err := ensureCurrentPortInventory(db); err != nil {
		return err
	}
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid host IP: %s", ip)
	}
	coverage, coveredPorts, err := normalizePortScanCoverage(values)
	if err != nil {
		return err
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
		if !coverage.Full {
			if _, covered := coveredPorts[record.port]; !covered {
				return fmt.Errorf("scan result port %d is outside the declared coverage", record.port)
			}
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
		if err = upsertCurrentPort(tx, recordsByPort[port]); err != nil {
			return err
		}
	}

	statement, args := coveredMissingPortsStatement(`DELETE FROM current_port_inventory WHERE ip = ?`, []interface{}{ip}, coverage, ports)
	if _, err = tx.Exec(statement, args...); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

func normalizePortScanCoverage(values []PortScanCoverage) (PortScanCoverage, map[int]struct{}, error) {
	if len(values) > 1 {
		return PortScanCoverage{}, nil, errors.New("only one port scan coverage value is allowed")
	}
	coverage := FullPortScanCoverage()
	if len(values) == 1 {
		coverage = values[0]
	}
	if coverage.Full && len(coverage.Ports) > 0 {
		return PortScanCoverage{}, nil, errors.New("full port coverage cannot include selected ports")
	}
	covered := make(map[int]struct{}, len(coverage.Ports))
	if coverage.Full {
		return coverage, covered, nil
	}
	ports := make([]int, 0, len(coverage.Ports))
	for _, port := range coverage.Ports {
		if port < 1 || port > 65535 {
			return PortScanCoverage{}, nil, fmt.Errorf("invalid covered port: %d", port)
		}
		if _, exists := covered[port]; exists {
			continue
		}
		covered[port] = struct{}{}
		ports = append(ports, port)
	}
	sort.Ints(ports)
	coverage.Ports = ports
	return coverage, covered, nil
}

func coveredMissingPortsStatement(statement string, args []interface{}, coverage PortScanCoverage, openPorts []int) (string, []interface{}) {
	if !coverage.Full {
		if len(coverage.Ports) == 0 {
			return statement + ` AND 1 = 0`, args
		}
		statement += ` AND port IN (` + sqlPlaceholders(len(coverage.Ports)) + `)`
		for _, port := range coverage.Ports {
			args = append(args, port)
		}
	}
	if len(openPorts) > 0 {
		statement += ` AND port NOT IN (` + sqlPlaceholders(len(openPorts)) + `)`
		for _, port := range openPorts {
			args = append(args, port)
		}
	}
	return statement, args
}

func ensureCurrentPortInventory(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS current_port_inventory (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			ip           TEXT    NOT NULL,
			port         INTEGER NOT NULL,
			service_type TEXT    NOT NULL,
			last_seen    DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(ip, port)
		)`)
	return err
}

// SyncScopeOpenPorts updates one host's port membership inside one scan scope.
// It intentionally does not alter another scope's port rows or the global
// scope-port inventory used for latest service profiling.
func SyncScopeOpenPorts(db *sql.DB, scope, ip string, results []model.ScanResult, values ...PortScanCoverage) error {
	scope = strings.TrimSpace(scope)
	ip = strings.TrimSpace(ip)
	if scope == "" {
		return errors.New("scan scope is required")
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid host IP: %s", ip)
	}
	coverage, coveredPorts, err := normalizePortScanCoverage(values)
	if err != nil {
		return err
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
		if !coverage.Full {
			if _, covered := coveredPorts[record.port]; !covered {
				return fmt.Errorf("scan result port %d is outside the declared coverage", record.port)
			}
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
	statement, args := coveredMissingPortsStatement(statement, []interface{}{scope, ip}, coverage, ports)
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

	rows, err := db.Query(latestAssetPortRunsCTE+`
		SELECT inventory.port, inventory.service_type, inventory.last_seen,
			COALESCE(latest.scan_task_run_id, 0), COALESCE(latest.observed_at, '')
		FROM current_port_inventory AS inventory
		LEFT JOIN latest_port_runs AS latest ON latest.port = inventory.port
		WHERE inventory.ip = ?
		ORDER BY inventory.port ASC`, ip, ip)
	if isMissingCurrentPortInventory(err) {
		detail.Ports = make([]model.AssetPort, 0)
		return detail, nil
	}
	if err != nil {
		return model.AssetDetail{}, err
	}
	detail.Ports = make([]model.AssetPort, 0)
	for rows.Next() {
		var port model.AssetPort
		if err := rows.Scan(&port.Port, &port.Service, &port.LastSeenAt, &port.ObservationRunID, &port.ObservedAt); err != nil {
			return model.AssetDetail{}, err
		}
		port.Transport = "tcp"
		port.State = "open"
		port.ProtocolEvidence = make([]model.ScanTaskRunProtocolEvidence, 0)
		port.Technologies = make([]model.AssetTechnology, 0)
		port.UnresolvedReasons = make([]string, 0)
		port.Validation.UnmappedProducts = make([]string, 0)
		port.Validation.Findings = make([]model.ScanTaskRunVulnerability, 0)
		detail.Ports = append(detail.Ports, port)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return model.AssetDetail{}, err
	}
	if err := rows.Close(); err != nil {
		return model.AssetDetail{}, err
	}
	if err := loadAssetPortEvidenceSet(db, ip, detail.Ports); err != nil {
		return model.AssetDetail{}, err
	}
	if err := loadAssetPortTechnologySet(db, ip, detail.Ports); err != nil {
		return model.AssetDetail{}, err
	}
	if err := loadAssetPortValidationSet(db, ip, detail.Ports); err != nil {
		return model.AssetDetail{}, err
	}
	finalizeAssetPortProfiles(detail.Ports)
	return detail, nil
}

const latestAssetPortRunsCTE = `
	WITH ranked_port_runs AS (
		SELECT run_port.port, run_port.scan_task_run_id,
			COALESCE(run.snapshot_written_at, run.finished_at, run.updated_at, run.created_at) AS observed_at,
			ROW_NUMBER() OVER (PARTITION BY run_port.port ORDER BY run_port.scan_task_run_id DESC) AS position
		FROM scan_task_run_ports AS run_port
		JOIN scan_task_runs AS run ON run.id = run_port.scan_task_run_id
		WHERE run_port.ip = ? AND run.snapshot_written_at IS NOT NULL
	), latest_port_runs AS (
		SELECT port, scan_task_run_id, observed_at FROM ranked_port_runs WHERE position = 1
	)`

func loadAssetPortEvidenceSet(db *sql.DB, ip string, ports []model.AssetPort) error {
	if len(ports) == 0 {
		return nil
	}
	portIndexes := make(map[int]int, len(ports))
	for index := range ports {
		portIndexes[ports[index].Port] = index
		ports[index].ProtocolEvidence = make([]model.ScanTaskRunProtocolEvidence, 0)
	}
	rows, err := db.Query(latestAssetPortRunsCTE+`
		SELECT evidence.port, evidence.evidence_type, evidence.probe_name, evidence.protocol, evidence.responded,
			COALESCE(evidence.outcome, ''), COALESCE(evidence.diagnostic, ''),
			COALESCE(evidence.status_code, 0), COALESCE(evidence.server, ''), COALESCE(evidence.title, ''),
			evidence.banner_captured_length, COALESCE(evidence.banner_sha256, ''), evidence.banner_truncated,
			evidence.header_captured_length, COALESCE(evidence.header_sha256, ''), evidence.header_truncated,
			evidence.body_captured_length, COALESCE(evidence.body_sha256, ''), evidence.body_truncated
		FROM scan_task_run_protocol_evidence AS evidence
		JOIN latest_port_runs AS latest ON latest.port = evidence.port AND latest.scan_task_run_id = evidence.scan_task_run_id
		WHERE evidence.ip = ?
		ORDER BY evidence.port, evidence.evidence_type, evidence.protocol, evidence.probe_name`, ip, ip)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "no such table: scan_task_run_protocol_evidence") || strings.Contains(message, "no such column: evidence.evidence_type") {
			return nil
		}
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var evidence model.ScanTaskRunProtocolEvidence
		var responded, bannerTruncated, headerTruncated, bodyTruncated int
		if err := rows.Scan(&evidence.Port, &evidence.EvidenceType, &evidence.ProbeName, &evidence.Protocol, &responded, &evidence.Outcome, &evidence.Diagnostic,
			&evidence.StatusCode, &evidence.Server, &evidence.Title,
			&evidence.BannerCapturedLength, &evidence.BannerSHA256, &bannerTruncated,
			&evidence.HeaderCapturedLength, &evidence.HeaderSHA256, &headerTruncated,
			&evidence.BodyCapturedLength, &evidence.BodySHA256, &bodyTruncated); err != nil {
			return err
		}
		index, ok := portIndexes[evidence.Port]
		if !ok {
			continue
		}
		evidence.IP = ip
		evidence.Responded = responded != 0
		evidence.BannerTruncated = bannerTruncated != 0
		evidence.HeaderTruncated = headerTruncated != 0
		evidence.BodyTruncated = bodyTruncated != 0
		ports[index].ProtocolEvidence = append(ports[index].ProtocolEvidence, evidence)
		applyAssetPortEvidenceCompatibility(&ports[index])
	}
	return rows.Err()
}

type assetTechnologyAccumulator struct {
	technology         model.AssetTechnology
	protocols          map[string]struct{}
	versions           map[string]struct{}
	cpes               map[string]struct{}
	tags               map[string]struct{}
	sourceProducts     map[string]struct{}
	sources            map[string]model.AssetTechnologySource
	evidence           map[string]struct{}
	productStatus      string
	versionStatus      string
	cpeStatus          string
	productSourceCount int
	versionSourceCount int
	cpeSourceCount     int
}

func loadAssetPortTechnologySet(db *sql.DB, ip string, ports []model.AssetPort) error {
	if len(ports) == 0 {
		return nil
	}
	portIndexes := make(map[int]int, len(ports))
	for index := range ports {
		portIndexes[ports[index].Port] = index
	}
	rows, err := db.Query(latestAssetPortRunsCTE+`
		SELECT conclusion.port, conclusion.protocol, conclusion.product_key,
			COALESCE(conclusion.product_role, ''), COALESCE(conclusion.exclusive_group, ''),
			COALESCE(conclusion.version, ''), COALESCE(conclusion.cpe, ''), conclusion.tags_json,
			conclusion.product_status, conclusion.product_source_count,
			conclusion.version_status, conclusion.version_source_count,
			conclusion.cpe_status, conclusion.cpe_source_count,
			COALESCE(source.source_key, ''), COALESCE(source_rule.source_rule_id, ''),
			COALESCE(match.source_product_name, ''), COALESCE(match.evidence_summary, '')
		FROM asset_fingerprint_conclusions AS conclusion
		JOIN latest_port_runs AS latest ON latest.port = conclusion.port AND latest.scan_task_run_id = conclusion.scan_task_run_id
		LEFT JOIN asset_fingerprint_matches AS match
			ON match.scan_task_run_id = conclusion.scan_task_run_id AND match.ip = conclusion.ip
			AND match.port = conclusion.port AND match.protocol = conclusion.protocol
			AND match.product_key = conclusion.product_key AND match.is_soft = 0
		LEFT JOIN fingerprint_source_rules AS source_rule ON source_rule.id = match.fingerprint_source_rule_id
		LEFT JOIN fingerprint_imports AS import_revision ON import_revision.id = source_rule.fingerprint_import_id
		LEFT JOIN fingerprint_sources AS source ON source.id = import_revision.fingerprint_source_id
		WHERE conclusion.ip = ?
		ORDER BY conclusion.port, conclusion.product_role, conclusion.product_key, conclusion.protocol, source.source_key, source_rule.source_rule_id`, ip, ip)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "no such table") && strings.Contains(message, "fingerprint") {
			return nil
		}
		return err
	}
	defer rows.Close()
	byPort := make(map[int]map[string]*assetTechnologyAccumulator)
	for rows.Next() {
		var port, productSources, versionSources, cpeSources int
		var protocol, product, role, exclusiveGroup, version, cpe, tagsJSON string
		var productStatus, versionStatus, cpeStatus, sourceKey, sourceRuleID, sourceProduct, evidenceSummary string
		if err := rows.Scan(&port, &protocol, &product, &role, &exclusiveGroup, &version, &cpe, &tagsJSON,
			&productStatus, &productSources, &versionStatus, &versionSources, &cpeStatus, &cpeSources,
			&sourceKey, &sourceRuleID, &sourceProduct, &evidenceSummary); err != nil {
			return err
		}
		if _, ok := portIndexes[port]; !ok {
			continue
		}
		if byPort[port] == nil {
			byPort[port] = make(map[string]*assetTechnologyAccumulator)
		}
		key := strings.ToLower(strings.TrimSpace(product)) + "\x00" + strings.ToLower(strings.TrimSpace(role)) + "\x00" + strings.ToLower(strings.TrimSpace(exclusiveGroup))
		value := byPort[port][key]
		if value == nil {
			value = &assetTechnologyAccumulator{
				technology: model.AssetTechnology{ProductKey: product, DisplayName: product, Role: role, ExclusiveGroup: exclusiveGroup},
				protocols:  make(map[string]struct{}), versions: make(map[string]struct{}), cpes: make(map[string]struct{}), tags: make(map[string]struct{}),
				sourceProducts: make(map[string]struct{}), sources: make(map[string]model.AssetTechnologySource), evidence: make(map[string]struct{}),
			}
			byPort[port][key] = value
		}
		addNonEmptySet(value.protocols, protocol)
		addNonEmptySet(value.versions, version)
		addNonEmptySet(value.cpes, cpe)
		var tags []string
		_ = json.Unmarshal([]byte(tagsJSON), &tags)
		for _, tag := range tags {
			addNonEmptySet(value.tags, tag)
		}
		addNonEmptySet(value.sourceProducts, sourceProduct)
		addNonEmptySet(value.evidence, evidenceSummary)
		if sourceKey != "" || sourceRuleID != "" || sourceProduct != "" {
			sourceIdentity := sourceKey + "\x00" + sourceRuleID + "\x00" + sourceProduct
			value.sources[sourceIdentity] = model.AssetTechnologySource{SourceKey: sourceKey, SourceRuleID: sourceRuleID, SourceProduct: sourceProduct}
		}
		value.productStatus = strongerEvidenceStatus(value.productStatus, productStatus)
		value.versionStatus = strongerEvidenceStatus(value.versionStatus, versionStatus)
		value.cpeStatus = strongerEvidenceStatus(value.cpeStatus, cpeStatus)
		value.productSourceCount = maxInt(value.productSourceCount, productSources)
		value.versionSourceCount = maxInt(value.versionSourceCount, versionSources)
		value.cpeSourceCount = maxInt(value.cpeSourceCount, cpeSources)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for port, products := range byPort {
		index := portIndexes[port]
		technologies := make([]model.AssetTechnology, 0, len(products))
		for _, value := range products {
			technology := value.technology
			technology.Protocols = sortedSet(value.protocols)
			technology.VersionCandidates = sortedSet(value.versions)
			technology.CPECandidates = sortedSet(value.cpes)
			technology.Tags = sortedSet(value.tags)
			technology.SourceProductNames = sortedSet(value.sourceProducts)
			technology.EvidenceSummaries = sortedSet(value.evidence)
			technology.Sources = sortedTechnologySources(value.sources)
			technology.ProductStatus = nonEmptyStatus(value.productStatus, "matched")
			technology.VersionStatus = nonEmptyStatus(value.versionStatus, "unobserved")
			technology.CPEStatus = nonEmptyStatus(value.cpeStatus, "unobserved")
			technology.ProductSourceCount = maxInt(value.productSourceCount, len(technology.Sources))
			technology.VersionSourceCount = value.versionSourceCount
			technology.CPESourceCount = value.cpeSourceCount
			if len(technology.VersionCandidates) == 1 {
				technology.Version = technology.VersionCandidates[0]
			} else if len(technology.VersionCandidates) > 1 {
				technology.VersionStatus = "conflicted"
			}
			if len(technology.CPECandidates) == 1 {
				technology.CPE = technology.CPECandidates[0]
			} else if len(technology.CPECandidates) > 1 {
				technology.CPEStatus = "conflicted"
			}
			technologies = append(technologies, technology)
		}
		sort.Slice(technologies, func(left, right int) bool {
			if technologies[left].Role != technologies[right].Role {
				return technologies[left].Role < technologies[right].Role
			}
			return technologies[left].ProductKey < technologies[right].ProductKey
		})
		for technologyIndex := range technologies {
			if technologies[technologyIndex].ProductStatus != "conflicted" || technologies[technologyIndex].ExclusiveGroup == "" {
				continue
			}
			for candidateIndex := range technologies {
				if candidateIndex != technologyIndex && technologies[candidateIndex].ExclusiveGroup == technologies[technologyIndex].ExclusiveGroup {
					technologies[technologyIndex].ConflictCandidates = append(technologies[technologyIndex].ConflictCandidates, technologies[candidateIndex].ProductKey)
				}
			}
			sort.Strings(technologies[technologyIndex].ConflictCandidates)
		}
		ports[index].Technologies = technologies
	}
	return nil
}

func loadAssetPortValidationSet(db *sql.DB, ip string, ports []model.AssetPort) error {
	if len(ports) == 0 {
		return nil
	}
	portIndexes := make(map[int]int, len(ports))
	for index := range ports {
		portIndexes[ports[index].Port] = index
	}
	rows, err := db.Query(latestAssetPortRunsCTE+`
		SELECT latest.port, endpoint.protocol, endpoint.enabled, endpoint.status, endpoint.reason,
			endpoint.identified_product_count, endpoint.mapped_product_count, endpoint.unmapped_products_json,
			endpoint.candidate_template_count, endpoint.executed_template_count, endpoint.finding_count,
			COALESCE(endpoint.started_at, ''), COALESCE(endpoint.finished_at, ''), COALESCE(endpoint.error_message, ''),
			COALESCE(validation.candidate_endpoint_count, 0), COALESCE(validation.executed_endpoint_count, 0),
			COALESCE(validation.identified_product_count, 0), COALESCE(validation.mapped_product_count, 0),
			COALESCE(validation.template_count, 0), COALESCE(validation.executed_template_count, 0), COALESCE(validation.finding_count, 0)
		FROM latest_port_runs AS latest
		JOIN scan_task_run_endpoint_validation AS endpoint
			ON endpoint.scan_task_run_id = latest.scan_task_run_id AND endpoint.ip = ? AND endpoint.port = latest.port
		LEFT JOIN scan_task_run_validation AS validation ON validation.scan_task_run_id = latest.scan_task_run_id
		ORDER BY latest.port, endpoint.protocol`, ip, ip)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "no such table: scan_task_run_endpoint_validation") {
			return nil
		}
		return err
	}
	for rows.Next() {
		var port int
		var endpoint model.ScanTaskRunEndpointValidation
		var enabled int
		var unmappedProductsJSON string
		var runCandidateEndpoints, runExecutedEndpoints, runIdentified, runMapped, runTemplates, runExecutedTemplates, runFindings int
		if err := rows.Scan(&port, &endpoint.Protocol, &enabled, &endpoint.Status, &endpoint.Reason,
			&endpoint.IdentifiedProductCount, &endpoint.MappedProductCount, &unmappedProductsJSON,
			&endpoint.CandidateTemplateCount, &endpoint.ExecutedTemplateCount, &endpoint.FindingCount,
			&endpoint.StartedAt, &endpoint.FinishedAt, &endpoint.Error,
			&runCandidateEndpoints, &runExecutedEndpoints, &runIdentified, &runMapped,
			&runTemplates, &runExecutedTemplates, &runFindings); err != nil {
			rows.Close()
			return err
		}
		if index, ok := portIndexes[port]; ok {
			endpoint.IP = ip
			endpoint.Port = port
			endpoint.Enabled = enabled != 0
			endpoint.UnmappedProducts = make([]string, 0)
			_ = json.Unmarshal([]byte(unmappedProductsJSON), &endpoint.UnmappedProducts)
			ports[index].EndpointValidations = append(ports[index].EndpointValidations, endpoint)
			summary := &ports[index].Validation
			summary.Enabled = summary.Enabled || endpoint.Enabled
			summary.Status = mergeAssetValidationStatus(summary.Status, endpoint.Status)
			if summary.Reason == "" || endpoint.Status == model.ScanTaskRunValidationFailed {
				summary.Reason = endpoint.Reason
			}
			summary.IdentifiedProductCount += endpoint.IdentifiedProductCount
			summary.MappedProductCount += endpoint.MappedProductCount
			summary.CandidateTemplateCount += endpoint.CandidateTemplateCount
			summary.ExecutedTemplateCount += endpoint.ExecutedTemplateCount
			summary.FindingCount += endpoint.FindingCount
			summary.UnmappedProducts = append(summary.UnmappedProducts, endpoint.UnmappedProducts...)
			summary.StartedAt, summary.FinishedAt = endpoint.StartedAt, endpoint.FinishedAt
			if endpoint.Error != "" {
				summary.Error = endpoint.Error
			}
			summary.RunCandidateEndpointCount, summary.RunExecutedEndpointCount = runCandidateEndpoints, runExecutedEndpoints
			summary.RunIdentifiedProductCount, summary.RunMappedProductCount = runIdentified, runMapped
			summary.RunTemplateCount, summary.RunExecutedTemplateCount, summary.RunFindingCount = runTemplates, runExecutedTemplates, runFindings
			summary.Findings = make([]model.ScanTaskRunVulnerability, 0)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for index := range ports {
		ports[index].Validation.UnmappedProducts = uniqueSortedStrings(ports[index].Validation.UnmappedProducts)
	}
	candidateRows, err := db.Query(latestAssetPortRunsCTE+`
		SELECT endpoint.port, endpoint.template_id, endpoint.path,
			COALESCE(product.product_key, NULLIF(endpoint.product_key, ''), ''), COALESCE(endpoint.executed, 0)
		FROM scan_task_run_template_candidate_endpoints AS endpoint
		JOIN latest_port_runs AS latest ON latest.port = endpoint.port AND latest.scan_task_run_id = endpoint.scan_task_run_id
		LEFT JOIN scan_task_run_template_candidate_products AS product
			ON product.scan_task_run_id = endpoint.scan_task_run_id AND product.template_id = endpoint.template_id AND product.path = endpoint.path
			AND product.ip = endpoint.ip AND product.port = endpoint.port AND product.protocol = endpoint.protocol
		WHERE endpoint.ip = ?
		ORDER BY endpoint.port, endpoint.template_id, endpoint.path, product.product_key`, ip, ip)
	if err != nil {
		return err
	}
	templatesByPort := make(map[int]map[string]struct{})
	executedTemplatesByPort := make(map[int]map[string]struct{})
	mappedProductsByPort := make(map[int]map[string]struct{})
	for candidateRows.Next() {
		var port, executed int
		var templateID, path, product string
		if err := candidateRows.Scan(&port, &templateID, &path, &product, &executed); err != nil {
			candidateRows.Close()
			return err
		}
		if _, ok := portIndexes[port]; ok {
			if templatesByPort[port] == nil {
				templatesByPort[port] = make(map[string]struct{})
			}
			templatesByPort[port][templateID+"\x00"+path] = struct{}{}
			if executed != 0 {
				if executedTemplatesByPort[port] == nil {
					executedTemplatesByPort[port] = make(map[string]struct{})
				}
				executedTemplatesByPort[port][templateID+"\x00"+path] = struct{}{}
			}
			if product != "" {
				if mappedProductsByPort[port] == nil {
					mappedProductsByPort[port] = make(map[string]struct{})
				}
				mappedProductsByPort[port][strings.ToLower(strings.TrimSpace(product))] = struct{}{}
			}
		}
	}
	if err := candidateRows.Err(); err != nil {
		candidateRows.Close()
		return err
	}
	if err := candidateRows.Close(); err != nil {
		return err
	}
	for port, index := range portIndexes {
		ports[index].Validation.CandidateTemplateCount = len(templatesByPort[port])
		ports[index].Validation.ExecutedTemplateCount = len(executedTemplatesByPort[port])
		ports[index].Validation.MappedProductCount = len(mappedProductsByPort[port])
		ports[index].Validation.UnmappedProducts = make([]string, 0)
		for _, technology := range ports[index].Technologies {
			if _, mapped := mappedProductsByPort[port][strings.ToLower(strings.TrimSpace(technology.ProductKey))]; !mapped {
				ports[index].Validation.UnmappedProducts = append(ports[index].Validation.UnmappedProducts, technology.ProductKey)
			}
		}
		sort.Strings(ports[index].Validation.UnmappedProducts)
	}
	findingRows, err := db.Query(latestAssetPortRunsCTE+`
		SELECT finding.target_port, finding.finding_key, COALESCE(finding.template_id, ''), COALESCE(finding.name, ''),
			COALESCE(finding.severity, ''), finding.target, COALESCE(finding.target_ip, ''),
			COALESCE(finding.matched_at, ''), COALESCE(finding.description, '')
		FROM scan_task_run_vulnerabilities AS finding
		JOIN latest_port_runs AS latest ON latest.port = finding.target_port AND latest.scan_task_run_id = finding.scan_task_run_id
		WHERE finding.target_ip = ?
		ORDER BY finding.target_port, finding.finding_key`, ip, ip)
	if err != nil {
		return err
	}
	defer findingRows.Close()
	for findingRows.Next() {
		var finding model.ScanTaskRunVulnerability
		if err := findingRows.Scan(&finding.TargetPort, &finding.FindingKey, &finding.TemplateID, &finding.Name,
			&finding.Severity, &finding.Target, &finding.TargetIP, &finding.MatchedAt, &finding.Description); err != nil {
			return err
		}
		if index, ok := portIndexes[finding.TargetPort]; ok {
			ports[index].Validation.Findings = append(ports[index].Validation.Findings, finding)
			ports[index].Validation.FindingCount = len(ports[index].Validation.Findings)
		}
	}
	return findingRows.Err()
}

func finalizeAssetPortProfiles(ports []model.AssetPort) {
	for index := range ports {
		port := &ports[index]
		port.Validation.IdentifiedProductCount = len(port.Technologies)
		if port.Validation.Enabled && port.Validation.Status == model.ScanTaskRunValidationSuccess && port.Validation.CandidateTemplateCount == 0 {
			port.Validation.Status = model.ScanTaskRunValidationNoCandidates
		}
		if port.ObservationRunID == 0 {
			port.UnresolvedReasons = append(port.UnresolvedReasons, "observation_unavailable")
		}
		responded := false
		for _, evidence := range port.ProtocolEvidence {
			responded = responded || evidence.Responded
		}
		if !responded {
			port.UnresolvedReasons = append(port.UnresolvedReasons, "no_protocol_response")
		}
		if len(port.Technologies) == 0 {
			port.UnresolvedReasons = append(port.UnresolvedReasons, "unidentified_product")
		}
		if len(port.Validation.UnmappedProducts) > 0 && port.Validation.MappedProductCount > 0 {
			port.UnresolvedReasons = append(port.UnresolvedReasons, "partial_template_mapping")
		}
		if port.Validation.Reason == "" {
			port.Validation.Reason = assetValidationReason(*port)
		}
		if port.Validation.Reason != "" && port.Validation.Reason != "disabled" {
			port.UnresolvedReasons = append(port.UnresolvedReasons, port.Validation.Reason)
		}
		port.UnresolvedReasons = uniqueSortedStrings(port.UnresolvedReasons)
	}
}

func mergeAssetValidationStatus(current, next string) string {
	priority := map[string]int{
		model.ScanTaskRunValidationDisabled: 1, model.ScanTaskRunValidationNotStarted: 2,
		model.ScanTaskRunValidationNoCandidates: 3, model.ScanTaskRunValidationSuccess: 4,
		model.ScanTaskRunValidationFailed: 5,
	}
	if priority[next] > priority[current] {
		return next
	}
	return current
}

func assetValidationReason(port model.AssetPort) string {
	switch port.Validation.Status {
	case model.ScanTaskRunValidationDisabled:
		return "disabled"
	case model.ScanTaskRunValidationNotStarted:
		return "scan_or_collection_incomplete"
	case model.ScanTaskRunValidationNoCandidates:
		if len(port.Technologies) == 0 {
			return "unidentified_product"
		}
		return "mapping_missing"
	case model.ScanTaskRunValidationFailed:
		return "execution_failed"
	case model.ScanTaskRunValidationSuccess:
		return ""
	default:
		if port.ObservationRunID == 0 {
			return "observation_unavailable"
		}
		return "validation_state_unavailable"
	}
}

func addNonEmptySet(set map[string]struct{}, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		set[value] = struct{}{}
	}
}

func sortedSet(set map[string]struct{}) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func sortedTechnologySources(values map[string]model.AssetTechnologySource) []model.AssetTechnologySource {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]model.AssetTechnologySource, 0, len(keys))
	for _, key := range keys {
		result = append(result, values[key])
	}
	return result
}

func strongerEvidenceStatus(current, candidate string) string {
	rank := map[string]int{"": 0, "unobserved": 1, "matched": 2, "corroborated": 3, "conflicted": 4}
	if rank[candidate] > rank[current] {
		return candidate
	}
	return current
}

func nonEmptyStatus(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func uniqueSortedStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		addNonEmptySet(set, value)
	}
	return sortedSet(set)
}

func applyAssetPortEvidenceCompatibility(port *model.AssetPort) {
	if port == nil {
		return
	}
	var evidence model.ScanTaskRunProtocolEvidence
	priority := 0
	for _, candidate := range port.ProtocolEvidence {
		if !candidate.Responded {
			continue
		}
		candidatePriority := 1
		if candidate.EvidenceType == model.ProtocolEvidencePassiveBanner {
			candidatePriority = 2
		} else if candidate.EvidenceType == model.ProtocolEvidenceWeb {
			candidatePriority = 3
		}
		if candidatePriority > priority {
			evidence = candidate
			priority = candidatePriority
		}
	}
	if priority == 0 {
		return
	}
	port.Protocol = evidence.Protocol
	port.StatusCode = evidence.StatusCode
	port.Server = evidence.Server
	port.Title = evidence.Title
	port.ResponseLength = evidence.BodyCapturedLength
	port.ResponseSHA256 = evidence.BodySHA256
	port.ResponseTruncated = evidence.BodyTruncated
	if port.ResponseLength == 0 {
		port.ResponseLength = evidence.HeaderCapturedLength
		port.ResponseSHA256 = evidence.HeaderSHA256
		port.ResponseTruncated = evidence.HeaderTruncated
	}
	if port.ResponseLength == 0 {
		port.ResponseLength = evidence.BannerCapturedLength
		port.ResponseSHA256 = evidence.BannerSHA256
		port.ResponseTruncated = evidence.BannerTruncated
	}
}

func isMissingCurrentPortInventory(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table: current_port_inventory")
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
