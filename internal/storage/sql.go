package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
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
	tables := []string{"banner", "scan_results", "domain_info", "domain_ips", "tasks", "pocs", "vulnerabilities"}
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

func initSQLiteSchema(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS banner (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name   TEXT    NOT NULL,
    banner_pattern TEXT    NOT NULL,
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
    title       TEXT,
    first_seen  DATETIME NOT NULL,
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
    UNIQUE(domain_id, ip)
);

CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_type   TEXT    NOT NULL,
    target      TEXT    NOT NULL,
    status      TEXT    NOT NULL,
    progress    INTEGER NOT NULL DEFAULT 0,
    error_msg   TEXT,
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
`
	_, err := db.Exec(schema)
	return err
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

	var out []model.Vulnerability
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
	var startedAt, finishedAt, errorMsg, updatedAt sql.NullString

	err := db.QueryRow(`
		SELECT id, task_type, target, status, progress, error_msg, started_at, finished_at, created_at, updated_at
		FROM tasks
		WHERE id = ?`, taskID).Scan(
		&t.ID,
		&t.TaskType,
		&t.Target,
		&t.Status,
		&t.Progress,
		&errorMsg,
		&startedAt,
		&finishedAt,
		&t.CreatedAt,
		&updatedAt,
	)
	if err != nil {
		return model.Task{}, err
	}

	applyNullableTaskFields(&t, errorMsg, startedAt, finishedAt, updatedAt)

	return t, nil
}

func ListTasks(db *sql.DB) ([]model.Task, error) {
	rows, err := db.Query(`
		SELECT id, task_type, target, status, progress, error_msg, started_at, finished_at, created_at, updated_at
		FROM tasks
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []model.Task
	for rows.Next() {
		var t model.Task
		var startedAt, finishedAt, errorMsg, updatedAt sql.NullString
		if err := rows.Scan(
			&t.ID,
			&t.TaskType,
			&t.Target,
			&t.Status,
			&t.Progress,
			&errorMsg,
			&startedAt,
			&finishedAt,
			&t.CreatedAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		applyNullableTaskFields(&t, errorMsg, startedAt, finishedAt, updatedAt)
		tasks = append(tasks, t)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tasks, nil
}

func applyNullableTaskFields(t *model.Task, errorMsg, startedAt, finishedAt, updatedAt sql.NullString) {
	if errorMsg.Valid {
		t.ErrorMsg = errorMsg.String
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
	return UpdateTaskStatus(db, taskID, model.TaskStatusCanceled, "")
}

func IsTaskCanceled(db *sql.DB, taskID int64) (bool, error) {
	status, err := GetTaskStatus(db, taskID)
	if err != nil {
		return false, err
	}
	return status == model.TaskStatusCanceled, nil
}

func isValidTaskTransition(fromStatus, toStatus string) bool {
	if fromStatus == toStatus {
		return true
	}

	allowed := map[string]map[string]bool{
		model.TaskStatusQueued: {
			model.TaskStatusRunning:  true,
			model.TaskStatusCanceled: true,
		},
		model.TaskStatusRunning: {
			model.TaskStatusSuccess:  true,
			model.TaskStatusFailed:   true,
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

func SaveResult(db *sql.DB, result model.ScanResult) error {
	if !result.Open || result.Service == "unknown" || result.Service == "None_unknown" {
		return fmt.Errorf("skip: not open or unknown service")
	}

	ip, portStr, err := net.SplitHostPort(result.Address)
	if err != nil {
		return fmt.Errorf("解析地址失败: %v", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("端口转换失败: %v", err)
	}

	serviceType := MatchFingerprint(db, result.Banner)
	if serviceType == "" {
		serviceType = strings.ToLower(result.Service)
		if strings.HasPrefix(serviceType, "http") {
			serviceType = "http-unknown"
		}
	}
	if len(serviceType) > 255 {
		serviceType = serviceType[:255]
	}

	_, err = db.Exec(`
        INSERT OR REPLACE INTO scan_results 
        (ip, port, service_id, service_type, scan_time)
        VALUES (
            ?, 
            ?, 
            (SELECT id FROM banner WHERE service_name = ? LIMIT 1),
            ?,
            datetime('now')
        )
		ON CONFLICT(ip, port) DO UPDATE SET
            service_id   = excluded.service_id,
            service_type = excluded.service_type,
            scan_time    = datetime('now')               
		`, ip, port, serviceType, serviceType,
	)

	return err
}

func MatchFingerprint(db *sql.DB, banner string) string {
	var serviceName string

	cleaned := regexp.MustCompile(`[^\x09\x0A\x0D\x20-\x7E]+`).ReplaceAllString(banner, " ")
	cleaned = strings.TrimSpace(cleaned)
	cleaned = regexp.MustCompile(`\s+`).ReplaceAllString(cleaned, " ")

	if cleaned == "" {
		return ""
	}

	var service string
	if err := db.QueryRow(`
        SELECT service_name FROM banner
        WHERE banner_pattern <> '' AND service_name <> 'unknown'
          AND INSTR(?, banner_pattern) > 0
        ORDER BY LENGTH(banner_pattern) DESC
        LIMIT 1`, cleaned).Scan(&service); err == nil && service != "" {
		return service
	}

	rows, err := db.Query(`SELECT service_name, banner_pattern FROM banner WHERE banner_pattern <> '' AND service_name <> 'unknown'`)
	if err != nil {
		return ""
	}
	defer rows.Close()

	for rows.Next() {
		var s, p string
		if err := rows.Scan(&s, &p); err != nil {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		if re.MatchString(cleaned) {
			return s
		}
	}

	if err := db.QueryRow(`
	   SELECT service_name FROM banner
	   WHERE ? LIKE banner_pattern
	   ORDER BY LENGTH(banner_pattern) DESC
	   LIMIT 1`, cleaned).Scan(&serviceName); err == nil && serviceName != "" {
		return serviceName
	}

	if strings.Contains(cleaned, "HTTP/") {
		if server := assist.ExtractHeader(cleaned, "Server"); server != "" {
			if err := db.QueryRow(`
			   SELECT service_name FROM banner
			   WHERE ? REGEXP banner_pattern
			   ORDER BY LENGTH(banner_pattern) DESC
			   LIMIT 1`, server).Scan(&serviceName); err == nil && serviceName != "" {
				return serviceName
			}
			if err := db.QueryRow(`
			   SELECT service_name FROM banner
			   WHERE ? LIKE banner_pattern
			   ORDER BY LENGTH(banner_pattern) DESC
			   LIMIT 1`, server).Scan(&serviceName); err == nil && serviceName != "" {
				return serviceName
			}
		}
	}

	return serviceName
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
            SET title = ?, last_scan = datetime('now')
            WHERE id = (SELECT domain_id FROM domain_ips WHERE ip = ? LIMIT 1)`,
			title, ip)
		if err != nil {
			return fmt.Errorf("更新标题失败: %v", err)
		}
	}

	return nil
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

func SaveDomainInfo(db *sql.DB, mainDomain, subdomain string, isWildcard bool, title string, source string) (int64, error) {
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

	res, err := db.Exec(`
        INSERT INTO domain_info 
        (domain, subdomain, is_wildcard, title, first_seen, last_scan, source)
        VALUES (?, ?, ?, ?, datetime('now'), datetime('now'), ?)`,
		mainDomain,
		subdomain,
		isWildcard,
		title,
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
            last_scan = datetime('now')
        WHERE subdomain = ?`,
		title, title,
		newSource,
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

func SaveDomainIP(db *sql.DB, domainID int64, ip string, subdomain string, ports []int) error {
	portsJSON, _ := json.Marshal(ports)
	_, err := db.Exec(`
        INSERT OR REPLACE INTO domain_ips 
        (domain_id, subdomain, ip, ports)
        VALUES (?, ?, ?, ?)`,
		domainID,
		subdomain,
		ip,
		string(portsJSON),
	)
	return err
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
