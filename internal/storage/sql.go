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
		if err := initSQLiteSchema(db); err != nil {
			db.Close()
			return nil, fmt.Errorf("初始化 SQLite 表结构失败: %v", err)
		}
		log.Println("SQLite 数据库初始化完成")
	}

	if err := resetSequencesIfEmpty(db); err != nil {
		log.Printf("重置自增序列失败: %v", err)
	}

	return db, nil
}

func resetSequencesIfEmpty(db *sql.DB) error {
	tables := []string{"banner", "scan_results", "domain_info", "domain_ips"}
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
`
	_, err := db.Exec(schema)
	return err
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
            SET title = ?, last_scan = NOW()
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
