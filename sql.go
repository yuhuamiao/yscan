package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const sqliteFile = "asm.db"

//// 常见端口兜底映射
//var defaultPortService = map[int]string{
//	21:    "ftp",
//	22:    "ssh",
//	23:    "telnet",
//	25:    "smtp",
//	53:    "dns",
//	80:    "http",
//	110:   "pop3",
//	143:   "imap",
//	389:   "ldap",
//	443:   "http",
//	465:   "smtp",
//	587:   "smtp",
//	993:   "imap",
//	995:   "pop3",
//	1433:  "mssql",
//	1521:  "oracle",
//	3306:  "mysql",
//	3389:  "rdp",
//	5432:  "postgres",
//	5900:  "vnc",
//	6379:  "redis",
//	27017: "mongodb",
//}

// InitDB 初始化 SQLite 数据库（当前目录下 asm.db）。
// 如果文件不存在则创建并初始化表结构；存在则直接使用。
func InitDB() (*sql.DB, error) {
	dbExists := fileExists(sqliteFile)

	db, err := sql.Open("sqlite3", sqliteFile)
	if err != nil {
		return nil, fmt.Errorf("打开 SQLite 数据库失败: %v", err)
	}

	// SQLite 不需要太多连接
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("SQLite 连接测试失败: %v", err)
	}

	// 如果是新建的数据库文件，初始化表结构
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

// 重置已知表的 AUTOINCREMENT 序列（仅当表为空）
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

// 修改saveResult函数
func SaveResult(db *sql.DB, result scanResult) error { //用于存放 scan_results 库
	if !result.open || result.service == "unknown" || result.service == "None_unknown" {
		return fmt.Errorf("skip: not open or unknown service") // 只存储开放端口
	}

	ip, portStr, err := net.SplitHostPort(result.address)
	if err != nil {
		return fmt.Errorf("解析地址失败: %v", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("端口转换失败: %v", err)
	}

	serviceType := MatchFingerprint(db, result.banner)

	if serviceType == "" {
		serviceType = strings.ToLower(result.service)
		if strings.HasPrefix(serviceType, "http") {
			serviceType = "http-unknown"
		}
	}
	if len(serviceType) > 255 {
		serviceType = serviceType[:255]
	}

	// 限制banner长度以避免溢出
	banner := result.banner
	if len(banner) > 65535 {
		banner = banner[:65535]
	}

	//a, _ := db.Exec(`select * from scan_results `)
	//fmt.Println(a)

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

	//b, _ := db.Exec(`select * from scan_results `)
	//fmt.Println(b)

	return err
}

//func MatchFingerprint(db *sql.DB, banner string) string { //和 banner 库进行匹配，实验一；放弃原因：用正则匹配，换下面尝试用模糊匹配
//	var serviceName string
//	db.QueryRow(`
//     SELECT service_name FROM banner
//     WHERE ? REGEXP banner_pattern  -- 改用REGEXP
//     ORDER BY
//         LENGTH(banner_pattern) DESC,  -- 优先匹配更长模式
//         CASE WHEN banner_pattern LIKE '^%' THEN 0 ELSE 1 END  -- 优先匹配开头模式
//     LIMIT 1`, banner).Scan(&serviceName)
//	return serviceName
//}

//func MatchFingerprint(db *sql.DB, banner string) string { //和 banner 库进行匹配，实验二：放弃原因：下面有更完善的版本，但这个先不删
//	var serviceName string
//	db.QueryRow(`
//      SELECT service_name FROM banner
//      WHERE ? LIKE CONCAT('%', banner_pattern, '%')
//      ORDER BY LENGTH(banner_pattern) DESC
//      LIMIT 1`, banner).Scan(&serviceName)
//	return serviceName
//}

func MatchFingerprint(db *sql.DB, banner string) string {
	var serviceName string

	// 1. 预处理Banner：移除首尾空白、压缩连续空格
	// 去除不可打印字符，压缩空白
	cleaned := regexp.MustCompile(`[^\x09\x0A\x0D\x20-\x7E]+`).ReplaceAllString(banner, " ")
	cleaned = strings.TrimSpace(banner)
	cleaned = regexp.MustCompile(`\s+`).ReplaceAllString(cleaned, " ")

	if cleaned == "" {
		return ""
	}

	// 2. 优先匹配完整Banner（使用REGEXP）
	//err := db.QueryRow(`
	//   SELECT service_name FROM banner
	//   WHERE ? REGEXP banner_pattern
	//   ORDER BY
	//       CASE
	//           WHEN banner_pattern LIKE '^[^^].*%' THEN 0
	//           ELSE 1
	//       END,
	//       LENGTH(banner_pattern) DESC
	//   LIMIT 1`, cleaned).Scan(&serviceName)
	//
	//if err == nil {
	//	return serviceName
	//}

	var service string
	if err := db.QueryRow(`
        SELECT service_name FROM banner
        WHERE banner_pattern <> '' AND service_name <> 'unknown'
          AND INSTR(?, banner_pattern) > 0
        ORDER BY LENGTH(banner_pattern) DESC
        LIMIT 1`, cleaned).Scan(&service); err == nil && service != "" {
		return service
	}

	// 2) Go regexp 逐条匹配（兼容你表里带正则的模式）
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
			continue // 跳过非法正则
		}
		if re.MatchString(cleaned) {
			return s
		}
	}

	// LIKE 兜底
	if err := db.QueryRow(`
	   SELECT service_name FROM banner
	   WHERE ? LIKE banner_pattern
	   ORDER BY LENGTH(banner_pattern) DESC
	   LIMIT 1`, cleaned).Scan(&serviceName); err == nil && serviceName != "" {
		return serviceName
	}

	// 3. 关键行匹配（针对HTTP等多行协议）
	if strings.Contains(cleaned, "HTTP/") {
		if server := ExtractHeader(cleaned, "Server"); server != "" {
			//db.QueryRow(`
			//   SELECT service_name FROM banner
			//   WHERE ? REGEXP banner_pattern
			//   ORDER BY LENGTH(banner_pattern) DESC
			//   LIMIT 1`, server).Scan(&serviceName)
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

func SaveDomainScanResult(db *sql.DB, ip string, openPorts []scanResult) error {
	var ports []int
	var title string

	// 优先从HTTP服务中提取标题
	for _, result := range openPorts {
		_, portStr, _ := net.SplitHostPort(result.address)
		port, _ := strconv.Atoi(portStr)
		ports = append(ports, port)

		if title == "" && strings.HasPrefix(result.service, "http") {
			title = extractTitleFromBanner(result.banner)
			// 如果从banner中没提取到，尝试直接请求
			if title == "" {
				title = GetWebsiteTitle(ip, port)
			}
		}
	}

	// 更新标题和端口信息
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

	// 如果有标题，更新到domain_info
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

// 辅助函数
func extractTitleFromBanner(banner string) string {
	// 先检查是否是HTTP响应
	if !strings.Contains(banner, "HTTP/") {
		return ""
	}

	// 更健壮的标题提取方式
	re := regexp.MustCompile(`(?is)<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(banner)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// 去除换行和多余空格
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

// SaveDomainInfo 保存子域名信息
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

	// 合并新来源
	if !existingSources[source] {
		existingSources[source] = true
	}

	// 构建新来源字符串
	var uniqueSources []string
	for s := range existingSources {
		uniqueSources = append(uniqueSources, s)
	}
	newSource := strings.Join(uniqueSources, ",")

	// 限制长度（假设source字段是VARCHAR(255)）
	if len(newSource) > 255 {
		newSource = newSource[:255]
	}

	// 先尝试插入（不存在则插入，存在则失败）
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

	// 如果插入失败（大概率是 UNIQUE(subdomain) 冲突），则执行更新
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

	// 返回已有记录的 id
	var id int64
	if err := db.QueryRow(`SELECT id FROM domain_info WHERE subdomain = ?`, subdomain).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// SaveDomainIP 保存域名解析IP
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
