package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func InitDB() (*sql.DB, error) {
	db, err := sql.Open("mysql", "root:mysqlyd0ngAlicloud@tcp(47.113.206.220:3306)/ASM?parseTime=true")
	if err != nil {
		return nil, fmt.Errorf("数据库连接失败: %v", err)
	}

	// 设置连接池参数
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("数据库连接测试失败: %v", err)
	}
	return db, nil
}

// 修改saveResult函数
func SaveResult(db *sql.DB, result scanResult) error { //用于存放 scan_results 库
	if !result.open || result.service == "unknown" {
		return nil // 只存储开放端口
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
        INSERT INTO scan_results 
        (ip, port, service_id, service_type)
        VALUES (?, ?, 
            (SELECT id FROM banner WHERE service_name = ? LIMIT 1),
            ?)
        ON DUPLICATE KEY UPDATE
            service_id = VALUES(service_id),
            service_type = VALUES(service_type)`,
		ip, port, serviceType, serviceType,
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
	cleaned := strings.TrimSpace(banner)
	cleaned = regexp.MustCompile(`\s+`).ReplaceAllString(cleaned, " ")

	// 2. 优先匹配完整Banner（使用REGEXP）
	err := db.QueryRow(`
        SELECT service_name FROM banner 
        WHERE ? REGEXP banner_pattern
        ORDER BY
            CASE 
                WHEN banner_pattern LIKE '^[^^].*%' THEN 0  -- 非^开头优先
                ELSE 1
            END,
            LENGTH(banner_pattern) DESC
        LIMIT 1`, cleaned).Scan(&serviceName)

	if err == nil {
		return serviceName
	}

	// 3. 关键行匹配（针对HTTP等多行协议）
	if strings.Contains(cleaned, "HTTP/") {
		if server := ExtractHeader(cleaned, "Server"); server != "" {
			db.QueryRow(`
                SELECT service_name FROM banner 
                WHERE ? REGEXP banner_pattern
                ORDER BY LENGTH(banner_pattern) DESC
                LIMIT 1`, server).Scan(&serviceName)
		}
	}

	return serviceName
}

//func MatchFingerprint(db *sql.DB, banner string, port int) string { //用其他的库进行匹配，这个库有点问题，先注释在这里放着
//	var serviceName string
//
//	err := db.QueryRow(`
//        SELECT description FROM finger_print
//        WHERE match_type = 'regex'
//        AND ? REGEXP keyword
//        AND protocol_type = 'TCP'
//        ORDER BY
//            CASE
//                WHEN description IN ('ssh', 'ftp', 'mysql', 'http', 'nginx', 'apache', 'iis') THEN 0
//                ELSE 1
//            END,
//            LENGTH(keyword) DESC
//        LIMIT 1`, banner).Scan(&serviceName)
//
//	if err == nil && serviceName != "" {
//		return serviceName
//	}
//
//	if strings.Contains(banner, "HTTP/") { //先匹配 http 服务
//		err := db.QueryRow(`
//            SELECT description FROM finger_print
//            WHERE match_type = 'regex'
//            AND ? REGEXP keyword
//            AND description IN ('nginx','apache','iis','http')
//            ORDER BY LENGTH(keyword) DESC
//            LIMIT 1`,
//			banner).Scan(&serviceName)
//
//		if err == nil && serviceName != "" {
//			log.Printf("DEBUG - HTTP服务匹配成功: %s", serviceName)
//			return serviceName
//		}
//	}
//
//	// 1. 优先尝试精确的banner匹配
//	err = db.QueryRow(`
//        SELECT description FROM finger_print
//        WHERE match_type = 'regex'
//        AND ? REGEXP keyword
//        AND (protocol_type = 'TCP' OR protocol_type IS NULL)
//        ORDER BY
//            CASE WHEN service_name IN ('ssh', 'ftp','mysql') THEN 0 ELSE 1 END, -- 优先匹配常见服务
//            LENGTH(keyword) DESC -- 其次匹配更长/更精确的模式
//        LIMIT 1`,
//		banner).Scan(&serviceName)
//
//	if err == nil && serviceName != "" {
//		return serviceName
//	}
//
//	// 次之尝试端口匹配
//	err = db.QueryRow(`
//        SELECT description FROM finger_print
//        WHERE match_type = 'port'
//        AND keyword = ?
//        LIMIT 1`,
//		strconv.Itoa(port)).Scan(&serviceName)
//
//	if err == nil && serviceName != "" {
//		return serviceName
//	}
//
//	// 3. 最后尝试模糊匹配
//	err = db.QueryRow(`
//        SELECT description FROM finger_print
//        WHERE match_type = 'regex'
//        AND ? LIKE CONCAT('%', keyword, '%')
//        AND (protocol_type = 'TCP' OR protocol_type IS NULL)
//        ORDER BY LENGTH(keyword) DESC
//        LIMIT 1`,
//		banner).Scan(&serviceName)
//
//	if err == nil && serviceName != "" {
//		return serviceName
//	}
//
//	return ""
//}

// SaveDomainScanResult 保存域名扫描结果
//func SaveDomainScanResult(db *sql.DB, ip string, openPorts []scanResult) error {//原先的
//	// 提取端口号列表
//	var ports []int
//	var title string
//
//	for _, result := range openPorts {
//		_, portStr, _ := net.SplitHostPort(result.address)
//		port, _ := strconv.Atoi(portStr)
//		ports = append(ports, port)
//
//		// 从第一个HTTP服务获取标题
//		if title == "" && strings.HasPrefix(result.service, "http") {
//			title = extractTitleFromBanner(result.banner)
//		}
//	}
//
//	// 更新domain_info中的标题(如果有)
//	if title != "" {
//		_, err := db.Exec(`
//            UPDATE domain_info d
//            JOIN domain_ips di ON d.id = di.domain_id
//            SET d.title = ?, d.last_scan = NOW()
//            WHERE di.ip = ?`,
//			title, ip)
//		if err != nil {
//			return fmt.Errorf("更新标题失败: %v", err)
//		}
//	}
//
//	// 更新domain_ips中的端口信息
//	_, err := db.Exec(`
//        UPDATE domain_ips
//        SET ports = ?
//        WHERE ip = ?`,
//		toJSON(ports),
//		ip)
//	if err != nil {
//		return fmt.Errorf("更新端口信息失败: %v", err)
//	}
//
//	return nil
//}

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
	//res, err := db.Exec(`
	//    INSERT INTO domain_info
	//    (domain, subdomain, is_wildcard, title, first_seen, source)
	//    VALUES (?, ?, ?, ?, NOW(), ?)
	//    ON DUPLICATE KEY UPDATE
	//        title = COALESCE(VALUES(title), title),
	//        last_scan = CURRENT_TIMESTAMP`,
	//	mainDomain,
	//	subdomain,
	//	isWildcard,
	//	title,
	//	source)
	// 去重处理来源
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

	res, err := db.Exec(`
        INSERT INTO domain_info 
        (domain, subdomain, is_wildcard, title, first_seen, source)
        VALUES (?, ?, ?, ?, NOW(), ?)
        ON DUPLICATE KEY UPDATE
            source = VALUES(source),
            last_scan = NOW()`,
		mainDomain, subdomain, isWildcard, title, newSource)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SaveDomainIP 保存域名解析IP
func SaveDomainIP(db *sql.DB, domainID int64, ip string, subdomain string, ports []int) error {
	portsJSON, _ := json.Marshal(ports)
	_, err := db.Exec(`
        INSERT INTO domain_ips 
        (domain_id, subdomain, ip, ports)
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            subdomain = VALUES(subdomain),
            ports = VALUES(ports)`,
		domainID,
		subdomain,
		ip,
		portsJSON)
	return err
}

//// SaveDomainToDB 保存子域名信息到数据库
//func SaveDomainToDB(db *sql.DB, result CollectResult) error { //这是后来加入的函数，专门用于子域名信息保存到数据库
//	// 先保存子域名信息
//	res, err := db.Exec(`
//        INSERT INTO domains
//        (domain, subdomain, is_wildcard, first_seen, source)
//        VALUES (?, ?, ?, ?, ?)
//        ON DUPLICATE KEY UPDATE
//            created_at = CURRENT_TIMESTAMP`,
//		"jiangnan.edu.cn", // 这里可以改为从参数获取
//		result.Subdomain,
//		strings.HasPrefix(result.Subdomain, "*."),
//		result.FirstSeen,
//		strings.Join(result.Sources, ","),
//	)
//	if err != nil {
//		return fmt.Errorf("保存子域名失败: %v", err)
//	}
//
//	// 如果是泛解析域名，不保存IP
//	if strings.HasPrefix(result.Subdomain, "*.") {
//		return nil
//	}
//
//	// 获取刚插入的domain_id
//	domainID, _ := res.LastInsertId()
//
//	// 保存IP信息
//	for _, ip := range result.IPs {
//		_, err := db.Exec(`
//            INSERT INTO domain_ips
//            (domain_id, ip)
//            VALUES (?, ?)
//            ON DUPLICATE KEY UPDATE
//                domain_id = VALUES(domain_id)`,
//			domainID,
//			ip.String(),
//		)
//		if err != nil {
//			log.Printf("保存IP %s 失败: %v", ip.String(), err)
//		}
//	}
//
//	return nil
//}

//package main//这是之前只存scan_results表的代码
//
//import (
//"database/sql"
//"fmt"
//"net"
//"strconv"
//"time"
//)
//
//func InitDB() (*sql.DB, error) {
//	db, err := sql.Open("mysql", "scan:437339Zzh@@tcp(localhost:3306)/scan?parseTime=true")
//	if err != nil {
//		return nil, fmt.Errorf("数据库连接失败: %v", err)
//	}
//
//	// 设置连接池参数
//	db.SetMaxOpenConns(20)
//	db.SetMaxIdleConns(10)
//	db.SetConnMaxLifetime(5 * time.Minute)
//
//	if err := db.Ping(); err != nil {
//		return nil, fmt.Errorf("数据库连接测试失败: %v", err)
//	}
//
//	return db, nil
//}
//
//// 修改saveResult函数
//func SaveResult(db *sql.DB, result scanResult) error {
//	if !result.open || result.service == "unknown" {
//		return nil // 只存储开放端口
//	}
//
//	ip, portStr, err := net.SplitHostPort(result.address)
//	if err != nil {
//		return fmt.Errorf("解析地址失败: %v", err)
//	}
//
//	port, err := strconv.Atoi(portStr)
//	if err != nil {
//		return fmt.Errorf("端口转换失败: %v", err)
//	}
//
//	serviceType := result.service
//	if len(serviceType) > 255 {
//		serviceType = serviceType[:255]
//	}
//
//	// 限制banner长度以避免溢出
//	banner := result.banner
//	if len(banner) > 65535 {
//		banner = banner[:65535]
//	}
//
//	//a, _ := db.Exec(`select * from scan_results `)
//	//fmt.Println(a)
//
//	_, err = db.Exec(`
//		INSERT INTO scan_results
//		(ip, port, service_type, banner)
//		VALUES (?, ?, ?, ?)
//		ON DUPLICATE KEY UPDATE
//			service_type = VALUES(service_type),
//			banner = VALUES(banner),
//			scan_time = CURRENT_TIMESTAMP`,
//		ip,
//		port,
//		result.service,
//		banner,
//	)
//
//	//b, _ := db.Exec(`select * from scan_results `)
//	//fmt.Println(b)
//
//	return err
//}
