package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
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

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("端口转换失败: %v", err)
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

func MatchFingerprint(db *sql.DB, banner string) string { //和 banner 库进行匹配
	var serviceName string
	db.QueryRow(`
        SELECT service_name FROM service_fingerprints 
        WHERE ? LIKE CONCAT('%', banner_pattern, '%')
        ORDER BY LENGTH(banner_pattern) DESC
        LIMIT 1`, banner).Scan(&serviceName)
	return serviceName
}

// SaveDomainScanResult 保存域名扫描结果
func SaveDomainScanResult(db *sql.DB, ip string, openPorts []scanResult) error {
	// 提取端口号列表
	var ports []int
	var title string

	for _, result := range openPorts {
		_, portStr, _ := net.SplitHostPort(result.address)
		port, _ := strconv.Atoi(portStr)
		ports = append(ports, port)

		// 从第一个HTTP服务获取标题
		if title == "" && strings.HasPrefix(result.service, "http") {
			title = extractTitleFromBanner(result.banner)
		}
	}

	// 更新domain_info中的标题(如果有)
	if title != "" {
		_, err := db.Exec(`
            UPDATE domain_info d
            JOIN domain_ips di ON d.id = di.domain_id
            SET d.title = ?, d.last_scan = NOW()
            WHERE di.ip = ?`,
			title, ip)
		if err != nil {
			return fmt.Errorf("更新标题失败: %v", err)
		}
	}

	// 更新domain_ips中的端口信息
	_, err := db.Exec(`
        UPDATE domain_ips 
        SET ports = ?
        WHERE ip = ?`,
		toJSON(ports),
		ip)
	if err != nil {
		return fmt.Errorf("更新端口信息失败: %v", err)
	}

	return nil
}

// 辅助函数
func extractTitleFromBanner(banner string) string {
	if !strings.Contains(banner, "<title>") {
		return ""
	}

	start := strings.Index(banner, "<title>")
	end := strings.Index(banner, "</title>")
	if start == -1 || end == -1 || start >= end {
		return ""
	}

	return strings.TrimSpace(banner[start+7 : end])
}

func toJSON(data interface{}) string {
	b, _ := json.Marshal(data)
	return string(b)
}

// SaveDomainInfo 保存子域名信息
func SaveDomainInfo(db *sql.DB, mainDomain, subdomain string, isWildcard bool, title string, source string) (int64, error) {
	res, err := db.Exec(`
        INSERT INTO domain_info 
        (domain, subdomain, is_wildcard, title, first_seen, source)
        VALUES (?, ?, ?, ?, NOW(), ?)
        ON DUPLICATE KEY UPDATE
            title = COALESCE(VALUES(title), title),
            last_scan = CURRENT_TIMESTAMP`,
		mainDomain,
		subdomain,
		isWildcard,
		title,
		source)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SaveDomainIP 保存域名解析IP
func SaveDomainIP(db *sql.DB, domainID int64, ip string, ports []int) error {
	portsJSON, _ := json.Marshal(ports)
	_, err := db.Exec(`
        INSERT INTO domain_ips 
        (domain_id, ip, ports)
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE
            ports = VALUES(ports)`,
		domainID,
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
