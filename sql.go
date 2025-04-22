package main

import (
	"database/sql"
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
func SaveResult(db *sql.DB, result scanResult) error {
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

func MatchFingerprint(db *sql.DB, banner string) string {
	var serviceName string
	db.QueryRow(`
        SELECT service_name FROM service_fingerprints 
        WHERE ? LIKE CONCAT('%', banner_pattern, '%')
        ORDER BY LENGTH(banner_pattern) DESC
        LIMIT 1`, banner).Scan(&serviceName)
	return serviceName
}

//package main
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
