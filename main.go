package main

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"strings"

	//"github.com/go-ping/ping"
	"log"
	"net"
	"time"
)

type scanner struct {
	network string
	ip      string
	port    int
	conn    net.Conn
}

type scanResult struct {
	address string
	err     error
	errtype string
	open    bool
	service string //指纹识别部分
	banner  string
}

func printProgress(current, total int, start time.Time) { //进度显示打印
	percent := float64(current) / float64(total) * 100
	elapsed := time.Since(start).Round(time.Second)

	// \r 让光标回到行首，实现原地刷新
	fmt.Printf("\rScanning: %d/%d (%.1f%%) | Elapsed: %v",
		current, total, percent, elapsed)
}

func printOpenPorts(results []scanResult) { //扫描结果打印
	fmt.Println("\n=== 开放端口详情 ===")
	fmt.Printf("%-20s\t%-25s\t%-30s\n", "地址", "服务类型", "Banner信息")
	for _, r := range results {
		banner := r.banner

		if banner == "" {
			banner = "[无Banner响应]"
		} else if len(banner) > 50 {
			banner = banner[:50] + "..."
		}

		fmt.Printf("%-20s\t%-25s\t%-30s\n",
			r.address,
			r.service,
			banner)
	}
	fmt.Println("\n=== ---------- ===")
}

func collectSubdomains(db *sql.DB, scan scanner) { //收集子域名函数
	var domain string

	fmt.Print("please enter your domain: ")
	fmt.Scan(&domain)

	results, err := CollectSubdomains_crtsh(domain, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}

	uniqueIPs := make(map[string]bool) //用于取独特的一个 IP，没有重复
	var ipsToScan []string

	for _, res := range results {
		fmt.Printf("[%s] %s (IPs: %v)\n", //打印收集到的子域名结果
			res.FirstSeen.Format("2006-01-02"),
			res.Subdomain,
			res.IPs)

		domainID, err := SaveDomainInfo(db, domain, res.Subdomain, strings.HasPrefix(res.Subdomain, "*."),
			"", "crt.sh")
		if err != nil {
			log.Printf("保存子域名失败 %s: %v", res.Subdomain, err)
			continue
		}

		for _, ip := range res.IPs {
			ipStr := ip.String()
			if !uniqueIPs[ipStr] && ip.To4() != nil {
				uniqueIPs[ipStr] = true
				ipsToScan = append(ipsToScan, ipStr)

				if err := SaveDomainIP(db, domainID, ipStr, nil); err != nil {
					log.Printf("保存IP关联失败 %s: %v", ipStr, err)
				}
			}
		}
	}

	var answer string
	fmt.Print("Subdomain collecting is done. Do the domains need to scan?(y/N): ")
	fmt.Scan(&answer)

	if answer == "y" {
		for _, scan.ip = range ipsToScan {
			domainScan(scan, db)
		}
	} else if answer == "n" {
		fmt.Print("The task is over.")
	}
}

func domainScan(scan scanner, db *sql.DB) {
	fmt.Printf("\n=== 开始域名扫描 %s ===\n", scan.ip)

	if IsHostAlive(scan.ip) {
		//Run(scan.ip, scan.network)				   //测试用
		openPorts := Run(scan.ip, scan.network) //真正利用，存储数据库
		// 3. 保存结果(存储逻辑)
		if err := SaveDomainScanResult(db, scan.ip, openPorts); err != nil {
			log.Printf("保存扫描结果失败: %v", err)
		}
	} else {
		fmt.Println("Can't ping")
		if IsHostAlive_TCP(scan.ip) {
			//Run(scan.ip, scan.network) 				   //测试用
			openPorts := Run(scan.ip, scan.network) //真正利用，存储数据库
			// 3. 保存结果(存储逻辑)
			if err := SaveDomainScanResult(db, scan.ip, openPorts); err != nil {
				log.Printf("保存扫描结果失败: %v", err)
			}
		} else {
			log.Print("没有进入TCP连接")
			fmt.Printf("%s is not alive\n", scan.ip)
		}
	}
}

func portScan(scan scanner, db *sql.DB) { //这是把之前的 端口扫描 和 主机检测 利用整合到一个函数里面，方便调用

	if IsHostAlive(scan.ip) {
		//Run(scan.ip, scan.network) //这一行是用于测试，结果不进入 sql 数据库
		openPorts := Run(scan.ip, scan.network) //这一段是真正利用，结果进入 sql 数据库
		for _, result := range openPorts {
			if err := SaveResult(db, result); err != nil {
				log.Printf("存储失败 %s: %v", result.address, err)
			} else {
				log.Printf("成功储存 %s", result.address)
			}
		}
	} else {
		fmt.Println("Can't ping")
		if IsHostAlive_TCP(scan.ip) {
			//Run(scan.ip, scan.network) //这一行是用于测试，结果不进入 sql 数据库
			openPorts := Run(scan.ip, scan.network) //这一段是真正利用，结果进入 sql 数据库
			for _, result := range openPorts {
				if err := SaveResult(db, result); err != nil {
					log.Printf("存储失败 %s: %v", result.address, err)
				} else {
					log.Printf("成功储存 %s", result.address)
				}
			}
		} else {
			log.Print("没有进入TCP连接")
			fmt.Printf("%s is not alive\n", scan.ip)
		}
	}
}

func main() {
	db, err := InitDB() //连接数据库
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var scan scanner
	scan.network = "tcp"

	var command string
	fmt.Print("please enter a command(domain/scan): ")
	fmt.Scan(&command)

	if command == "scan" {
		fmt.Print("Please enter your ip:")
		fmt.Scan(&scan.ip)

		portScan(scan, db) //进行扫描
	} else if command == "domain" {
		collectSubdomains(db, scan)
	} else {
		fmt.Println("please enter a true command.")
	}

	//var timeout time.Duration
	//var count int     //这两个是 go-ping 那个主机检测版本要用的变量

	//fmt.Print("Please enter your network:")
	//fmt.Scan(&scan.network)

	//fmt.Print("IsHostAlive count and time:")
	//fmt.Scan(&count, &timeout)

}

//func ishostAlive(ip string, count int, timeout time.Duration) bool { //检验主机是否存活，用的是 go-ping 库
//	pinger, err := ping.NewPinger(ip)
//	if err != nil {
//		log.Printf("Error creating pinger: %v", err)
//		return false
//	}
//
//	pinger.SetPrivileged(true)
//	pinger.Count = count
//	pinger.Timeout = timeout
//
//	if err := pinger.Run(); err != nil {
//		log.Printf("Ping failed: %v", err)
//		return false
//	}
//	stats := pinger.Statistics()
//	return stats.PacketsRecv > 0
//}

//func probeProtocol(conn net.Conn, port int) string {
//	switch port {
//	case 22: // SSH
//		conn.Write([]byte("SSH-2.0-GoScanner\r\n"))
//		return readBanner(conn)
//	case 80: // HTTP
//		conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
//		return readBanner(conn)
//	case 443:
//		conn.Write([]byte("\\x16\\x03\\x01\\x00\\x75"))
//		return readBanner(conn)
//	}
//	return ""
//}
