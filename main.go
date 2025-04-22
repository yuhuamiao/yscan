package main

import (
	"fmt"
	_ "github.com/go-sql-driver/mysql"
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

func printProgress(current, total int, start time.Time) {
	percent := float64(current) / float64(total) * 100
	elapsed := time.Since(start).Round(time.Second)

	// \r 让光标回到行首，实现原地刷新
	fmt.Printf("\rScanning: %d/%d (%.1f%%) | Elapsed: %v",
		current, total, percent, elapsed)
}

func printOpenPorts(results []scanResult) {
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
}

func main() {
	var scan scanner
	//var timeout time.Duration
	//var count int     //这两个是 go-ping 那个主机检测版本要用的变量

	db, err := InitDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	//fmt.Print("Please enter your network:")
	//fmt.Scan(&scan.network)
	scan.network = "tcp"
	fmt.Print("Please enter your ip:")
	fmt.Scan(&scan.ip)
	//fmt.Print("IsHostAlive count and time:")
	//fmt.Scan(&count, &timeout)

	if IsHostAlive(scan.ip) {
		Run(scan.ip, scan.network)
		//openPorts := Run(scan.ip, scan.network)
		//for _, result := range openPorts {
		//	if err := SaveResult(db, result); err != nil {
		//		log.Printf("存储失败 %s: %v", result.address, err)
		//	} else {
		//		log.Printf("成功储存 %s", result.address)
		//	}
		//}
	} else {
		fmt.Println("Can't ping")
		if IsHostAlive_TCP(scan.ip) {
			Run(scan.ip, scan.network)
			//openPorts := Run(scan.ip, scan.network)
			//for _, result := range openPorts {
			//	if err := SaveResult(db, result); err != nil {
			//		log.Printf("存储失败 %s: %v", result.address, err)
			//	} else {
			//		log.Printf("成功储存 %s", result.address)
			//	}
			//}
		} else {
			fmt.Printf("%s is not alive\n", scan.ip)
		}
	}
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
