//package main
//
//import (
//	"bytes"
//	"fmt"
//	"io"
//	"log"
//	"net"
//	"strings"
//	"time"
//)
//
//func ReadBanner(conn net.Conn) string {
//	//timeout := time.Second
//	remoteAddr := conn.RemoteAddr().(*net.TCPAddr) //这两行为调试信息
//	port := remoteAddr.Port
//	buf := make([]byte, 2048)
//	//fmt.Printf("[DEBUG] 开始探测端口 %d\n", remoteAddr.Port) // 添加这行
//
//	timeout := 3 * time.Second
//	switch port {
//	case 21:
//		timeout = 5 * time.Second // FTP
//	case 80, 443, 8080, 81:
//		timeout = 5 * time.Second // HTTP/S
//	}
//	//timeout := 1500 * time.Millisecond
//	//if port == 21 {
//	//	timeout = 3000 * time.Millisecond
//	//}
//
//	conn.SetReadDeadline(time.Now().Add(timeout))
//
//	n, err := conn.Read(buf) //1. 先读取服务端可能主动发送的Banner
//	if err != nil {
//		log.Printf("read banner failed: %v", err)
//	}
//	if n > 0 {
//		//fmt.Printf("[DEBUG] 端口 %d 主动响应: %q\n", port, string(buf[:n]))
//		return strings.TrimSpace(string(buf[:n]))
//	}
//
//	//2. 如果没有收到Banner，发送通用探测包
//	switch conn.RemoteAddr().(*net.TCPAddr).Port {
//	case 21: // FTP
//		conn.Write([]byte("USER anonymous\r\n"))
//		time.Sleep(500 * time.Millisecond)
//		n, _ = conn.Read(buf)
//	case 22: // SSH
//		conn.Write([]byte("SSH-2.0-GoScan\r\n"))
//		n, _ = conn.Read(buf)
//	case 80, 443, 8080, 888, 81: // HTTP/S
//		req := fmt.Sprintf(
//			"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Go-Scanner\r\nAccept: */*\r\nConnection: close\r\n\r\n",
//			remoteAddr.IP,
//		)
//		if _, err := conn.Write([]byte(req)); err != nil { //测试
//			log.Printf("write banner failed: %v", err)
//			return ""
//		}
//		//time.Sleep(500 * time.Millisecond)
//		//n, _ = conn.Read(buf)//原来
//		var resp bytes.Buffer //测试
//		for {
//			n, err := conn.Read(buf)
//			if err != nil {
//				if err != io.EOF {
//					log.Printf("读取 HTTP 响应失败: %v", err)
//				}
//				break
//			}
//			resp.Write(buf[:n])
//		}
//		return resp.String()
//	default: // 其他端口保持原样
//		conn.Write([]byte("\x01\x02\x03\x04\n")) //魔法数字探测包
//	}
//	//n, err = conn.Read(buf)
//	//if err != nil {
//	//	//fmt.Printf("[DEBUG] 端口 %d 读取错误: %v\n", port, err)
//	//	return ""
//	//}
//	////fmt.Printf("[DEBUG] 端口 %d 最终响应: %q\n", port, string(buf[:n]))
//	//return strings.TrimSpace(string(buf[:n]))
//	if n > 0 {
//		return strings.TrimSpace(string(buf[:n]))
//	}
//	return ""
//}
//
//func IdentifyService(banner string, port int) string { //指纹识别函数
//
//	if banner == "" {
//		switch port {
//		case 21:
//			return "ftp(无响应)"
//		case 80, 443, 8080, 888:
//			return "http(无响应)"
//		case 22:
//			return "ssh(无响应)"
//		default:
//			return "unknown"
//		}
//	}
//
//	if strings.Contains(banner, "HTTP/1.") { //检测 HTTP 响应头，即使返回 400
//		// 提取 Server 头（如 "Server: nginx"）
//		if serverHeader := ExtractHeader(banner, "Server"); serverHeader != "" {
//			return fmt.Sprintf("http | %s", serverHeader)
//		}
//		return "http" // 默认标识为 http
//	}
//
//	switch {
//	case strings.HasPrefix(banner, "SSH-"):
//		return fmt.Sprintf("ssh | %s", FirstLine(banner))
//	case strings.HasPrefix(banner, "220") && port == 21: //FTP效应码
//		return fmt.Sprintf("ftp | %s", FirstLine(banner))
//	case strings.Contains(banner, "HTTP"):
//		return fmt.Sprintf("http | %s", FirstLine(banner))
//	case bytes.HasPrefix([]byte(banner), []byte("\x16\x03")): // TLS
//		return "https(疑似)"
//	case strings.Contains(banner, "MySQL"):
//		return "mysql"
//	//case strings.Contains(banner, "<html>"):
//	//	return "http"
//	default:
//		// 端口猜测（保底逻辑）
//		switch port {
//		case 22:
//			return "ssh(疑似)"
//		case 80, 443, 8080, 888:
//			return "http(疑似)"
//		case 3306:
//			return "mysql(疑似)"
//		default:
//			return "unknown"
//		}
//	}
//}

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// 协议配置
var protocolConfig = map[int]struct {
	probe      string
	timeout    time.Duration
	identifier func(string) string
}{
	21:   {"USER anonymous\r\n", 5 * time.Second, identifyFTP},
	22:   {"SSH-2.0-GoScan\r\n", 3 * time.Second, identifySSH},
	80:   {"", 8 * time.Second, identifyHTTP},
	443:  {"", 8 * time.Second, identifyHTTP},
	3306: {"", 5 * time.Second, identifyMySQL},
	902:  {"", 3 * time.Second, identifyVMware},
	912:  {"", 3 * time.Second, identifyVMware},
}

func ReadBanner(conn net.Conn) string {
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	port := remoteAddr.Port

	// 设置连接参数
	setupConnection(conn, port)

	// 尝试读取初始banner
	if banner := tryReadBanner(conn); banner != "" {
		return banner //cleanResponse(banner)
	}

	// 协议特定探测
	if cfg, ok := protocolConfig[port]; ok {
		return probeProtocol(conn, port, cfg.probe, cfg.timeout)
	}

	// 默认探测
	return probeDefault(conn)
}

func setupConnection(conn net.Conn, port int) {
	timeout := 3 * time.Second
	if cfg, ok := protocolConfig[port]; ok {
		timeout = cfg.timeout
	}
	conn.SetReadDeadline(time.Now().Add(timeout))

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
}

func tryReadBanner(conn net.Conn) string {
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		return string(buf[:n])
	}
	return ""
}

func probeProtocol(conn net.Conn, port int, probe string, timeout time.Duration) string {
	switch port {
	case 80, 443, 8888:
		return probeHTTP(conn)
	default:
		if probe != "" {
			conn.Write([]byte(probe))
		}
		return readWithTimeout(conn, timeout)
	}
}

func probeHTTP(conn net.Conn) string {
	//req := buildHTTPRequest(conn.RemoteAddr().(*net.TCPAddr).IP.String())
	req := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (compatible; GoScanner/1.0)\r\n"+
			"Accept: */*\r\n"+
			"Connection: close\r\n\r\n",
		conn.RemoteAddr().(*net.TCPAddr).IP.String(),
	)

	conn.Write([]byte(req))

	reader := bufio.NewReader(conn)
	var resp strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
		resp.WriteString(line)
	}

	return resp.String()
}

//func buildHTTPRequest(host string) string { //并入 probeHTTP 函数
//	return fmt.Sprintf(
//		"GET / HTTP/1.1\r\n"+
//			"Host: %s\r\n"+
//			"User-Agent: Mozilla/5.0\r\n"+
//			"Connection: close\r\n\r\n",
//		host,
//	)
//}

func probeDefault(conn net.Conn) string { //万能请求包
	conn.Write([]byte("\x01\x02\x03\x04\n"))
	return readWithTimeout(conn, 1*time.Second)
}

func readWithTimeout(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	return string(buf[:n])
}

func cleanResponse(resp string) string {
	// 过滤非ASCII字符
	resp = strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 || r == '\n' || r == '\r' {
			return r
		}
		return -1
	}, resp)

	// 截断过长的响应
	if len(resp) > 200 {
		return resp[:200] + "..."
	}
	return resp
}

func IdentifyService(banner string, port int) string {
	//fmt.Printf("\n端口: %d\n[原始Banner开始]==========\n%s\n[原始Banner结束]==========\n", port, banner)

	//banner = cleanResponse(banner) //这是基于简单的端口和 banner 信息指纹识别
	//
	//if cfg, ok := protocolConfig[port]; ok {
	//	return cfg.identifier(banner)
	//}

	db, err := InitDB() //这里是通过连接数据库，和指纹库里的数据进行匹配
	if err != nil {
		log.Printf("数据库连接失败: %v", err)
		return "unknown"
	}
	defer db.Close()

	if strings.Contains(banner, "HTTP/") {
		bannerNew := ExtractHeader(banner, "Server")
		if bannerNew != "" {
			if service := MatchFingerprint(db, bannerNew); service != "" {
				return service
			} else {
				fmt.Println("no")
			}
		}
	}
	// 1. 尝试指纹匹配
	if service := MatchFingerprint(db, banner); service != "" {
		return service
	} else {
		fmt.Println("no")
	}

	switch { //保底逻辑
	case strings.Contains(banner, "HTTP/"):
		return identifyHTTP(banner)
	case port == 80 || port == 443 || port == 8080 || port == 8888:
		return "http"
	default:
		return "unknown"
	}
}

// 协议识别函数
func identifyHTTP(banner string) string {
	// 优先通过指纹库匹配
	if server := ExtractHeader(banner, "Server"); server != "" {
		// 返回标准化服务名（小写、去除版本号）
		switch {
		case strings.Contains(server, "nginx"):
			return "nginx"
		case strings.Contains(server, "Apache"):
			return "apache"
		case strings.Contains(server, "Microsoft-IIS"):
			return "iis"
		case strings.Contains(server, "lighttpd"):
			return "lighttpd"
		case strings.Contains(server, "Caddy"):
			return "caddy"
		}
	}

	// 次之通过特征匹配
	if strings.Contains(banner, "nginx") {
		return "nginx"
	}
	if strings.Contains(banner, "Apache") {
		return "apache"
	}

	// 最后返回通用标识
	return "http-unknown"
}

//	func identifyFTP(banner string) string {
//		return fmt.Sprintf("ftp | %s", FirstLine(banner))
//	}
func identifyFTP(banner string) string { //因为原来的在banner库中识别不到，所以换成通用的ftp
	if strings.Contains(banner, "Pure-FTPd") {
		return "pure-ftpd" // 精确匹配PureFTPd
	}
	return "ftp" // 通用FTP服务
}

//	func identifySSH(banner string) string {
//		return fmt.Sprintf("ssh | %s", FirstLine(banner))
//	}
func identifySSH(banner string) string { //因为原来的在banner库中识别不到，所以换成通用的ssh
	if strings.Contains(banner, "OpenSSH") {
		return "openssh" // 标准化为openssh而非带版本信息
	}
	return "ssh" // 通用SSH服务
}

func identifyMySQL(banner string) string {
	return "mysql"
}

func identifyVMware(banner string) string {
	return "vmware-auth"
}
