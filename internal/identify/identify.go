package identify

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"golandproject/yscan/internal/assist"
	"golandproject/yscan/internal/storage"
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
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr) //conn.RemoteAddr()返回一个 net.Addr 接口，包含对端（客户端）的网络地址信息（IP、port、Zone）
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

func IdentifyService(banner string, port int) string {
	fmt.Printf("\n端口: %d\n[原始Banner开始]==========\n%s\n[原始Banner结束]==========\n", port, banner)

	//banner = cleanResponse(banner) //这是基于简单的端口和 banner 信息指纹识别
	//
	//if cfg, ok := protocolConfig[port]; ok {
	//	return cfg.identifier(banner)
	//}

	db, err := storage.InitDB() //这里是通过连接数据库，和指纹库里的数据进行匹配
	if err != nil {
		log.Printf("数据库连接失败: %v", err)
		return "unknown"
	}
	defer db.Close()

	if strings.Contains(banner, "HTTP/") {
		bannerNew := assist.ExtractHeader(banner, "Server")
		if bannerNew != "" {
			if service := storage.MatchFingerprint(db, bannerNew); service != "" {
				return service
			}
			fmt.Println("no")
		}
	}

	// 1. 尝试指纹匹配
	if service := storage.MatchFingerprint(db, banner); service != "" {
		return service
	}
	fmt.Println("no")

	switch { //保底逻辑
	case strings.Contains(banner, "HTTP/"):
		return identifyHTTP(banner)
	case port == 80 || port == 443:
		return "http"
	case banner == "":
		return "None_unknown"
	default:
		return "unknown"
	}
}

// 协议识别函数
func identifyHTTP(banner string) string {
	// 优先通过指纹库匹配
	if server := assist.ExtractHeader(banner, "Server"); server != "" {
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

func identifyFTP(banner string) string {
	if strings.Contains(banner, "Pure-FTPd") {
		return "pure-ftpd" // 精确匹配PureFTPd
	}
	return "ftp" // 通用FTP服务
}

func identifySSH(banner string) string {
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
