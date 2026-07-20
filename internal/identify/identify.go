package identify

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"golandproject/yscan/internal/assist"
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
	switch {
	case strings.Contains(banner, "HTTP/"):
		return identifyHTTP(banner)
	case port == 21:
		return identifyFTP(banner)
	case port == 22:
		return identifySSH(banner)
	case port == 3306:
		return identifyMySQL(banner)
	case port == 902 || port == 912:
		return identifyVMware(banner)
	case port == 3389:
		return "rdp"
	case port == 5432:
		return "postgresql"
	case port == 6379:
		return "redis"
	case port == 27017:
		return "mongodb"
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
	if server := assist.ExtractHeader(banner, "Server"); server != "" {
		server = strings.ToLower(server)
		switch {
		case strings.Contains(server, "nginx"):
			return "nginx"
		case strings.Contains(server, "apache"):
			return "apache"
		case strings.Contains(server, "microsoft-iis"):
			return "iis"
		case strings.Contains(server, "lighttpd"):
			return "lighttpd"
		case strings.Contains(server, "caddy"):
			return "caddy"
		case strings.Contains(server, "jetty"):
			return "jetty"
		}
	}

	lower := strings.ToLower(banner)
	if strings.Contains(lower, "nginx") {
		return "nginx"
	}
	if strings.Contains(lower, "apache") {
		return "apache"
	}

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
