package identify

import (
	"net"
	"strings"
	"time"

	"golandproject/yscan/internal/assist"
)

const MaxBannerBytes = 16 << 10

// 协议配置
var protocolConfig = map[int]struct {
	probe      string
	timeout    time.Duration
	identifier func(string) string
}{
	21:   {"", 5 * time.Second, identifyFTP},
	22:   {"", 3 * time.Second, identifySSH},
	80:   {"", 8 * time.Second, identifyHTTP},
	443:  {"", 8 * time.Second, identifyHTTP},
	3306: {"", 5 * time.Second, identifyMySQL},
	902:  {"", 3 * time.Second, identifyVMware},
	912:  {"", 3 * time.Second, identifyVMware},
}

func ReadBanner(conn net.Conn) string {
	banner, _ := ReadBannerEvidence(conn)
	return banner
}

// ReadBannerEvidence keeps the bounded bytes even when the peer closes the
// connection or the read deadline fires in the same read that returned data.
func ReadBannerEvidence(conn net.Conn) (string, bool) {
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr) //conn.RemoteAddr()返回一个 net.Addr 接口，包含对端（客户端）的网络地址信息（IP、port、Zone）
	port := remoteAddr.Port

	// 设置连接参数
	setupConnection(conn, port)

	// 尝试读取初始banner
	if banner, truncated := tryReadBanner(conn); banner != "" {
		return banner, truncated //cleanResponse(banner)
	}

	// 协议特定探测
	if cfg, ok := protocolConfig[port]; ok {
		return probeProtocol(conn, port, cfg.probe, cfg.timeout)
	}

	// Unknown services retain an empty banner. Web fallback and any future
	// protocol probe are executed only by the run-scoped, read-only collector.
	return "", false
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

func tryReadBanner(conn net.Conn) (string, bool) {
	data := make([]byte, 0, MaxBannerBytes)
	buffer := make([]byte, MaxBannerBytes+1)
	for len(data) <= MaxBannerBytes {
		n, err := conn.Read(buffer[:min(len(buffer), MaxBannerBytes+1-len(data))])
		if n > 0 {
			data = append(data, buffer[:n]...)
			if len(data) > MaxBannerBytes {
				return string(data[:MaxBannerBytes]), true
			}
			// Once bytes arrive, only a short inter-read window is needed to
			// collect a split response without holding the entire scan worker.
			_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		}
		if err != nil || n == 0 {
			break
		}
	}
	return string(data), false
}

func probeProtocol(conn net.Conn, port int, probe string, timeout time.Duration) (string, bool) {
	if probe != "" {
		_, _ = conn.Write([]byte(probe))
	}
	return readWithTimeout(conn, timeout)
}

func readWithTimeout(conn net.Conn, timeout time.Duration) (string, bool) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	return tryReadBanner(conn)
}

func IdentifyService(banner string, port int) string {
	switch {
	case strings.Contains(banner, "HTTP/"):
		return identifyHTTP(banner)
	case strings.HasPrefix(strings.TrimSpace(banner), "SSH-"):
		return identifySSH(banner)
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
	case port == 443:
		return "https"
	case port == 80:
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
