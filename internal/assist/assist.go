package assist

import (
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"log"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golandproject/yscan/internal/model"
)

func ValidateInput(network string, address string) error {
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
	default:
		return fmt.Errorf("invalid network type: %s", network)
	}
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address: %s\nThis is error: %v", address, err)
	}
	return nil
}

func IsHostAlive(ip string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "2", "-w", "2000", ip)
	default:
		cmd = exec.Command("ping", "-c", "2", "-W", "2", ip)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("ping %s failed: %v \noutput: %s", ip, err, string(output))
		return false
	}
	return true
}

func IsHostAliveTCP(ip string) bool {
	ports := []int{80, 22, 443}
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 3*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func IsHostAlive_TCP(ip string) bool {
	return IsHostAliveTCP(ip)
}

func getTimeout(port int) time.Duration {
	switch port {
	case 21, 22, 80, 443:
		return 500 * time.Millisecond
	case 3306, 3389:
		return 1 * time.Second
	default:
		return 2 * time.Second
	}
}

func FirstLine(s string) string {
	if idx := strings.Index(s, "\r\n"); idx > 0 {
		return s[:idx]
	}
	return s
}

func ExtractHeader(banner, headerName string) string {
	re := regexp.MustCompile(fmt.Sprintf(`(?i)%s:\s*(.*?)\r\n`, headerName))
	match := re.FindStringSubmatch(banner)
	if len(match) > 1 {
		return strings.TrimSpace(match[1])
	}
	return ""
}

func ErrType(scan model.ScanResult) string {
	if netErr, ok := scan.Err.(net.Error); ok && netErr.Timeout() {
		return "Timeout"
	}
	if opErr, ok := scan.Err.(*net.OpError); ok {
		if opErr.Op == "dial" {
			return "refused"
		}
		return "op_error"
	}
	return "other"
}

// GetWebsiteTitle 获取网站标题
func GetWebsiteTitle(ip string, port int) string {
	url := fmt.Sprintf("http://%s:%d", ip, port)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return ""
	}
	return doc.Find("title").Text()
}
