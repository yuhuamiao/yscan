package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type CertRecord struct { //证书记录结构
	ID          uint64   `json:"id"`              //证书在 crt.sh 数据库中的唯一标识符
	LoggedAt    string   `json:"entry_timestamp"` //证书被记录到透明日志的时间（格式：2006-01-02T15:04:05）
	NotBefore   string   `json:"not_before"`      //证书生效的开始日期
	NotAfter    string   `json:"not_after"`       //证书过期时间
	CommonName  string   `json:"common_name"`     //证书的主域名（CN字段），可能是通配符如 *.example.com
	NameValue   string   `json:"name_value"`      //含所有主题备用名称(SANs)，多个域名用换行符(\n)分隔
	MatchingIPs []net.IP //非API字段，程序自行填充的匹配IP列表
	IsWildcard  bool     //非API字段，标记是否为通配符证书（根据CommonName或NameValue）
}

type CollectResult struct {
	Subdomain string
	IPs       []net.IP
	FirstSeen time.Time
	Sources   []string
}

// CollectSubdomains_crtsh 主收集函数
func CollectSubdomains_crtsh(domain string, timeout time.Duration) ([]CollectResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 使用更稳定的API端点
	apiURL := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)

	// 调试输出
	log.Printf("正在查询: %s", apiURL)

	records, err := fetchCertRecords(ctx, apiURL)
	if err != nil {
		return nil, fmt.Errorf("fetchCertRecords失败: %w", err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("未找到任何证书记录")
	}

	// 处理结果
	var results []CollectResult
	for _, rec := range records {
		select {
		case <-ctx.Done():
			return results, nil
		default:
			res := processRecord(rec, domain)
			if res.Subdomain != "" {
				results = append(results, res)
			}
		}
	}

	return results, nil
}

// fetchCertRecords 获取证书记录
func fetchCertRecords(ctx context.Context, apiURL string) ([]CertRecord, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; MyScanner/1.0)")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查状态码
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("API返回错误: %s\n响应: %s", resp.Status, string(body))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	// 调试输出
	log.Printf("API响应: %s", string(body[:min(200, len(body))]))

	var records []CertRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("JSON解析失败: %w\n响应: %s", err, string(body[:200]))
	}

	return records, nil
}

// processRecord 处理单条记录
func processRecord(rec CertRecord, baseDomain string) CollectResult {
	rec.IsWildcard = strings.HasPrefix(rec.CommonName, "*.") ||
		strings.Contains(rec.NameValue, "*.")

	names := append(strings.Split(rec.NameValue, "\n"), rec.CommonName)
	var validSubdomains []string

	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" && isValidSubdomain(name, baseDomain) {
			validSubdomains = append(validSubdomains, name)
		}
	}

	if len(validSubdomains) == 0 {
		return CollectResult{}
	}

	// 只处理第一个有效子域名
	subdomain := validSubdomains[0]
	var ips []net.IP
	if !rec.IsWildcard {
		if resolvedIPs, err := net.LookupIP(subdomain); err == nil {
			ips = resolvedIPs
		}
	}

	var firstSeen time.Time
	if rec.LoggedAt != "" {
		firstSeen, _ = time.Parse("2006-01-02T15:04:05", rec.LoggedAt)
	}

	return CollectResult{
		Subdomain: subdomain,
		IPs:       ips,
		FirstSeen: firstSeen,
		Sources:   []string{"crt.sh"},
	}
}

// isValidSubdomain 验证子域名
func isValidSubdomain(name, baseDomain string) bool {
	name = strings.TrimSuffix(name, ".")
	baseDomain = strings.TrimSuffix(baseDomain, ".")
	return name == baseDomain || strings.HasSuffix(name, "."+baseDomain)
}
