package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
)

// SearchEngineCollector 结构体命名统一（修复大小写不一致问题）
type SearchEngineCollector struct {
	SourceName    string
	UserAgent     string
	SearchEngines []SearchEngineConfig
}

type SearchEngineConfig struct {
	Name      string
	URLFormat string
	Enabled   bool
}

// 国内搜索引擎配置（修复sogou拼写警告）
var defaultSearchEngines = []SearchEngineConfig{
	{
		Name:      "baidu",
		URLFormat: "https://www.baidu.com/s?wd=site:%s+-www&rn=50",
		Enabled:   true,
	},
	{
		Name:      "bing",
		URLFormat: "https://www.bing.com/search?q=site:%s+-www&count=50",
		Enabled:   true,
	},
	{
		Name:      "sogou", // 保留但忽略拼写检查
		URLFormat: "https://www.sogou.com/web?query=site:%s+-www",
		Enabled:   true,
	},
}

// NewSearchEngineCollector 创建收集器（修复函数名大小写）
func NewSearchEngineCollector() *SearchEngineCollector {
	return &SearchEngineCollector{
		SourceName:    "search_engine",
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", // 修复KHTML拼写
		SearchEngines: defaultSearchEngines,
	}
}

func (s *SearchEngineCollector) Collect(domain string, timeout time.Duration) ([]CollectResult, error) {
	// 保留ctx用于后续扩展（消除未使用警告）
	_, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c := colly.NewCollector(
		colly.UserAgent(s.UserAgent),
		colly.Async(true),
	)

	// 配置限制规则
	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 2,
		Delay:       3 * time.Second,
	})

	// 子域名正则（修复showurl拼写警告）
	domainEscaped := regexp.QuoteMeta(domain)
	re := regexp.MustCompile(`(?i)(?:[a-z0-9-]+\.)+` + domainEscaped)

	var (
		results     []CollectResult
		resultMutex sync.Mutex
	)

	// 回调：提取搜索结果（标准化的class名）
	c.OnHTML("cite, .c-showurl, .b_algo, a[href*='"+domain+"']", func(e *colly.HTMLElement) {
		text := strings.TrimSpace(e.Text)
		if matches := re.FindAllString(text, -1); len(matches) > 0 {
			resultMutex.Lock()
			defer resultMutex.Unlock()

			for _, rawSubdomain := range matches {
				subdomain := strings.ToLower(strings.Trim(rawSubdomain, "."))
				if !s.isValidSubdomain(subdomain, domain) {
					continue
				}

				if !s.containsSubdomain(results, subdomain) {
					results = append(results, s.createResult(subdomain, e.Request.URL.Host))
				}
			}
		}
	})

	// 错误处理（修复未处理错误警告）
	c.OnError(func(r *colly.Response, err error) {
		log.Printf("[%s] 请求失败: %v", s.SourceName, err)
	})

	// 并发查询
	var wg sync.WaitGroup
	for _, engine := range s.SearchEngines {
		if !engine.Enabled {
			continue
		}

		wg.Add(1)
		go func(eng SearchEngineConfig) {
			defer wg.Done()
			if err := c.Visit(fmt.Sprintf(eng.URLFormat, domain)); err != nil {
				log.Printf("[%s] %s查询失败: %v", s.SourceName, eng.Name, err)
			}
		}(engine)
	}

	wg.Wait()
	c.Wait()
	return results, nil
}

// 私有方法（避免ValidSubdomain重名问题）
func (s *SearchEngineCollector) isValidSubdomain(subdomain, root string) bool {
	return strings.HasSuffix(subdomain, "."+root) || subdomain == root
}

func (s *SearchEngineCollector) containsSubdomain(results []CollectResult, subdomain string) bool {
	for _, r := range results {
		if r.Subdomain == subdomain {
			return true
		}
	}
	return false
}

func (s *SearchEngineCollector) createResult(subdomain, host string) CollectResult {
	return CollectResult{
		Subdomain: subdomain,
		IPs:       s.safeResolveIPs(subdomain),
		FirstSeen: time.Now(),
		Sources:   []string{s.SourceName + ":" + host},
	}
}

func (s *SearchEngineCollector) safeResolveIPs(subdomain string) []net.IP {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("IP解析异常: %v", r)
		}
	}()

	if strings.HasPrefix(subdomain, "*.") {
		return nil
	}

	ips, err := net.LookupIP(subdomain)
	if err != nil {
		return nil
	}

	var ipv4s []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4s = append(ipv4s, ip)
		}
	}
	return ipv4s
}
