package main

import (
	"context"
	"fmt"
	"html"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"
	pw "github.com/playwright-community/playwright-go"
)

type SearchEngineCollector struct {
	SourceName    string
	UserAgent     string
	SearchEngines []SearchEngineConfig
	UsePlaywright bool   // 新增：是否启用 Playwright
	Proxy         string // 新增：可选代理，如 "http://user:pass@host:port"
	Headless      bool   // 新增：Playwright 是否无头
	BrowserType   string // 新增：chromium|firefox|webkit
}

type SearchEngineConfig struct {
	Name      string
	URLFormat string
	Enabled   bool
}

// 默认依然用 Bing（Colly 路径）；Playwright 走 Brave 搜索，不依赖此配置
var defaultSearchEngines = []SearchEngineConfig{
	{
		Name:      "bing",
		URLFormat: "https://www.bing.com/search?q=site:*.%s&count=50",
		Enabled:   true,
	},
	{
		Name:      "baidu",
		URLFormat: "https://www.baidu.com/s?wd=site:*.%s&rn=50",
		Enabled:   false,
	},
}

func NewSearchEngineCollector() *SearchEngineCollector {
	return &SearchEngineCollector{
		SourceName:    "search_engine",
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
		SearchEngines: defaultSearchEngines,
		UsePlaywright: true, // 需要时打开
		Proxy:         "",   // 如无代理则留空
		Headless:      true,
		BrowserType:   "chromium",
	}
}

func (s *SearchEngineCollector) Collect(domain string, timeout time.Duration) ([]CollectResult, error) {
	// 若启用 Playwright，优先走 Playwright；失败再降级 Colly
	if s.UsePlaywright {
		if subs, err := s.collectWithPlaywright(domain, timeout); err == nil && len(subs) > 0 {
			return subs, nil
		} else if err != nil {
			log.Printf("[playwright] fallback to colly, err=%v", err)
		}
	}
	return s.collectWithColly(domain, timeout)
}

// ============ Playwright Brave 搜索 ============

func (s *SearchEngineCollector) collectWithPlaywright(domain string, timeout time.Duration) ([]CollectResult, error) {
	throttle(1200 * time.Millisecond) // 频率限制

	if err := pw.Install(); err != nil {
		return nil, err
	}

	launchOpts := pw.BrowserTypeLaunchOptions{
		Headless: pw.Bool(s.Headless),
		Args:     []string{"--disable-blink-features=AutomationControlled"},
	}
	if s.Proxy != "" {
		launchOpts.Proxy = &pw.Proxy{Server: s.Proxy}
	}

	pwInst, err := pw.Run()
	if err != nil {
		return nil, err
	}
	defer pwInst.Stop()

	var browser pw.Browser
	switch strings.ToLower(s.BrowserType) {
	case "firefox":
		browser, err = pwInst.Firefox.Launch(launchOpts)
	case "webkit":
		browser, err = pwInst.WebKit.Launch(launchOpts)
	default:
		browser, err = pwInst.Chromium.Launch(launchOpts)
	}
	if err != nil {
		return nil, err
	}
	defer browser.Close()

	ctx, err := browser.NewContext(pw.BrowserNewContextOptions{
		UserAgent: pw.String("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"),
	})
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	page, err := ctx.NewPage()
	if err != nil {
		return nil, err
	}
	page.SetDefaultTimeout(float64(timeout.Milliseconds()))

	url := "https://search.brave.com/search?q=site:" + domain + "&source=web"
	_, err = page.Goto(url, pw.PageGotoOptions{
		WaitUntil: pw.WaitUntilStateDomcontentloaded,
		Timeout:   pw.Float(float64(timeout.Milliseconds())),
	})
	if err != nil {
		return nil, err
	}

	page.WaitForSelector("body", pw.PageWaitForSelectorOptions{Timeout: pw.Float(10_000)})
	page.WaitForSelector("a", pw.PageWaitForSelectorOptions{Timeout: pw.Float(10_000)})
	time.Sleep(2 * time.Second)

	htmlContent, err := page.Content()
	if err != nil {
		return nil, err
	}
	// 可选：调试落盘
	// _ = os.WriteFile("brave_debug.html", []byte(htmlContent), 0644)

	re := regexp.MustCompile(`(?i)(?:[a-z0-9-]+\.)+` + regexp.QuoteMeta(domain))
	matches := re.FindAllString(strings.ToLower(htmlContent), -1)
	uniq := make(map[string]CollectResult)
	for _, m := range matches {
		sub := strings.Trim(strings.ToLower(m), ".")
		if !s.isValidSubdomain(sub, domain) {
			continue
		}
		if _, ok := uniq[sub]; ok {
			continue
		}
		uniq[sub] = s.createResult(sub, "playwright:brave")
	}

	var results []CollectResult
	for _, r := range uniq {
		results = append(results, r)
	}
	return results, nil
}

// 简单频率控制
var (
	rateLock sync.Mutex
	lastReq  time.Time
)

func throttle(minGap time.Duration) {
	rateLock.Lock()
	defer rateLock.Unlock()
	now := time.Now()
	if delta := now.Sub(lastReq); delta < minGap {
		time.Sleep(minGap - delta)
	}
	lastReq = time.Now()
}

// ============ Colly 路径（原有逻辑，稍简化） ============

func (s *SearchEngineCollector) collectWithColly(domain string, timeout time.Duration) ([]CollectResult, error) {
	_, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c := colly.NewCollector(
		colly.UserAgent(s.UserAgent),
		colly.Async(false),
		colly.AllowURLRevisit(),
	)
	if s.Proxy != "" {
		_ = c.SetProxy(s.Proxy)
	}

	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: 1,
		Delay:       3 * time.Second,
		RandomDelay: 2 * time.Second,
	})

	domainEscaped := regexp.QuoteMeta(domain)
	re := regexp.MustCompile(`(?i)(?:[a-z0-9-]+\.)+` + domainEscaped)

	var (
		results     []CollectResult
		resultMutex sync.Mutex
	)

	c.OnResponse(func(r *colly.Response) {
		body := html.UnescapeString(string(r.Body))
		matches := re.FindAllString(body, -1)
		if len(matches) == 0 {
			return
		}
		resultMutex.Lock()
		defer resultMutex.Unlock()
		for _, raw := range matches {
			sub := strings.ToLower(strings.Trim(raw, "."))
			if !s.isValidSubdomain(sub, domain) {
				continue
			}
			if !s.containsSubdomain(results, sub) {
				results = append(results, s.createResult(sub, "colly:body"))
			}
		}
	})

	// Bing 结果块
	c.OnHTML("ol#b_results li.b_algo a", func(e *colly.HTMLElement) {
		text := strings.TrimSpace(e.Text + " " + e.Attr("href"))
		extractAndAppend(text, re, domain, &results, &resultMutex, s, "colly:bing")
	})
	// 兜底：所有包含域名的链接
	c.OnHTML("a[href*='"+domain+"']", func(e *colly.HTMLElement) {
		text := strings.TrimSpace(e.Text + " " + e.Attr("href"))
		extractAndAppend(text, re, domain, &results, &resultMutex, s, "colly:any")
	})

	c.OnError(func(r *colly.Response, err error) {
		log.Printf("[%s] %s 请求失败: %v (status=%d)", s.SourceName, r.Request.URL, err, r.StatusCode)
	})

	var wg sync.WaitGroup
	for _, eng := range s.SearchEngines {
		if !eng.Enabled {
			continue
		}
		wg.Add(1)
		go func(eng SearchEngineConfig) {
			defer wg.Done()
			if err := c.Visit(fmt.Sprintf(eng.URLFormat, domain)); err != nil {
				log.Printf("[%s] %s 访问失败: %v", s.SourceName, eng.Name, err)
			}
		}(eng)
	}
	wg.Wait()
	c.Wait()
	return results, nil
}

func extractAndAppend(text string, re *regexp.Regexp, domain string, results *[]CollectResult, mu *sync.Mutex, s *SearchEngineCollector, src string) {
	if matches := re.FindAllString(text, -1); len(matches) > 0 {
		mu.Lock()
		defer mu.Unlock()
		for _, raw := range matches {
			sub := strings.ToLower(strings.Trim(raw, "."))
			if !s.isValidSubdomain(sub, domain) {
				continue
			}
			if !s.containsSubdomain(*results, sub) {
				*results = append(*results, s.createResult(sub, src))
			}
		}
	}
}

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
	return resolveA(context.Background(), subdomain)
}

//// ------------- Cookie 复用示例（可选） -------------
//const cookieFile = "brave_cookies.json"
//
//func saveCookies(ctx pw.BrowserContext) {
//	cookies, _ := ctx.Cookies()
//	data, _ := json.Marshal(cookies)
//	_ = os.WriteFile(cookieFile, data, 0644)
//}

//func loadCookies(ctx pw.BrowserContext) {
//	data, err := os.ReadFile(cookieFile)
//	if err != nil {
//		return
//	}
//	var cookies []pw.SetNetworkCookieParam
//	if err := json.Unmarshal(data, &cookies); err == nil {
//		_ = ctx.AddCookies(cookies)
//	}
//}
