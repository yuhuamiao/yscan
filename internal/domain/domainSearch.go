package domain

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"os"
	"path/filepath"
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
		Headless:      false,
		BrowserType:   "chromium",
	}
}

func (s *SearchEngineCollector) Collect(domain string, timeout time.Duration) ([]CollectResult, error) {
	if s.UsePlaywright {
		if !isPlaywrightReady() {
			log.Printf("[playwright] fallback to colly, runtime not ready")
		} else {
			watchdog := timeout + 15*time.Second
			ctx, cancel := context.WithTimeout(context.Background(), watchdog)
			defer cancel()

			subs, err := s.collectWithPlaywright(ctx, domain, timeout)
			if err == nil && len(subs) > 0 {
				return subs, nil
			}
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					log.Printf("[playwright] timeout after %v, fallback to colly", watchdog)
				} else {
					log.Printf("[playwright] fallback to colly, err=%v", err)
				}
			} else {
				log.Printf("[playwright] fallback to colly, no subdomains found")
			}
		}
	}
	return s.collectWithColly(domain, timeout)
}

// ============ Playwright Brave 搜索 ============

func (s *SearchEngineCollector) collectWithPlaywright(scanCtx context.Context, domain string, timeout time.Duration) ([]CollectResult, error) {
	throttle(1200 * time.Millisecond) // 频率限制

	select {
	case <-scanCtx.Done():
		return nil, scanCtx.Err()
	default:
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

	browserCtx, err := browser.NewContext(pw.BrowserNewContextOptions{
		UserAgent: pw.String("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"),
	})
	if err != nil {
		return nil, err
	}
	defer browserCtx.Close()

	page, err := browserCtx.NewPage()
	if err != nil {
		return nil, err
	}
	page.SetDefaultTimeout(float64(playwrightStepTimeout(scanCtx, timeout).Milliseconds()))

	url := "https://search.brave.com/search?q=site:" + domain + "&source=web"
	_, err = page.Goto(url, pw.PageGotoOptions{
		WaitUntil: pw.WaitUntilStateDomcontentloaded,
		Timeout:   pw.Float(float64(playwrightStepTimeout(scanCtx, timeout).Milliseconds())),
	})
	if err != nil {
		if scanCtx.Err() != nil {
			return nil, scanCtx.Err()
		}
		return nil, err
	}

	_, _ = page.WaitForSelector("body", pw.PageWaitForSelectorOptions{Timeout: pw.Float(float64(playwrightStepTimeout(scanCtx, 10*time.Second).Milliseconds()))})
	_, _ = page.WaitForSelector("a", pw.PageWaitForSelectorOptions{Timeout: pw.Float(float64(playwrightStepTimeout(scanCtx, 10*time.Second).Milliseconds()))})
	if scanCtx.Err() != nil {
		return nil, scanCtx.Err()
	}
	time.Sleep(2 * time.Second)
	if scanCtx.Err() != nil {
		return nil, scanCtx.Err()
	}

	htmlContent, err := page.Content()
	if err != nil {
		return nil, err
	}
	bodyText, err := page.InnerText("body")
	if err != nil {
		bodyText = ""
	}

	target := strings.ToLower(htmlContent + "\n" + bodyText)
	re := regexp.MustCompile(`(?i)(?:[a-z0-9-]+\.)+` + regexp.QuoteMeta(domain))
	matches := re.FindAllString(target, -1)

	uniq := make(map[string]CollectResult)
	for _, m := range matches {
		sub := strings.Trim(strings.ToLower(m), ".")
		if !s.isValidSubdomain(sub, domain) {
			continue
		}
		if _, ok := uniq[sub]; ok {
			continue
		}
		// Playwright 路径先返回子域名本身，避免 DNS 解析拖慢导致被 watchdog 超时截断。
		uniq[sub] = CollectResult{
			Subdomain: sub,
			IPs:       nil,
			FirstSeen: time.Now(),
			Sources:   []string{s.SourceName + ":playwright:brave"},
		}
	}

	log.Printf("[playwright] raw_matches=%d, unique_subdomains=%d", len(matches), len(uniq))

	results := make([]CollectResult, 0, len(uniq))
	for _, r := range uniq {
		results = append(results, r)
	}
	results = s.resolveIPsConcurrent(scanCtx, results, 8)
	if scanCtx.Err() != nil {
		return nil, scanCtx.Err()
	}
	return results, nil
}

func (s *SearchEngineCollector) resolveIPsConcurrent(ctx context.Context, results []CollectResult, workers int) []CollectResult {
	if len(results) == 0 {
		return results
	}
	if workers <= 0 {
		workers = 4
	}

	type job struct{ idx int }
	jobs := make(chan job, len(results))
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				sub := results[j.idx].Subdomain
				if strings.HasPrefix(sub, "*.") {
					continue
				}
				ips := s.safeResolveIPs(ctx, sub)
				results[j.idx].IPs = ips
			}
		}()
	}

	for i := range results {
		if ctx.Err() != nil {
			break
		}
		jobs <- job{idx: i}
	}
	close(jobs)
	wg.Wait()
	return results
}

func playwrightStepTimeout(ctx context.Context, preferred time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 1 * time.Millisecond
		}
		if remaining < preferred {
			return remaining
		}
	}
	return preferred
}

func isPlaywrightReady() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	driverDir := filepath.Join(home, ".cache", "ms-playwright-go")
	browserDir := filepath.Join(home, ".cache", "ms-playwright")

	if st, err := os.Stat(driverDir); err != nil || !st.IsDir() {
		return false
	}

	chromiumBuilds, _ := filepath.Glob(filepath.Join(browserDir, "chromium-*"))
	if len(chromiumBuilds) == 0 {
		return false
	}

	return true
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
	c.SetRequestTimeout(timeout)
	if s.Proxy != "" {
		_ = c.SetProxy(s.Proxy)
	}

	_ = c.Limit(&colly.LimitRule{
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
			visitURL := fmt.Sprintf(eng.URLFormat, domain)
			if err := c.Visit(visitURL); err != nil {
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
		IPs:       s.safeResolveIPs(context.Background(), subdomain),
		FirstSeen: time.Now(),
		Sources:   []string{s.SourceName + ":" + host},
	}
}

func (s *SearchEngineCollector) safeResolveIPs(parent context.Context, subdomain string) []net.IP {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("IP解析异常: %v", r)
		}
	}()
	if strings.HasPrefix(subdomain, "*.") {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	return resolveA(ctx, subdomain)
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
