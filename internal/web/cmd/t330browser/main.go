package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/playwright-community/playwright-go"
)

func main() {
	baseURL := flag.String("base-url", "", "CAASM API base URL")
	ip := flag.String("ip", "127.0.0.1", "asset IP")
	browserPath := flag.String("browser", "", "Chromium executable path")
	expectedPorts := flag.Int("expected-ports", 6, "expected endpoint profile count")
	expectedValidations := flag.Int("expected-validations", 6, "expected endpoint validation row count")
	expectedFindings := flag.Int("expected-findings", 2, "expected vulnerability finding count")
	flag.Parse()
	if strings.TrimSpace(*baseURL) == "" {
		fatal(errors.New("--base-url is required"))
	}

	pw, err := playwright.Run()
	if err != nil {
		fatal(fmt.Errorf("start playwright: %w", err))
	}
	defer pw.Stop()
	launch := playwright.BrowserTypeLaunchOptions{Headless: playwright.Bool(true)}
	if strings.TrimSpace(*browserPath) != "" {
		launch.ExecutablePath = playwright.String(*browserPath)
	}
	browser, err := pw.Chromium.Launch(launch)
	if err != nil {
		fatal(fmt.Errorf("launch chromium: %w", err))
	}
	defer browser.Close()
	page, err := browser.NewPage()
	if err != nil {
		fatal(fmt.Errorf("new page: %w", err))
	}
	page.SetDefaultTimeout(15_000)

	var mu sync.Mutex
	problems := make([]string, 0)
	record := func(message string) {
		mu.Lock()
		problems = append(problems, message)
		mu.Unlock()
	}
	page.OnPageError(func(err error) { record("pageerror: " + err.Error()) })
	page.OnConsole(func(message playwright.ConsoleMessage) {
		if message.Type() == "error" {
			record("console error: " + message.Text())
		}
	})
	page.OnRequestFailed(func(request playwright.Request) {
		record(fmt.Sprintf("request failed: %s: %v", request.URL(), request.Failure()))
	})

	if _, err := page.Goto(strings.TrimRight(*baseURL, "/") + "/assets"); err != nil {
		fatal(fmt.Errorf("open assets page: %w", err))
	}
	row := page.Locator(fmt.Sprintf(`[data-testid="asset-row"][data-asset-ip="%s"]`, *ip))
	if err := row.WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for asset row: %w", err))
	}
	if err := row.Click(); err != nil {
		fatal(fmt.Errorf("click asset row: %w", err))
	}
	profiles := page.GetByTestId("endpoint-profile")
	if err := profiles.First().WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for endpoint profiles: %w", err))
	}
	assertCount(profiles, *expectedPorts, "endpoint profiles")
	for _, port := range []int{22222, 6379, 26379, 28080, 28081, 28082} {
		assertCount(page.Locator(fmt.Sprintf(`[data-testid="endpoint-profile"][data-port="%d"]`, port)), 1, fmt.Sprintf("endpoint %d", port))
	}
	for product, minimum := range map[string]int{"dropbear": 1, "flask": 1, "php": 2, "redis": 2} {
		assertMinimumCount(page.Locator(fmt.Sprintf(`[data-testid="technology"][data-product="%s"]`, product)), minimum, "technology "+product)
	}
	validations := page.GetByTestId("endpoint-validation")
	assertCount(validations, *expectedValidations, "endpoint validations")
	assertMinimumCount(page.Locator(`[data-testid="endpoint-validation"][data-protocol="tcp"]`), 3, "TCP endpoint validations")
	assertEndpointValidation(page, 28080, "success", 1, 1)
	assertEndpointValidation(page, 28081, "success", 1, 0)
	assertEndpointValidation(page, 28082, "success", 1, 0)
	assertCount(page.GetByTestId("vulnerability-finding"), *expectedFindings, "vulnerability findings")
	assertCount(page.Locator(`[data-testid="vulnerability-finding"][data-template="exposed-redis"]`), 2, "Redis findings")
	assertCount(page.Locator(`[data-testid="vulnerability-finding"][data-template="php-ini"]`), 1, "PHP finding")

	mu.Lock()
	deferredProblems := append([]string(nil), problems...)
	mu.Unlock()
	if len(deferredProblems) > 0 {
		fatal(fmt.Errorf("browser errors: %s", strings.Join(deferredProblems, " | ")))
	}
	fmt.Printf("T330 browser journey verified: ip=%s endpoints=%d validations=%d findings=%d\n", *ip, *expectedPorts, *expectedValidations, *expectedFindings)
}

func assertEndpointValidation(page playwright.Page, port int, status string, executed, findings int) {
	selector := fmt.Sprintf(`[data-testid="endpoint-profile"][data-port="%d"] [data-testid="endpoint-validation"][data-status="%s"][data-executed="%d"][data-findings="%d"]`, port, status, executed, findings)
	assertCount(page.Locator(selector), 1, fmt.Sprintf("endpoint %d validation", port))
}

func assertCount(locator playwright.Locator, expected int, name string) {
	count, err := locator.Count()
	if err != nil || count != expected {
		fatal(fmt.Errorf("%s count=%d, expected=%d, err=%v", name, count, expected, err))
	}
}

func assertMinimumCount(locator playwright.Locator, expected int, name string) {
	count, err := locator.Count()
	if err != nil || count < expected {
		fatal(fmt.Errorf("%s count=%d, expected at least %d, err=%v", name, count, expected, err))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
