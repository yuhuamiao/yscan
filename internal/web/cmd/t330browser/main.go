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
	taskID := flag.Int64("task-id", 0, "active ScanTask ID used to verify detail refresh")
	immediateTaskID := flag.Int64("immediate-task-id", 0, "active one-time task used to verify list refresh")
	defaultTaskID := flag.Int64("default-task-id", 0, "task with an empty default port policy")
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

	base := strings.TrimRight(*baseURL, "/")
	if *taskID > 0 {
		verifyActiveTaskDetail(page, base, *taskID)
	}
	if *immediateTaskID > 0 {
		verifyListRefresh(page, base+"/tasks", "refresh-scan-tasks", *immediateTaskID, "task list")
		verifyListRefresh(page, base+"/executions", "refresh-tasks", *immediateTaskID, "immediate list")
	}
	verifyPortPresetSubmission(page, base)
	if *defaultTaskID > 0 {
		verifyDefaultPortPolicySave(page, base, *defaultTaskID)
	}
	if err := page.SetViewportSize(1440, 900); err != nil {
		fatal(fmt.Errorf("set desktop viewport: %w", err))
	}
	if _, err := page.Goto(base + "/assets"); err != nil {
		fatal(fmt.Errorf("open assets page: %w", err))
	}
	row := page.Locator(fmt.Sprintf(`[data-testid="asset-row"][data-asset-ip="%s"]`, *ip))
	if err := row.WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for asset row: %w", err))
	}
	if err := row.Click(); err != nil {
		fatal(fmt.Errorf("click asset row: %w", err))
	}
	assertPageFitsViewport(page, "desktop asset page")
	assetNavigation := page.Locator(".asset-nav")
	box, err := assetNavigation.BoundingBox()
	if err != nil || box == nil || box.Width < 370 || box.Width > 390 {
		fatal(fmt.Errorf("asset navigation width=%#v err=%v, expected about 380px", box, err))
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
	verifyReports(page, base, *taskID)

	mu.Lock()
	deferredProblems := append([]string(nil), problems...)
	mu.Unlock()
	if len(deferredProblems) > 0 {
		fatal(fmt.Errorf("browser errors: %s", strings.Join(deferredProblems, " | ")))
	}
	fmt.Printf("T330 browser journey verified: ip=%s endpoints=%d validations=%d findings=%d\n", *ip, *expectedPorts, *expectedValidations, *expectedFindings)
}

func verifyActiveTaskDetail(page playwright.Page, baseURL string, taskID int64) {
	if err := page.SetViewportSize(1440, 640); err != nil {
		fatal(fmt.Errorf("set refresh viewport: %w", err))
	}
	if _, err := page.Goto(baseURL + "/tasks"); err != nil {
		fatal(fmt.Errorf("open task page: %w", err))
	}
	row := page.Locator(fmt.Sprintf(`[data-scan-task-id="%d"]`, taskID))
	if err := row.WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for active task row: %w", err))
	}
	detailOpened := false
	other := page.Locator(`[data-scan-task-id]:not([data-scan-task-id="` + fmt.Sprint(taskID) + `"])`).First()
	if count, err := other.Count(); err == nil && count == 1 {
		otherID, attributeErr := other.GetAttribute("data-scan-task-id")
		if attributeErr != nil {
			fatal(fmt.Errorf("read stale-response task ID: %w", attributeErr))
		}
		_, err = page.Evaluate(`taskID => { const original = window.fetch.bind(window); window.__yscanOriginalFetch = original; window.fetch = (url, options) => String(url).includes('/api/scan-tasks/' + taskID) ? new Promise(resolve => setTimeout(() => resolve(original(url, options)), 900)) : original(url, options); }`, otherID)
		if err != nil {
			fatal(fmt.Errorf("install stale-response delay: %w", err))
		}
		if err := other.Click(); err != nil {
			fatal(fmt.Errorf("open delayed task detail: %w", err))
		}
		if err := row.Click(); err != nil {
			fatal(fmt.Errorf("switch back to active task: %w", err))
		}
		page.WaitForTimeout(1_100)
		assertCount(page.Locator(fmt.Sprintf(`[data-testid="scan-task-detail"][data-task-id="%d"]`, taskID)), 1, "active detail after stale response")
		detailOpened = true
		_, _ = page.Evaluate(`() => { if (window.__yscanOriginalFetch) window.fetch = window.__yscanOriginalFetch; }`)
	} else if err != nil {
		fatal(fmt.Errorf("count alternate task rows: %w", err))
	}
	if !detailOpened {
		if err := row.Click(); err != nil {
			fatal(fmt.Errorf("open active task detail: %w", err))
		}
	}
	detail := page.Locator(fmt.Sprintf(`[data-testid="scan-task-detail"][data-task-id="%d"]`, taskID))
	if err := detail.WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for active task detail: %w", err))
	}
	runState := page.GetByTestId("run-state")
	if err := runState.WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for initial run state: %w", err))
	}
	if status, err := runState.GetAttribute("data-run-status"); err != nil || !isActiveStatus(status) {
		fatal(fmt.Errorf("run was not active when detail refresh verification began: status=%q err=%v", status, err))
	}
	marker, err := detail.Evaluate(`node => { node.__t352Marker = 'stable-detail'; return node.__t352Marker; }`, nil)
	if err != nil || marker != "stable-detail" {
		fatal(fmt.Errorf("mark active detail node: marker=%v err=%v", marker, err))
	}
	runSelect := page.Locator("#run-select")
	if err := runSelect.Focus(); err != nil {
		fatal(fmt.Errorf("focus run selector: %w", err))
	}
	scrollValue, err := page.Evaluate(`() => { document.body.style.paddingBottom = '1200px'; window.scrollTo(0, 420); return window.scrollY; }`)
	if err != nil || number(scrollValue) < 400 {
		fatal(fmt.Errorf("prepare detail scroll position=%v err=%v", scrollValue, err))
	}
	if _, err := page.Evaluate(`taskID => {
		const original = window.fetch.bind(window), path = '/api/scan-tasks/' + taskID + '/runs';
		window.__t352RefreshOriginalFetch = original; window.__t352RefreshAttempts = 0; window.__t352InjectedProgress = null;
		window.fetch = async (url, options) => {
			if (String(url) !== path) return original(url, options);
			window.__t352RefreshAttempts++;
			if (window.__t352RefreshAttempts === 1) return new Response('transient runs failure', {status:503});
			const response = await original(url, options);
			if (window.__t352RefreshAttempts !== 2 || !response.ok) return response;
			const runs = await response.json(), latest = runs[runs.length - 1];
			if (latest) { if (['queued','running','cancel_requested'].includes(latest.status)) latest.progress = Math.min(99, Math.max(Number(latest.progress || 0), Number(document.querySelector('[data-testid="run-state"]')?.dataset.runProgress || 0) + 1)); window.__t352InjectedProgress = latest.progress; }
			return new Response(JSON.stringify(runs), {status:response.status, headers:{'Content-Type':'application/json'}});
		};
	}`, fmt.Sprint(taskID)); err != nil {
		fatal(fmt.Errorf("install transient detail refresh failure: %w", err))
	}

	page.WaitForTimeout(6_500)
	assertCount(detail, 1, "active task detail after two refresh intervals")
	marker, err = detail.Evaluate(`node => node.__t352Marker`, nil)
	if err != nil || marker != "stable-detail" {
		fatal(fmt.Errorf("active detail DOM was replaced: marker=%v err=%v", marker, err))
	}
	focused, err := page.Evaluate(`() => document.activeElement && document.activeElement.id`)
	if err != nil || focused != "run-select" {
		fatal(fmt.Errorf("detail refresh lost focus: active=%v err=%v", focused, err))
	}
	scrollValue, err = page.Evaluate(`() => window.scrollY`)
	if err != nil || number(scrollValue) < 400 {
		fatal(fmt.Errorf("detail refresh changed scroll position=%v err=%v", scrollValue, err))
	}
	recovery, err := page.Evaluate(`() => ({attempts:window.__t352RefreshAttempts, injected:window.__t352InjectedProgress, displayed:Number(document.querySelector('[data-testid="run-state"]')?.dataset.runProgress), message:document.getElementById('status-line')?.textContent || ''})`)
	values, ok := recovery.(map[string]interface{})
	if err != nil || !ok || number(values["attempts"]) < 2 || values["injected"] == nil || number(values["displayed"]) != number(values["injected"]) || fmt.Sprint(values["message"]) != "" {
		fatal(fmt.Errorf("detail refresh did not recover after one failure: state=%#v err=%v", recovery, err))
	}
	_, _ = page.Evaluate(`() => { window.fetch = window.__t352RefreshOriginalFetch; }`)
	assertCount(page.Locator("#run-detail"), 1, "active run detail after refresh interval")
	for _, attribute := range []string{"data-run-status", "data-run-stage", "data-run-progress"} {
		rowValue, rowErr := row.GetAttribute(attribute)
		detailValue, detailErr := runState.GetAttribute(attribute)
		if rowErr != nil || detailErr != nil || rowValue != detailValue {
			fatal(fmt.Errorf("task list/detail %s mismatch row=%q detail=%q row_err=%v detail_err=%v", attribute, rowValue, detailValue, rowErr, detailErr))
		}
	}
	completed := false
	for attempt := 0; attempt < 90; attempt++ {
		status, statusErr := runState.GetAttribute("data-run-status")
		if statusErr != nil {
			fatal(fmt.Errorf("read naturally completing run status: %w", statusErr))
		}
		if status == "success" {
			completed = true
			break
		}
		if !isActiveStatus(status) {
			fatal(fmt.Errorf("run reached unexpected terminal status %q", status))
		}
		page.WaitForTimeout(1_000)
	}
	if !completed {
		fatal(errors.New("active run did not naturally reach success"))
	}
	selectedText, err := page.Locator("#run-select option:checked").TextContent()
	if err != nil || !strings.Contains(selectedText, "success") || !strings.Contains(selectedText, "completed 100%") {
		fatal(fmt.Errorf("terminal run selector was not updated: text=%q err=%v", selectedText, err))
	}
	if count, err := page.Locator("#baseline-select option").Count(); err != nil || count < 2 {
		fatal(fmt.Errorf("terminal baseline options count=%d err=%v", count, err))
	}
	changes, err := page.Locator("#run-changes").TextContent()
	if err != nil || strings.Contains(changes, "仅成功运行具有可比较的快照") || strings.Contains(changes, "正在加载") {
		fatal(fmt.Errorf("terminal Diff was not refreshed: text=%q err=%v", changes, err))
	}
	baselines := page.Locator(`#baseline-select option:not([value=""])`)
	if count, err := baselines.Count(); err != nil || count < 2 {
		fatal(fmt.Errorf("baseline race needs two explicit baselines: count=%d err=%v", count, err))
	}
	baselineA, _ := baselines.Nth(0).GetAttribute("value")
	baselineB, _ := baselines.Nth(1).GetAttribute("value")
	if _, err := page.Evaluate(`baseline => { const original = window.fetch.bind(window); window.__t352DiffOriginalFetch = original; window.fetch = (url, options) => String(url).includes('baseline_run_id=' + baseline) ? new Promise(resolve => setTimeout(() => resolve(original(url, options)), 900)) : original(url, options); }`, baselineA); err != nil {
		fatal(fmt.Errorf("install delayed baseline response: %w", err))
	}
	valuesA := []string{baselineA}
	if _, err := page.Locator("#baseline-select").SelectOption(playwright.SelectOptionValues{Values: &valuesA}); err != nil {
		fatal(fmt.Errorf("select delayed baseline A: %w", err))
	}
	valuesB := []string{baselineB}
	if _, err := page.Locator("#baseline-select").SelectOption(playwright.SelectOptionValues{Values: &valuesB}); err != nil {
		fatal(fmt.Errorf("select current baseline B: %w", err))
	}
	matchedB := false
	for attempt := 0; attempt < 30; attempt++ {
		note, noteErr := page.Locator("#run-changes > .section-note").TextContent()
		if noteErr == nil && note == "基线运行 #"+baselineB {
			matchedB = true
			break
		}
		page.WaitForTimeout(100)
	}
	page.WaitForTimeout(1_000)
	selectedBaseline, _ := page.Locator("#baseline-select").InputValue()
	baselineNote, noteErr := page.Locator("#run-changes > .section-note").TextContent()
	if !matchedB || noteErr != nil || selectedBaseline != baselineB || baselineNote != "基线运行 #"+baselineB {
		fatal(fmt.Errorf("delayed baseline A overwrote B: selected=%q note=%q A=%q B=%q err=%v", selectedBaseline, baselineNote, baselineA, baselineB, noteErr))
	}
	_, _ = page.Evaluate(`() => { window.fetch = window.__t352DiffOriginalFetch; }`)
	_, _ = page.Evaluate(`() => { document.body.style.paddingBottom = ''; window.scrollTo(0, 0); }`)
}

func verifyListRefresh(page playwright.Page, url, refreshID string, taskID int64, name string) {
	if _, err := page.Goto(url); err != nil {
		fatal(fmt.Errorf("open %s: %w", name, err))
	}
	row := page.Locator(fmt.Sprintf(`[data-scan-task-id="%d"]`, taskID))
	if err := row.WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for %s active row: %w", name, err))
	}
	root := page.Locator("#scan-task-stats")
	if _, err := root.Evaluate(`node => { node.__t352ListMarker = 'stable-list'; return true; }`, nil); err != nil {
		fatal(fmt.Errorf("mark %s root: %w", name, err))
	}
	refresh := page.Locator("#" + refreshID)
	if err := refresh.Focus(); err != nil {
		fatal(fmt.Errorf("focus %s refresh: %w", name, err))
	}
	if value, err := page.Evaluate(`() => { document.body.style.paddingBottom = '1200px'; window.scrollTo(0, 360); return window.scrollY; }`); err != nil || number(value) < 340 {
		fatal(fmt.Errorf("prepare %s scroll=%v err=%v", name, value, err))
	}
	page.WaitForTimeout(6_500)
	if marker, err := root.Evaluate(`node => node.__t352ListMarker`, nil); err != nil || marker != "stable-list" {
		fatal(fmt.Errorf("%s root was replaced: marker=%v err=%v", name, marker, err))
	}
	if focused, err := page.Evaluate(`() => document.activeElement && document.activeElement.id`); err != nil || focused != refreshID {
		fatal(fmt.Errorf("%s lost focus: active=%v err=%v", name, focused, err))
	}
	if value, err := page.Evaluate(`() => window.scrollY`); err != nil || number(value) < 340 {
		fatal(fmt.Errorf("%s changed scroll=%v err=%v", name, value, err))
	}
	assertCount(row, 1, name+" row after two refresh periods")
	_, _ = page.Evaluate(`() => { document.body.style.paddingBottom = ''; window.scrollTo(0, 0); }`)
}

func isActiveStatus(status string) bool {
	return status == "queued" || status == "running" || status == "cancel_requested"
}

func verifyPortPresetSubmission(page playwright.Page, baseURL string) {
	if _, err := page.Goto(baseURL + "/executions"); err != nil {
		fatal(fmt.Errorf("open immediate execution page: %w", err))
	}
	form := page.Locator("#task-form")
	if err := form.WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for immediate form: %w", err))
	}
	values := []string{"web"}
	if _, err := form.Locator(`[name="port_preset"]`).SelectOption(playwright.SelectOptionValues{Values: &values}); err != nil {
		fatal(fmt.Errorf("select Web port preset: %w", err))
	}
	const expected = "80-82,443,8000,8008,8080-8081,8443,8888,9000,9090"
	actual, err := form.Locator(`[name="port_spec"]`).InputValue()
	if err != nil || actual != expected {
		fatal(fmt.Errorf("Web port preset=%q err=%v, expected %q", actual, err, expected))
	}
	if _, err := page.Evaluate(`() => { const original = window.fetch.bind(window); window.__yscanOriginalFetch = original; window.__capturedPortSpec = ''; window.fetch = (url, options = {}) => { if (String(url) === '/api/scan-tasks' && options.method === 'POST') { window.__capturedPortSpec = JSON.parse(options.body).config.port_spec; return Promise.resolve(new Response(JSON.stringify({task:{id:999},run:{id:999}}), {status:201,headers:{'Content-Type':'application/json'}})); } return original(url, options); }; }`); err != nil {
		fatal(fmt.Errorf("install port submission capture: %w", err))
	}
	if err := form.Locator(`[name="target"]`).Fill("127.0.0.1"); err != nil {
		fatal(fmt.Errorf("fill immediate target: %w", err))
	}
	if err := form.Locator(`button[type="submit"]`).Click(); err != nil {
		fatal(fmt.Errorf("submit immediate preset: %w", err))
	}
	if _, err := page.WaitForFunction(`expected => window.__capturedPortSpec === expected`, expected); err != nil {
		fatal(fmt.Errorf("wait for captured port preset: %w", err))
	}
	_, _ = page.Evaluate(`() => { window.fetch = window.__yscanOriginalFetch; }`)
}

func verifyDefaultPortPolicySave(page playwright.Page, baseURL string, taskID int64) {
	readTask := `async id => { const task = await (await fetch('/api/scan-tasks/' + id)).json(); return task.config_hash + '|' + (task.config.port_spec || ''); }`
	before, err := page.Evaluate(readTask, fmt.Sprint(taskID))
	if err != nil {
		fatal(fmt.Errorf("read default task before Web save: %w", err))
	}
	if _, err := page.Goto(baseURL + "/tasks"); err != nil {
		fatal(fmt.Errorf("open tasks for default policy edit: %w", err))
	}
	row := page.Locator(fmt.Sprintf(`[data-scan-task-id="%d"]`, taskID))
	if err := row.Click(); err != nil {
		fatal(fmt.Errorf("open default policy task: %w", err))
	}
	edit := page.Locator(`[data-scan-task-action="edit"]`)
	if err := edit.WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for default policy edit: %w", err))
	}
	if err := edit.Click(); err != nil {
		fatal(fmt.Errorf("edit default policy task: %w", err))
	}
	form := page.Locator("#scan-task-form")
	if err := form.WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for default policy form: %w", err))
	}
	preset, _ := form.Locator(`[name="port_preset"]`).InputValue()
	display, _ := form.Locator(`[name="port_spec"]`).InputValue()
	if preset != "default" || display != "1-65535" {
		fatal(fmt.Errorf("default port policy preset=%q display=%q", preset, display))
	}
	if err := form.Locator(`button[type="submit"]`).Click(); err != nil {
		fatal(fmt.Errorf("save unchanged default task: %w", err))
	}
	if err := row.WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for tasks after default policy save: %w", err))
	}
	after, err := page.Evaluate(readTask, fmt.Sprint(taskID))
	if err != nil || fmt.Sprint(after) != fmt.Sprint(before) || !strings.HasSuffix(fmt.Sprint(after), "|") {
		fatal(fmt.Errorf("default policy Web save changed hash/config: before=%v after=%v err=%v", before, after, err))
	}
}

func verifyReports(page playwright.Page, baseURL string, taskID int64) {
	if _, err := page.Goto(baseURL + "/reports"); err != nil {
		fatal(fmt.Errorf("open reports page: %w", err))
	}
	taskSearch := page.Locator("#report-task-search")
	if err := taskSearch.WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for report task search: %w", err))
	}
	assertCount(page.Locator("#report-task-results [data-report-task]"), 20, "bounded task search results")
	if err := taskSearch.Fill(fmt.Sprintf("#%d", taskID)); err != nil {
		fatal(fmt.Errorf("filter report tasks: %w", err))
	}
	taskOption := page.Locator(fmt.Sprintf(`[data-report-task="%d"]`, taskID))
	if err := taskOption.WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for selected report task: %w", err))
	}
	if err := taskOption.Click(); err != nil {
		fatal(fmt.Errorf("select report task: %w", err))
	}
	runSearch := page.Locator("#report-run-search")
	if err := runSearch.Fill("success"); err != nil {
		fatal(fmt.Errorf("filter successful runs: %w", err))
	}
	runOption := page.Locator("#report-run-results [data-report-run]").First()
	if err := runOption.WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for successful report run: %w", err))
	}
	if err := runOption.Click(); err != nil {
		fatal(fmt.Errorf("select successful report run: %w", err))
	}
	if err := page.Locator("#markdown-report h1").WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for rendered report heading: %w", err))
	}
	assertMinimumCount(page.Locator("#markdown-report .markdown-table table"), 1, "rendered Markdown tables")
	selectedTask, _ := page.Locator("[data-report-task].selected").GetAttribute("data-report-task")
	selectedRun, _ := page.Locator("[data-report-run].selected").GetAttribute("data-report-run")
	if err := page.Locator(`[data-report-mode="audit"]`).Click(); err != nil {
		fatal(fmt.Errorf("switch to audit report: %w", err))
	}
	if err := page.GetByText("Frozen Fingerprint Revisions").WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for rendered audit report: %w", err))
	}
	if task, _ := page.Locator("[data-report-task].selected").GetAttribute("data-report-task"); task != selectedTask {
		fatal(fmt.Errorf("audit switch changed task selection from %s to %s", selectedTask, task))
	}
	if run, _ := page.Locator("[data-report-run].selected").GetAttribute("data-report-run"); run != selectedRun {
		fatal(fmt.Errorf("audit switch changed run selection from %s to %s", selectedRun, run))
	}
	if _, err := page.Evaluate("() => { document.getElementById('markdown-report').innerHTML = renderMarkdown('| Value |\\n| --- |\\n| a \\\\| b |'); }"); err != nil {
		fatal(fmt.Errorf("render escaped-pipe Markdown: %w", err))
	}
	if value, err := page.Locator("#markdown-report tbody td").TextContent(); err != nil || value != "a | b" {
		fatal(fmt.Errorf("escaped Markdown pipe cell=%q err=%v", value, err))
	}
	if _, err := page.Evaluate(`() => { const original = window.fetch.bind(window); window.__reportRaceOriginalFetch = original; window.fetch = (url, options) => String(url).includes('/audit-report') ? new Promise(resolve => setTimeout(() => resolve(new Response('delayed report failure', {status:404})), 900)) : original(url, options); }`); err != nil {
		fatal(fmt.Errorf("install delayed report failure: %w", err))
	}
	if err := page.Locator(`[data-report-mode="audit"]`).Click(); err != nil {
		fatal(fmt.Errorf("start delayed audit report: %w", err))
	}
	if err := page.Locator(`[data-report-mode="user"]`).Click(); err != nil {
		fatal(fmt.Errorf("switch back during delayed audit report: %w", err))
	}
	if err := page.Locator("#markdown-report h1").WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for current report after delayed failure: %w", err))
	}
	page.WaitForTimeout(1_100)
	if content, err := page.Locator("#markdown-report").TextContent(); err != nil || strings.Contains(content, "delayed report failure") {
		fatal(fmt.Errorf("stale report error replaced current report: content=%q err=%v", content, err))
	}
	_, _ = page.Evaluate(`() => { window.fetch = window.__reportRaceOriginalFetch; }`)
	runs := page.Locator("#report-run-results [data-report-run]")
	if count, err := runs.Count(); err != nil || count < 2 {
		fatal(fmt.Errorf("report race needs two runs: count=%d err=%v", count, err))
	}
	oldRun, _ := runs.Nth(0).GetAttribute("data-report-run")
	newRun, _ := runs.Nth(1).GetAttribute("data-report-run")
	if _, err := page.Evaluate(`oldRun => { const original = window.fetch.bind(window); window.__findingRaceOriginalFetch = original; window.fetch = (url, options) => String(url).includes('/runs/' + oldRun + '/findings') ? new Promise(resolve => setTimeout(() => resolve(new Response('delayed findings failure', {status:404})), 900)) : original(url, options); }`, oldRun); err != nil {
		fatal(fmt.Errorf("install delayed findings failure: %w", err))
	}
	if err := page.Locator(`[data-report-run="` + oldRun + `"]`).Click(); err != nil {
		fatal(fmt.Errorf("start delayed findings request: %w", err))
	}
	if err := page.Locator(`[data-report-run="` + newRun + `"]`).Click(); err != nil {
		fatal(fmt.Errorf("switch run during delayed findings request: %w", err))
	}
	if err := page.Locator("#markdown-report h1").WaitFor(); err != nil {
		fatal(fmt.Errorf("wait for report after run race: %w", err))
	}
	page.WaitForTimeout(1_100)
	if content, err := page.Locator("#finding-list").TextContent(); err != nil || strings.Contains(content, "delayed findings failure") {
		fatal(fmt.Errorf("stale findings error replaced current run: content=%q err=%v", content, err))
	}
	if selected, _ := page.Locator("[data-report-run].selected").GetAttribute("data-report-run"); selected != newRun {
		fatal(fmt.Errorf("report race selected run=%q want=%q", selected, newRun))
	}
	_, _ = page.Evaluate(`() => { window.fetch = window.__findingRaceOriginalFetch; }`)
	if _, err := page.Evaluate(`() => { window.__markdownXSS = 0; document.getElementById('markdown-report').innerHTML = renderMarkdown('# Safe\n\n| Name | Value |\n| --- | --- |\n| row | ok |\n\n<script>window.__markdownXSS=1</script>\n<img src=x onerror="window.__markdownXSS=2">'); }`); err != nil {
		fatal(fmt.Errorf("render hostile Markdown: %w", err))
	}
	assertCount(page.Locator("#markdown-report .markdown-table table"), 1, "hostile Markdown table")
	assertCount(page.Locator("#markdown-report script, #markdown-report img"), 0, "unsafe Markdown elements")
	if value, err := page.Evaluate(`() => window.__markdownXSS`); err != nil || number(value) != 0 {
		fatal(fmt.Errorf("Markdown executed active content: value=%v err=%v", value, err))
	}
	if err := page.SetViewportSize(390, 844); err != nil {
		fatal(fmt.Errorf("set mobile viewport: %w", err))
	}
	assertPageFitsViewport(page, "mobile report page")
	if clipped, err := page.Evaluate(`() => [...document.querySelectorAll('.report-toolbar input, .report-mode button')].some(node => { const box = node.getBoundingClientRect(); return box.left < 0 || box.right > window.innerWidth; })`); err != nil || clipped == true {
		fatal(fmt.Errorf("mobile report controls clipped=%v err=%v", clipped, err))
	}
}

func assertPageFitsViewport(page playwright.Page, name string) {
	value, err := page.Evaluate(`() => document.documentElement.scrollWidth <= window.innerWidth`)
	if err != nil || value != true {
		fatal(fmt.Errorf("%s has horizontal overflow: value=%v err=%v", name, value, err))
	}
}

func number(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	default:
		return 0
	}
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
