package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestImmediateExecutionUsesV2ScanTasks(t *testing.T) {
	page := string(indexHTML)
	immediate := pageSection(t, page, "async function renderImmediateExecutions()", "async function renderAssets()")
	if !strings.Contains(immediate, "request('/api/scan-tasks')") {
		t.Fatal("immediate execution must load V2 scan tasks")
	}
	if !strings.Contains(immediate, "mode: 'once'") {
		t.Fatal("immediate execution must create a one-time scan task")
	}
	if strings.Contains(immediate, "/api/tasks") {
		t.Fatal("immediate execution must not call the legacy task API")
	}
	if !strings.Contains(page, "'/executions':renderImmediateExecutions") {
		t.Fatal("execution route must render the V2 immediate execution page")
	}
}

func TestScheduledTaskFormStaysScheduledOnly(t *testing.T) {
	page := string(indexHTML)
	form := pageSection(t, page, "function scanTaskForm(task = null)", "function changeList(")
	if !strings.Contains(form, "mode: 'scheduled'") {
		t.Fatal("scheduled task form must submit scheduled mode")
	}
	if strings.Contains(form, "name=\"mode\"") {
		t.Fatal("scheduled task form must not expose an immediate execution mode")
	}
	for _, expected := range []string{"portPolicyControl(scanType", "name=\"schedule_mode\"", "每日", "每周", "高级 Cron", "method:task ? 'PUT' : 'POST'"} {
		if !strings.Contains(form, expected) {
			t.Fatalf("scheduled task form missing %q", expected)
		}
	}
}

func TestTaskControlsExposeRunNowProgressCancelAndRefresh(t *testing.T) {
	page := string(indexHTML)
	for _, expected := range []string{"run-now", "立即运行", "run.progress", "run.stage", "<progress", "/cancel`, {method:'POST'}", "scheduleRouteRefresh", "scheduleScanTaskDetailRefresh", "3000"} {
		if !strings.Contains(page, expected) {
			t.Fatalf("task controls missing %q", expected)
		}
	}
}

func TestActiveRunDetailRefreshDoesNotReturnToTaskList(t *testing.T) {
	page := string(indexHTML)
	refresh := pageSection(t, page, "let routeRefreshTimer = 0", "function renderScanTaskStats(rows)")
	for _, expected := range []string{
		"let selectedScanTaskID = ''",
		"let scanTaskDetailEpoch = 0",
		"let runDetailLoadSerial = 0",
		"let scanTaskDetailRefreshFailed = false",
		"function refreshScanTaskDetail(taskID, runs, epoch)",
		"epoch !== scanTaskDetailEpoch",
		"runs.splice(0, runs.length, ...refreshedRuns)",
		"updateRunState(document.getElementById('run-detail')",
		"scanTaskDetailRefreshFailed = false; message('')",
		"scanTaskDetailRefreshFailed = true; message(error.message, true); scheduleScanTaskDetailRefresh(taskID, runs, epoch)",
	} {
		if !strings.Contains(refresh, expected) {
			t.Fatalf("detail refresh state machine missing %q", expected)
		}
	}
	if strings.Contains(refresh, "showScanTaskDetail(taskID)") || strings.Contains(refresh, "showScanTaskDetail(selectedScanTaskID)") {
		t.Fatal("active-run polling still rebuilds the selected task detail")
	}
	if strings.Contains(refresh, "renderScanTasks()") || strings.Contains(refresh, "renderImmediateExecutions()") {
		t.Fatal("list polling still rebuilds the current route")
	}
	detail := pageSection(t, page, "async function showScanTaskDetail(id)", "function bindScanTaskActions(task)")
	if !strings.Contains(detail, "selectedScanTaskID = String(id)") || !strings.Contains(detail, "scheduleScanTaskDetailRefresh(task.id, runs, epoch)") || !strings.Contains(detail, "data-testid=\"scan-task-detail\"") {
		t.Fatal("task detail does not retain selection and schedule its own refresh")
	}
}

func TestRunDiffRequestsIncludeBaselineAndSequenceIdentity(t *testing.T) {
	page := string(indexHTML)
	section := pageSection(t, page, "async function loadRunDetailAndChanges", "async function renderImmediateExecutions")
	for _, expected := range []string{
		"loadSerial = ++runDetailLoadSerial",
		"function runDetailRequestCurrent(taskID, runID, baselineRunID, epoch, loadSerial)",
		"loadSerial === runDetailLoadSerial",
		"document.getElementById('baseline-select')?.value",
		"loadRunChanges(taskID, run, baselineRunID, epoch, loadSerial)",
	} {
		if !strings.Contains(section, expected) {
			t.Fatalf("run Diff request isolation missing %q", expected)
		}
	}
	if !strings.Contains(page, "loadRunChanges(taskID, selectedRun, baselineRunID, epoch, ++runDetailLoadSerial)") {
		t.Fatal("natural completion does not invalidate older Diff requests")
	}
}

func TestListAndTerminalRefreshMutateExistingControls(t *testing.T) {
	page := string(indexHTML)
	for _, expected := range []string{
		"function refreshScanTaskRows(routeMode, rows, epoch)",
		"syncVisibleScanTaskRow(task, runs)",
		"scheduleRouteRefresh('all', rows, epoch)",
		"scheduleRouteRefresh('once', rows, epoch)",
		"function syncRunSelectors(runs, selectedRunID)",
		"activeRun(previousSelected) && !activeRun(selectedRun)",
		"loadRunChanges(taskID, selectedRun",
	} {
		if !strings.Contains(page, expected) {
			t.Fatalf("incremental list/terminal refresh missing %q", expected)
		}
	}
}

func TestPortPolicyPresetsAreSharedByScheduledAndImmediateForms(t *testing.T) {
	page := string(indexHTML)
	for _, expected := range []string{
		"function portPolicyControl(scanType, portSpec = '')",
		"function bindPortPolicy(form)",
		"默认策略", "重要端口", "Web 常见端口", "基础服务端口", "数据库与中间件", "全端口", "自定义",
		"name=\"port_preset\"", "name=\"port_spec\"", "1-65535", "baselinePortSpec",
	} {
		if !strings.Contains(page, expected) {
			t.Fatalf("port policy presets missing %q", expected)
		}
	}
	if strings.Count(page, "bindPortPolicy(") < 3 {
		t.Fatal("scheduled and immediate forms do not share port policy binding")
	}
	if !strings.Contains(page, "function submittedPortSpec(values) { return values.get('port_preset') === 'default' ? ''") || strings.Count(page, "port_spec: submittedPortSpec(") != 2 {
		t.Fatal("default port policy must display its range without persisting an explicit port_spec")
	}
}

func TestMarkdownTablesHandleEscapedPipes(t *testing.T) {
	page := string(indexHTML)
	section := pageSection(t, page, "function markdownCells(line)", "function markdownTableSeparator(line)")
	for _, expected := range []string{"trimmed[index] === '\\\\'", "trimmed[index + 1] === '|'", "cell += '|'"} {
		if !strings.Contains(section, expected) {
			t.Fatalf("Markdown table parser does not preserve escaped pipes: missing %q", expected)
		}
	}
}

func TestReportLoadingRejectsStaleSuccessAndFailure(t *testing.T) {
	page := string(indexHTML)
	section := pageSection(t, page, "const reportSelection =", "function route()")
	for _, expected := range []string{
		"loadSerial: 0",
		"loadSerial = ++reportSelection.loadSerial",
		"const isCurrent = () => loadSerial === reportSelection.loadSerial",
		"catch (error) { if (isCurrent()) setMarkdownReport",
		"catch (error) { if (isCurrent()) findings.innerHTML",
	} {
		if !strings.Contains(section, expected) {
			t.Fatalf("report request isolation missing %q", expected)
		}
	}
}

func TestTerminalRunRefreshWaitsForReportOutcome(t *testing.T) {
	page := string(indexHTML)
	refresh := pageSection(t, page, "function activeRun(run)", "function scheduleRefresh(refresh)")
	for _, expected := range []string{
		"function runNeedsRefresh(run)",
		"['failed', 'canceled'].includes(run.status)",
		"!run.report_error",
		"!run.report_path || !run.audit_report_path",
	} {
		if !strings.Contains(refresh, expected) {
			t.Fatalf("terminal report refresh missing %q", expected)
		}
	}
	if !strings.Contains(page, "rows.some(row => runNeedsRefresh") || !strings.Contains(page, "if (!runNeedsRefresh(runs[runs.length - 1])) return") {
		t.Fatal("task list and detail do not use the terminal report refresh contract")
	}
}

func TestActiveRunDetailRefreshSynchronizesVisibleTaskRow(t *testing.T) {
	page := string(indexHTML)
	for _, expected := range []string{
		"let visibleScanTaskRows = []",
		"function syncVisibleScanTaskRow(task, runs)",
		"stats.innerHTML = renderScanTaskStats(visibleScanTaskRows)",
		"syncVisibleRunDetail(taskID, runs, run)",
		"data-testid=\"run-state\"",
		"data-run-status",
		"data-run-stage",
		"data-run-progress",
	} {
		if !strings.Contains(page, expected) {
			t.Fatalf("task list/detail synchronization missing %q", expected)
		}
	}
}

func TestHandlerServesImmediateExecutionRoute(t *testing.T) {
	recorder := httptest.NewRecorder()
	Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/executions", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /executions status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !strings.Contains(recorder.Body.String(), "renderImmediateExecutions") {
		t.Fatal("execution route must serve the V2 immediate execution page")
	}
}

func TestFingerprintPageLoadsCompleteManagementData(t *testing.T) {
	page := string(indexHTML)
	section := pageSection(t, page, "async function renderFingerprints(importPage = 1)", "async function showAssetDetail(")
	for _, endpoint := range []string{
		"/api/fingerprints/sources",
		"/api/fingerprints/imports",
		"/api/fingerprints/template-mappings",
		"page_size: '50'",
		"/fingerprints/${resource}",
		"['imports', 'matches', 'evidence', 'conclusions']",
	} {
		if !strings.Contains(section, endpoint) {
			t.Fatalf("fingerprint page does not load %s", endpoint)
		}
	}
	for _, field := range []string{"raw_content", "evidence_summary", "match_id", "product_status", "product_role", "exclusive_group", "version_status", "cpe_status", "fingerprint_source_id"} {
		if !strings.Contains(section, field) {
			t.Fatalf("fingerprint page does not render %s", field)
		}
	}
	for _, field := range []string{"fingerprint-import-select", "fingerprint-rule-id", "fingerprint-product", "fingerprint-rule-status", "projection_sha256", "adapter_version", "fingerprint-page-next"} {
		if !strings.Contains(section, field) {
			t.Fatalf("fingerprint page does not provide %s", field)
		}
	}
	if strings.Contains(section, "evidence.body") || strings.Contains(section, "raw_response") {
		t.Fatal("fingerprint page must not render raw response evidence")
	}
}

func TestReportsLoadStructuredFindingsAndSeparateAuditReport(t *testing.T) {
	page := string(indexHTML)
	section := pageSection(t, page, "async function renderReports()", "function route()")
	for _, expected := range []string{"/findings?page=1&page_size=100", "'audit-report'", "executed_endpoint_count", "candidate_endpoint_count", "未启用漏洞验证", "无可用端点或模板", "验证成功，未发现漏洞", "漏洞验证失败"} {
		if !strings.Contains(section, expected) {
			t.Fatalf("report page missing %q", expected)
		}
	}
	if strings.Contains(section, "详情包含在 Markdown 报告中") {
		t.Fatal("report page still redirects users to raw Markdown for findings")
	}
	if !strings.Contains(section, "item.description") || strings.Contains(section, "item.evidence") {
		t.Fatal("report page must render parsed descriptions without raw nuclei evidence")
	}
}

func TestReportsUseSafeMarkdownAndBoundedSearchPickers(t *testing.T) {
	page := string(indexHTML)
	for _, expected := range []string{
		"function renderMarkdown(source)", "markdownTableSeparator", "markdownInline", "setMarkdownReport(content)",
		"id=\"report-task-search\"", "id=\"report-run-search\"", "data-report-mode=\"user\"", "data-report-mode=\"audit\"",
		"reportTaskMatches", "reportRunMatches", ".slice(0, 20)", "sort((left, right) => Number(right.sequence)",
	} {
		if !strings.Contains(page, expected) {
			t.Fatalf("report interaction missing %q", expected)
		}
	}
	if strings.Contains(page, "<pre class=\"markdown\"") || strings.Contains(page, "report.textContent = await request") {
		t.Fatal("reports still expose Markdown source instead of the safe renderer")
	}
}

func TestAssetPageUsesFixedSearchableNavigation(t *testing.T) {
	page := string(indexHTML)
	if !strings.Contains(page, ".asset-split { grid-template-columns: 380px minmax(0, 1fr); }") {
		t.Fatal("asset navigation does not use the fixed desktop track")
	}
	section := pageSection(t, page, "async function renderAssets()", "let fingerprintRulePage")
	for _, expected := range []string{"asset-nav", "id=\"asset-search\"", "asset-list", "data-asset-search", "最后发现"} {
		if !strings.Contains(section, expected) {
			t.Fatalf("asset navigation missing %q", expected)
		}
	}
	if strings.Contains(section, "<th>首次发现</th>") {
		t.Fatal("asset navigation still renders the wide five-column table")
	}
}

func TestAssetDetailRendersProtocolResponseSummary(t *testing.T) {
	page := string(indexHTML)
	section := pageSection(t, page, "async function showAssetDetail(ip)", "async function renderReports()")
	for _, expected := range []string{
		"port.protocol_evidence", "passive_banner", "active_probe", "item.status_code", "item.server", "item.title",
		"TCP 被动 Banner", "TCP 主动 Probe", "未保存协议响应摘要",
		"port.technologies", "item.version", "item.cpe", "item.sources", "item.product_status", "item.conflict_candidates",
		"网络服务", "Web Server", "运行时 / 语言", "框架", "CMS / 应用", "控制面板", "前端技术",
		"port.validation", "port.endpoint_validations", "data-testid=\"endpoint-validation\"", "data-status", "data-executed", "data-findings",
		"data-testid=\"vulnerability-finding\"", "data-template", "candidate_template_count", "identified_product_count", "finding_count", "unresolved_reasons", "observation_run_id",
	} {
		if !strings.Contains(section, expected) {
			t.Fatalf("asset detail missing %q", expected)
		}
	}
	for _, forbidden := range []string{"raw_response", "raw_content", "item.raw"} {
		if strings.Contains(section, forbidden) {
			t.Fatalf("asset detail must not expose %q", forbidden)
		}
	}
}

func pageSection(t *testing.T, page, start, end string) string {
	t.Helper()
	startIndex := strings.Index(page, start)
	if startIndex < 0 {
		t.Fatalf("start marker %q not found", start)
	}
	endIndex := strings.Index(page[startIndex:], end)
	if endIndex < 0 {
		t.Fatalf("end marker %q not found", end)
	}
	return page[startIndex : startIndex+endIndex]
}
