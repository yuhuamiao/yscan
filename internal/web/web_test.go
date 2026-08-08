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
	form := pageSection(t, page, "function scanTaskForm()", "function changeList(")
	if !strings.Contains(form, "mode: 'scheduled'") {
		t.Fatal("scheduled task form must submit scheduled mode")
	}
	if strings.Contains(form, "name=\"mode\"") {
		t.Fatal("scheduled task form must not expose an immediate execution mode")
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
	for _, expected := range []string{"/findings?page=1&page_size=100", "/audit-report", "executed_endpoint_count", "candidate_endpoint_count", "未启用漏洞验证", "无可用端点或模板", "验证成功，未发现漏洞", "漏洞验证失败"} {
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

func TestAssetDetailRendersProtocolResponseSummary(t *testing.T) {
	page := string(indexHTML)
	section := pageSection(t, page, "async function showAssetDetail(ip)", "async function renderReports()")
	for _, expected := range []string{
		"port.protocol_evidence", "passive_banner", "active_probe", "item.status_code", "item.server", "item.title",
		"TCP 被动 Banner", "TCP 主动 Probe", "未保存协议响应摘要",
		"port.technologies", "item.version", "item.cpe", "item.sources", "item.product_status", "item.conflict_candidates",
		"网络服务", "Web Server", "运行时 / 语言", "框架", "CMS / 应用", "控制面板", "前端技术",
		"port.validation", "candidate_template_count", "identified_product_count", "finding_count", "unresolved_reasons", "observation_run_id",
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
