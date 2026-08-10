package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/report"
	"golandproject/yscan/internal/schedule"
	"golandproject/yscan/internal/storage"
)

func TestLegacyTaskCreationIsReadOnly(t *testing.T) {
	for _, taskType := range []string{model.TaskTypeScanSubnet, model.TaskTypeScanSubnetVuln} {
		t.Run(taskType, func(t *testing.T) {
			handler, err := newHandler(nil, func(string, string) (int64, error) {
				t.Fatal("legacy task runner must not be called")
				return 0, nil
			})
			if err != nil {
				t.Fatalf("newHandler: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewBufferString(`{"type":"`+taskType+`","target":"192.168.1.0/24"}`))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			if recorder.Code != http.StatusGone {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestFingerprintImportAPISeparatesSummaryDetailAndBoundsPages(t *testing.T) {
	db, err := storage.InitDBAt(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	const manifestMarker = "T304-MANIFEST-MUST-BE-DETAIL-ONLY"
	fingerprintImport, err := storage.ImportFingerprintBatch(db, storage.FingerprintImportBatch{
		Source: model.FingerprintSource{SourceKey: "api-fixture", RepositoryURL: "https://example.invalid/api-fixture", License: "test", Status: "enabled"},
		Import: model.FingerprintImport{
			Commit: "api-fixture-v1", ContentSHA256: strings.Repeat("a", 64), UpstreamContentSHA256: strings.Repeat("a", 64),
			AdapterVersion: "api-fixture-adapter-v1", ManifestJSON: `{"marker":"` + manifestMarker + `"}`,
			RuleTotal: 1, ExecutableTotal: 1,
		},
		Rules: []model.FingerprintSourceRule{{SourceRuleID: "api-rule", SourcePath: "api/rule.json", ContentSHA256: strings.Repeat("b", 64), RawContent: `{"rule":"api"}`, ImportStatus: "executable"}},
		Projections: []model.FingerprintRuleProjection{{
			SourcePath: "api/rule.json", ContentSHA256: strings.Repeat("b", 64), Product: model.FingerprintProduct{CanonicalName: "api-fixture-product"}, Protocol: "http",
			Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: "http_body", Target: "body", Operator: "contains", Value: "api-fixture"}}},
		}},
	})
	if err != nil {
		t.Fatalf("import API fixture: %v", err)
	}
	handler, err := newHandler(db, func(string, string) (int64, error) { return 1, nil })
	if err != nil {
		t.Fatal(err)
	}

	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/fingerprints/imports?page=1&page_size=1", nil))
	if list.Code != http.StatusOK || bytes.Contains(list.Body.Bytes(), []byte("manifest_json")) || bytes.Contains(list.Body.Bytes(), []byte(manifestMarker)) {
		t.Fatalf("summary list status=%d body=%s", list.Code, list.Body.String())
	}
	var page struct {
		Items    []model.FingerprintImportSummary `json:"items"`
		Page     int                              `json:"page"`
		PageSize int                              `json:"page_size"`
		Total    int                              `json:"total"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &page); err != nil || page.Page != 1 || page.PageSize != 1 || len(page.Items) != 1 || page.Total < 1 {
		t.Fatalf("decode summary page=%#v err=%v", page, err)
	}

	detail := httptest.NewRecorder()
	handler.ServeHTTP(detail, httptest.NewRequest(http.MethodGet, "/api/fingerprints/imports/"+strconv.FormatInt(fingerprintImport.ID, 10), nil))
	if detail.Code != http.StatusOK || !bytes.Contains(detail.Body.Bytes(), []byte("manifest_json")) || !bytes.Contains(detail.Body.Bytes(), []byte(manifestMarker)) {
		t.Fatalf("detail status=%d body=%s", detail.Code, detail.Body.String())
	}

	tooLarge := httptest.NewRecorder()
	handler.ServeHTTP(tooLarge, httptest.NewRequest(http.MethodGet, "/api/fingerprints/imports?page_size=201", nil))
	if tooLarge.Code != http.StatusBadRequest {
		t.Fatalf("oversized import page status=%d body=%s", tooLarge.Code, tooLarge.Body.String())
	}

	service := schedule.NewTaskService(db, nil)
	task, run, err := service.Create(context.Background(), model.ScanTask{Target: "192.168.88.10", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce})
	if err != nil || run == nil {
		t.Fatalf("create run for paged fingerprint resources: task=%#v run=%#v err=%v", task, run, err)
	}
	var sourceRuleID, matcherID int64
	if err := db.QueryRow(`SELECT id FROM fingerprint_source_rules WHERE fingerprint_import_id = ?`, fingerprintImport.ID).Scan(&sourceRuleID); err != nil {
		t.Fatalf("read API fixture source rule: %v", err)
	}
	if err := db.QueryRow(`
		SELECT matcher.id
		FROM fingerprint_matchers AS matcher
		JOIN fingerprint_match_groups AS match_group ON match_group.id = matcher.fingerprint_match_group_id
		JOIN fingerprint_rules AS rule ON rule.id = match_group.fingerprint_rule_id
		WHERE rule.fingerprint_source_rule_id = ?`, sourceRuleID).Scan(&matcherID); err != nil {
		t.Fatalf("read API fixture matcher: %v", err)
	}
	if err := storage.SaveFingerprintRunMatches(db, run.ID, []model.FingerprintRunMatch{{
		FingerprintImportID: fingerprintImport.ID, FingerprintSourceRuleID: sourceRuleID,
		IP: "192.168.88.10", Port: 80, Protocol: "http", Product: "api-fixture-product", EvidenceSummary: "fixture summary",
		Evidence: []model.FingerprintMatchEvidence{{MatcherID: matcherID, EvidenceType: "http_body", Target: "body", Operator: "contains", ObservedSHA256: strings.Repeat("0", 64), ObservedLength: 7, Summary: "fixture matcher evidence"}},
	}}); err != nil {
		t.Fatalf("save API fixture run match: %v", err)
	}
	runHandler, err := newHandlerWithScanTasks(db, func(string, string) (int64, error) { return 1, nil }, service, nil)
	if err != nil {
		t.Fatal(err)
	}
	basePath := "/api/scan-tasks/" + strconv.FormatInt(task.ID, 10) + "/runs/" + strconv.FormatInt(run.ID, 10) + "/fingerprints"
	resources := httptest.NewRecorder()
	runHandler.ServeHTTP(resources, httptest.NewRequest(http.MethodGet, basePath, nil))
	if resources.Code != http.StatusOK || !bytes.Contains(resources.Body.Bytes(), []byte(`"evidence"`)) {
		t.Fatalf("run fingerprint resources status=%d body=%s", resources.Code, resources.Body.String())
	}

	matches := httptest.NewRecorder()
	runHandler.ServeHTTP(matches, httptest.NewRequest(http.MethodGet, basePath+"/matches?page=1&page_size=1", nil))
	if matches.Code != http.StatusOK || bytes.Contains(matches.Body.Bytes(), []byte("matcher_evidence")) || !bytes.Contains(matches.Body.Bytes(), []byte("evidence_summary")) {
		t.Fatalf("paged matches status=%d body=%s", matches.Code, matches.Body.String())
	}

	evidence := httptest.NewRecorder()
	runHandler.ServeHTTP(evidence, httptest.NewRequest(http.MethodGet, basePath+"/evidence?page=1&page_size=1", nil))
	var evidencePage struct {
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(evidence.Body.Bytes(), &evidencePage); err != nil || evidence.Code != http.StatusOK || evidencePage.Total != 1 || len(evidencePage.Items) != 1 || evidencePage.Items[0]["match_id"] == nil {
		t.Fatalf("paged evidence status=%d page=%#v err=%v body=%s", evidence.Code, evidencePage, err, evidence.Body.String())
	}

	runPage := httptest.NewRecorder()
	path := basePath + "/imports?page_size=201"
	runHandler.ServeHTTP(runPage, httptest.NewRequest(http.MethodGet, path, nil))
	if runPage.Code != http.StatusBadRequest {
		t.Fatalf("oversized run resource page status=%d body=%s", runPage.Code, runPage.Body.String())
	}
	oversizedEvidence := httptest.NewRecorder()
	runHandler.ServeHTTP(oversizedEvidence, httptest.NewRequest(http.MethodGet, basePath+"/evidence?page_size=201", nil))
	if oversizedEvidence.Code != http.StatusBadRequest {
		t.Fatalf("oversized evidence page status=%d body=%s", oversizedEvidence.Code, oversizedEvidence.Body.String())
	}
}

func TestSubnetTaskRejectsNonCIDRTarget(t *testing.T) {
	handler, err := newHandler(nil, func(string, string) (int64, error) {
		t.Fatal("task runner should not be called")
		return 0, nil
	})
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewBufferString(`{"type":"scan_subnet","target":"192.168.1.10"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusGone {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestConsoleRoutesServeTheWebApplication(t *testing.T) {
	handler, err := newHandler(nil, func(string, string) (int64, error) { return 0, nil })
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	for _, path := range []string{"/", "/tasks", "/executions", "/assets", "/reports"} {
		t.Run(path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d", recorder.Code)
			}
			if !bytes.Contains(recorder.Body.Bytes(), []byte("yscan")) {
				t.Fatalf("console response does not contain application name")
			}
			if path == "/tasks" && !bytes.Contains(recorder.Body.Bytes(), []byte("renderScanTasks")) {
				t.Fatal("tasks route must render the logical scan task view")
			}
		})
	}
}

func TestAssetAPIReturnsScopeReadModel(t *testing.T) {
	db := openAssetTestDB(t)
	const (
		scope16 = "subnet:192.168.0.0/16"
		scope24 = "subnet:192.168.10.0/24"
		ip      = "192.168.10.10"
	)
	if err := storage.SyncHostInventory(db, scope16, []string{ip}); err != nil {
		t.Fatalf("sync /16: %v", err)
	}
	if err := storage.SyncHostInventory(db, scope24, []string{ip}); err != nil {
		t.Fatalf("sync /24: %v", err)
	}
	if err := storage.SyncHostInventory(db, scope24, nil); err != nil {
		t.Fatalf("mark /24 inactive: %v", err)
	}

	handler, err := newHandler(db, func(string, string) (int64, error) { return 1, nil })
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/assets?scope="+scope24+"&active=true", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("scope asset list status = %d, body = %s", list.Code, list.Body.String())
	}
	if strings.Contains(list.Body.String(), `"source"`) {
		t.Fatalf("asset list must not expose a legacy source: %s", list.Body.String())
	}
	var assets []model.HostInventory
	if err := json.Unmarshal(list.Body.Bytes(), &assets); err != nil {
		t.Fatalf("decode asset list: %v", err)
	}
	if len(assets) != 1 || assets[0].IP != ip || !assets[0].IsActive || assets[0].ScopeCount != 2 {
		t.Fatalf("scope asset list = %#v", assets)
	}

	compatibility := httptest.NewRecorder()
	handler.ServeHTTP(compatibility, httptest.NewRequest(http.MethodGet, "/api/assets?source="+scope24, nil))
	if compatibility.Code != http.StatusOK || !strings.Contains(compatibility.Body.String(), ip) {
		t.Fatalf("source alias response = %d %s", compatibility.Code, compatibility.Body.String())
	}

	detail := httptest.NewRecorder()
	handler.ServeHTTP(detail, httptest.NewRequest(http.MethodGet, "/api/assets/"+ip, nil))
	if detail.Code != http.StatusOK {
		t.Fatalf("asset detail status = %d, body = %s", detail.Code, detail.Body.String())
	}
	var asset model.AssetDetail
	if err := json.Unmarshal(detail.Body.Bytes(), &asset); err != nil {
		t.Fatalf("decode asset detail: %v", err)
	}
	if asset.Host.ScopeCount != 2 || len(asset.Scopes) != 2 || asset.Scopes[0].Scope != scope16 || asset.Scopes[1].Scope != scope24 {
		t.Fatalf("asset detail = %#v", asset)
	}
}

func TestScanTaskAPICreatesAndManagesInternalTasks(t *testing.T) {
	db := openScanTaskAPIDB(t)
	service := schedule.NewTaskService(db, schedule.ClockFunc(func() time.Time {
		return time.Date(2026, time.July, 24, 2, 0, 0, 0, time.UTC)
	}))
	started := make(chan model.ScanTaskRun, 1)
	handler, err := newHandlerWithScanTasks(db, func(string, string) (int64, error) { return 1, nil }, service, func(_ context.Context, run model.ScanTaskRun) {
		started <- run
	})
	if err != nil {
		t.Fatalf("new scan task handler: %v", err)
	}

	scheduled := httptest.NewRecorder()
	handler.ServeHTTP(scheduled, httptest.NewRequest(http.MethodPost, "/api/scan-tasks", bytes.NewBufferString(`{"target":"192.168.10.12/24","scan_type":"subnet","mode":"scheduled","cron":"0 2 * * *","timezone":"UTC"}`)))
	if scheduled.Code != http.StatusCreated {
		t.Fatalf("create scheduled status = %d, body = %s", scheduled.Code, scheduled.Body.String())
	}
	var created createScanTaskResponse
	if err := json.Unmarshal(scheduled.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode scheduled response: %v", err)
	}
	if created.Task.Target != "192.168.10.0/24" || created.Run != nil {
		t.Fatalf("created scheduled task = %#v", created)
	}
	runNow := httptest.NewRecorder()
	handler.ServeHTTP(runNow, httptest.NewRequest(http.MethodPost, "/api/scan-tasks/"+strconv.FormatInt(created.Task.ID, 10)+"/run-now", nil))
	if runNow.Code != http.StatusAccepted || !strings.Contains(runNow.Body.String(), `"started":true`) {
		t.Fatalf("run-now response = %d %s", runNow.Code, runNow.Body.String())
	}
	select {
	case run := <-started:
		if run.ScanTaskID != created.Task.ID || run.Trigger != model.ScanTaskRunTriggerManual {
			t.Fatalf("manual run = %#v", run)
		}
	case <-time.After(time.Second):
		t.Fatal("scheduled task run-now did not request start")
	}

	pause := httptest.NewRecorder()
	handler.ServeHTTP(pause, httptest.NewRequest(http.MethodPost, "/api/scan-tasks/"+strconv.FormatInt(created.Task.ID, 10)+"/pause", nil))
	if pause.Code != http.StatusOK || !strings.Contains(pause.Body.String(), `"status":"paused"`) {
		t.Fatalf("pause response = %d %s", pause.Code, pause.Body.String())
	}

	once := httptest.NewRecorder()
	handler.ServeHTTP(once, httptest.NewRequest(http.MethodPost, "/api/scan-tasks", bytes.NewBufferString(`{"target":"192.168.10.20","scan_type":"ip","mode":"once"}`)))
	if once.Code != http.StatusCreated {
		t.Fatalf("create once status = %d, body = %s", once.Code, once.Body.String())
	}
	select {
	case run := <-started:
		if run.ScanType != model.ScanTypeIP || run.Target != "192.168.10.20" {
			t.Fatalf("started run = %#v", run)
		}
	case <-time.After(time.Second):
		t.Fatal("one-time API task did not request run start")
	}

	public := httptest.NewRecorder()
	handler.ServeHTTP(public, httptest.NewRequest(http.MethodPost, "/api/scan-tasks", bytes.NewBufferString(`{"target":"8.8.8.8","scan_type":"ip","mode":"once"}`)))
	if public.Code != http.StatusBadRequest {
		t.Fatalf("public IP task status = %d, body = %s", public.Code, public.Body.String())
	}

	for _, body := range []string{
		`{"target":"not-an-ip","scan_type":"ip","mode":"once"}`,
		`{"target":"192.168.10.0/24","scan_type":"subnet","mode":"scheduled","cron":"@every 1m","timezone":"UTC"}`,
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/scan-tasks", bytes.NewBufferString(body)))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid schedule task status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestHealthCheckAndRunStarterUseServiceContext(t *testing.T) {
	db := openScanTaskAPIDB(t)
	service := schedule.NewTaskService(db, nil)
	serviceContext, cancel := context.WithCancel(context.Background())
	started := make(chan context.Context, 1)
	handler, err := newHandlerWithScanTasksContext(serviceContext, db, func(string, string) (int64, error) { return 1, nil }, service, func(ctx context.Context, _ model.ScanTaskRun) {
		started <- ctx
	})
	if err != nil {
		t.Fatal(err)
	}
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/healthz", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"status":"ok"`) {
		t.Fatalf("health response=%d %s", health.Code, health.Body.String())
	}
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, httptest.NewRequest(http.MethodPost, "/api/scan-tasks", bytes.NewBufferString(`{"target":"127.0.0.1","scan_type":"ip","mode":"once","config":{"port_spec":"80"}}`)))
	if created.Code != http.StatusCreated {
		t.Fatalf("create response=%d %s", created.Code, created.Body.String())
	}
	var runContext context.Context
	select {
	case runContext = <-started:
	case <-time.After(time.Second):
		t.Fatal("run starter was not called")
	}
	cancel()
	select {
	case <-runContext.Done():
	case <-time.After(time.Second):
		t.Fatal("run starter context did not follow service shutdown")
	}
}

func TestScanTaskRunChangesAPIStaysWithinLogicalTask(t *testing.T) {
	db := openScanTaskAPIDB(t)
	service := schedule.NewTaskService(db, schedule.ClockFunc(func() time.Time {
		return time.Date(2026, time.July, 24, 2, 0, 0, 0, time.UTC)
	}))
	handler, err := newHandlerWithScanTasks(db, func(string, string) (int64, error) { return 1, nil }, service, nil)
	if err != nil {
		t.Fatalf("new scan task handler: %v", err)
	}

	task, _, err := service.Create(context.Background(), model.ScanTask{
		Target:   "192.168.40.0/24",
		ScanType: model.ScanTypeSubnet,
		Mode:     model.ScanTaskModeScheduled,
		Cron:     "0 2 * * *",
		Timezone: "UTC",
	})
	if err != nil {
		t.Fatalf("create logical task: %v", err)
	}
	first := createCompletedScanTaskRunForAPI(t, db, task.ID, "2026-07-24T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.40.10", IsActive: true}},
		Ports: []model.ScanTaskRunPort{{IP: "192.168.40.10", Port: 80, ServiceType: "http"}},
	})
	second := createCompletedScanTaskRunForAPI(t, db, task.ID, "2026-07-25T02:00:00Z", model.ScanTaskRunSnapshot{
		Hosts: []model.ScanTaskRunHost{{IP: "192.168.40.10", IsActive: true}, {IP: "192.168.40.11", IsActive: true}},
		Ports: []model.ScanTaskRunPort{{IP: "192.168.40.10", Port: 443, ServiceType: "https"}},
	})

	changesResponse := httptest.NewRecorder()
	changesPath := "/api/scan-tasks/" + strconv.FormatInt(task.ID, 10) + "/runs/" + strconv.FormatInt(second.ID, 10) + "/changes"
	handler.ServeHTTP(changesResponse, httptest.NewRequest(http.MethodGet, changesPath, nil))
	if changesResponse.Code != http.StatusOK {
		t.Fatalf("default changes status = %d, body = %s", changesResponse.Code, changesResponse.Body.String())
	}
	var changes model.ScanTaskRunChanges
	if err := json.Unmarshal(changesResponse.Body.Bytes(), &changes); err != nil {
		t.Fatalf("decode changes: %v", err)
	}
	if changes.BaselineRunID != first.ID || changes.CurrentRunID != second.ID || len(changes.HostChanges.NewHosts) != 1 || changes.HostChanges.NewHosts[0] != "192.168.40.11" {
		t.Fatalf("unexpected changes = %#v", changes)
	}

	explicitResponse := httptest.NewRecorder()
	handler.ServeHTTP(explicitResponse, httptest.NewRequest(http.MethodGet, changesPath+"?baseline_run_id="+strconv.FormatInt(first.ID, 10), nil))
	if explicitResponse.Code != http.StatusOK {
		t.Fatalf("explicit changes status = %d, body = %s", explicitResponse.Code, explicitResponse.Body.String())
	}

	otherTask, _, err := service.Create(context.Background(), model.ScanTask{
		Target:   "192.168.41.0/24",
		ScanType: model.ScanTypeSubnet,
		Mode:     model.ScanTaskModeScheduled,
		Cron:     "0 2 * * *",
		Timezone: "UTC",
	})
	if err != nil {
		t.Fatalf("create other task: %v", err)
	}
	otherRun := createCompletedScanTaskRunForAPI(t, db, otherTask.ID, "2026-07-24T02:00:00Z", model.ScanTaskRunSnapshot{})
	crossTaskResponse := httptest.NewRecorder()
	handler.ServeHTTP(crossTaskResponse, httptest.NewRequest(http.MethodGet, changesPath+"?baseline_run_id="+strconv.FormatInt(otherRun.ID, 10), nil))
	if crossTaskResponse.Code != http.StatusBadRequest {
		t.Fatalf("cross-task baseline status = %d, body = %s", crossTaskResponse.Code, crossTaskResponse.Body.String())
	}
}

func TestScanTaskAPIUpdatesFutureConfigAndCancelsOnlyOwnedRun(t *testing.T) {
	db := openScanTaskAPIDB(t)
	service := schedule.NewTaskService(db, nil)
	handler, err := newHandlerWithScanTasks(db, func(string, string) (int64, error) { return 1, nil }, service, nil)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	task, _, err := service.Create(context.Background(), model.ScanTask{Target: "192.168.50.0/24", ScanType: model.ScanTypeSubnet, Mode: model.ScanTaskModeScheduled, Cron: "0 2 * * *", Timezone: "UTC"})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	queued, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-24T02:00:00Z"})
	if err != nil {
		t.Fatalf("create queued run: %v", err)
	}
	update := httptest.NewRecorder()
	handler.ServeHTTP(update, httptest.NewRequest(http.MethodPut, "/api/scan-tasks/"+strconv.FormatInt(task.ID, 10), bytes.NewBufferString(`{"target":"192.168.51.7/24","scan_type":"subnet","mode":"scheduled","cron":"30 3 * * *","timezone":"Asia/Shanghai","config":{"port_spec":"443"}}`)))
	if update.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", update.Code, update.Body.String())
	}
	preserved, err := storage.GetScanTaskRun(db, queued.ID)
	if err != nil || preserved.Target != "192.168.50.0/24" {
		t.Fatalf("queued snapshot=%#v err=%v", preserved, err)
	}
	cancel := httptest.NewRecorder()
	handler.ServeHTTP(cancel, httptest.NewRequest(http.MethodPost, "/api/scan-tasks/"+strconv.FormatInt(task.ID, 10)+"/runs/"+strconv.FormatInt(queued.ID, 10)+"/cancel", nil))
	if cancel.Code != http.StatusOK {
		t.Fatalf("cancel status=%d body=%s", cancel.Code, cancel.Body.String())
	}
	other, _, err := service.Create(context.Background(), model.ScanTask{Target: "192.168.52.0/24", ScanType: model.ScanTypeSubnet, Mode: model.ScanTaskModeScheduled, Cron: "0 2 * * *", Timezone: "UTC"})
	if err != nil {
		t.Fatalf("create other task: %v", err)
	}
	cross := httptest.NewRecorder()
	handler.ServeHTTP(cross, httptest.NewRequest(http.MethodPost, "/api/scan-tasks/"+strconv.FormatInt(other.ID, 10)+"/runs/"+strconv.FormatInt(queued.ID, 10)+"/cancel", nil))
	if cross.Code != http.StatusNotFound {
		t.Fatalf("cross-task cancel status=%d body=%s", cross.Code, cross.Body.String())
	}
}

func TestScanTaskRunReportAPIIsTaskScopedAndReturnsDiagnostics(t *testing.T) {
	db := openScanTaskAPIDB(t)
	service := schedule.NewTaskService(db, nil)
	handler, err := newHandlerWithScanTasks(db, func(string, string) (int64, error) { return 1, nil }, service, nil)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	task, _, err := service.Create(context.Background(), model.ScanTask{Target: "192.168.70.10", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	runs, err := storage.ListScanTaskRuns(db, task.ID)
	if err != nil || len(runs) != 1 {
		t.Fatalf("list runs=%#v err=%v", runs, err)
	}
	run := runs[0]
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ?, finished_at = datetime('now') WHERE id = ?`, model.ScanTaskRunStatusSuccess, run.ID); err != nil {
		t.Fatalf("finish run: %v", err)
	}
	if err := storage.UpdateScanTaskRunReportError(db, run.ID, "report directory is read-only"); err != nil {
		t.Fatalf("save report error: %v", err)
	}
	detail := httptest.NewRecorder()
	detailPath := "/api/scan-tasks/" + strconv.FormatInt(task.ID, 10) + "/runs/" + strconv.FormatInt(run.ID, 10)
	handler.ServeHTTP(detail, httptest.NewRequest(http.MethodGet, detailPath, nil))
	if detail.Code != http.StatusOK || !strings.Contains(detail.Body.String(), `"report_error":"report directory is read-only"`) {
		t.Fatalf("run detail=%d %s", detail.Code, detail.Body.String())
	}

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("change working directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(workingDirectory) })
	if _, err := report.WriteScanTaskRunReport(report.DefaultDirectory, report.ScanTaskRunReport{Task: task, Run: model.ScanTaskRun{ID: run.ID, ScanTaskID: task.ID, Status: model.ScanTaskRunStatusSuccess}}); err != nil {
		t.Fatalf("write report: %v", err)
	}
	reportResponse := httptest.NewRecorder()
	handler.ServeHTTP(reportResponse, httptest.NewRequest(http.MethodGet, detailPath+"/report", nil))
	if reportResponse.Code != http.StatusOK || !strings.Contains(reportResponse.Body.String(), "yscan CAASM Scan Task Run Report") {
		t.Fatalf("report response=%d %s", reportResponse.Code, reportResponse.Body.String())
	}
	auditResponse := httptest.NewRecorder()
	handler.ServeHTTP(auditResponse, httptest.NewRequest(http.MethodGet, detailPath+"/audit-report", nil))
	if auditResponse.Code != http.StatusOK || !strings.Contains(auditResponse.Body.String(), "yscan CAASM Scan Task Run Audit Report") {
		t.Fatalf("audit report response=%d %s", auditResponse.Code, auditResponse.Body.String())
	}
	other, _, err := service.Create(context.Background(), model.ScanTask{Target: "192.168.70.11", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce})
	if err != nil {
		t.Fatalf("create other task: %v", err)
	}
	crossTask := httptest.NewRecorder()
	handler.ServeHTTP(crossTask, httptest.NewRequest(http.MethodGet, "/api/scan-tasks/"+strconv.FormatInt(other.ID, 10)+"/runs/"+strconv.FormatInt(run.ID, 10)+"/report", nil))
	if crossTask.Code != http.StatusNotFound {
		t.Fatalf("cross-task report=%d %s", crossTask.Code, crossTask.Body.String())
	}
}

func TestScanTaskRunFindingsAPIReportsValidationStateAndPaginates(t *testing.T) {
	db := openScanTaskAPIDB(t)
	service := schedule.NewTaskService(db, nil)
	handler, err := newHandlerWithScanTasks(db, func(string, string) (int64, error) { return 1, nil }, service, nil)
	if err != nil {
		t.Fatal(err)
	}
	task, _, err := service.Create(context.Background(), model.ScanTask{Target: "192.168.71.0/24", ScanType: model.ScanTypeSubnet, Mode: model.ScanTaskModeScheduled, Cron: "0 2 * * *", Timezone: "UTC", Config: model.ScanTaskConfig{VulnerabilityOn: true}})
	if err != nil {
		t.Fatal(err)
	}
	run := createCompletedScanTaskRunForAPI(t, db, task.ID, "2026-07-24T02:00:00Z", model.ScanTaskRunSnapshot{
		Validation: model.ScanTaskRunValidation{Status: model.ScanTaskRunValidationSuccess, CandidateEndpointCount: 2, ExecutedEndpointCount: 2, TemplateCount: 3, FindingCount: 2},
		Vulnerabilities: []model.ScanTaskRunVulnerability{
			{FindingKey: "one", TemplateID: "one", Name: "One", Severity: "high", Target: "https://192.168.71.10"},
			{FindingKey: "two", TemplateID: "two", Name: "Two", Severity: "medium", Target: "https://192.168.71.11", Description: "Readable API description", Evidence: `{"raw":"nuclei-json"}`},
		},
	})
	response := httptest.NewRecorder()
	path := fmt.Sprintf("/api/scan-tasks/%d/runs/%d/findings?page=2&page_size=1", task.ID, run.ID)
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("findings status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Validation model.ScanTaskRunValidation      `json:"validation"`
		Items      []model.ScanTaskRunVulnerability `json:"items"`
		Total      int                              `json:"total"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Validation.Status != model.ScanTaskRunValidationSuccess || result.Total != 2 || len(result.Items) != 1 || result.Items[0].FindingKey != "two" || result.Items[0].Description != "Readable API description" {
		t.Fatalf("unexpected findings response: %#v", result)
	}
	if strings.Contains(response.Body.String(), "nuclei-json") || strings.Contains(response.Body.String(), "\"evidence\"") {
		t.Fatalf("findings API exposed raw nuclei JSON: %s", response.Body.String())
	}
}

func createCompletedScanTaskRunForAPI(t *testing.T, db *sql.DB, taskID int64, scheduledFor string, snapshot model.ScanTaskRunSnapshot) model.ScanTaskRun {
	t.Helper()
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: taskID, ScheduledFor: scheduledFor})
	if err != nil {
		t.Fatalf("create scan task run: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ? WHERE id = ?`, model.ScanTaskRunStatusRunning, run.ID); err != nil {
		t.Fatalf("start scan task run: %v", err)
	}
	snapshot.RunID = run.ID
	if err := storage.SaveScanTaskRunSnapshot(db, snapshot); err != nil {
		t.Fatalf("save scan task run snapshot: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ?, finished_at = datetime('now') WHERE id = ?`, model.ScanTaskRunStatusSuccess, run.ID); err != nil {
		t.Fatalf("finish scan task run: %v", err)
	}
	return run
}

func openAssetTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	for _, statement := range []string{
		`CREATE TABLE host_inventory (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL UNIQUE, source TEXT, first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL, last_scan DATETIME, is_active INTEGER NOT NULL DEFAULT 1)`,
		`CREATE TABLE host_inventory_scopes (scope TEXT NOT NULL, ip TEXT NOT NULL, first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL, last_checked DATETIME NOT NULL, is_active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (scope, ip))`,
		`CREATE TABLE scan_results (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, port INTEGER NOT NULL, service_type TEXT NOT NULL, scan_time DATETIME, UNIQUE(ip, port))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create asset test schema: %v", err)
		}
	}
	return db
}

func openScanTaskAPIDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, scan_type TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL, cron TEXT, timezone TEXT, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, archived_at DATETIME)`,
		`CREATE TABLE scan_task_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_task_id INTEGER NOT NULL, sequence INTEGER NOT NULL, scheduled_for DATETIME NOT NULL, status TEXT NOT NULL, trigger TEXT NOT NULL DEFAULT 'scheduled', stage TEXT NOT NULL DEFAULT 'queued', progress INTEGER NOT NULL DEFAULT 0, target TEXT NOT NULL, scan_type TEXT NOT NULL, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', error_message TEXT, report_path TEXT, audit_report_path TEXT, report_error TEXT, started_at DATETIME, finished_at DATETIME, snapshot_written_at DATETIME, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL, UNIQUE(scan_task_id, sequence), UNIQUE(scan_task_id, scheduled_for))`,
		`CREATE TABLE scan_task_run_hosts (scan_task_run_id INTEGER NOT NULL, ip TEXT NOT NULL, is_active INTEGER NOT NULL, PRIMARY KEY(scan_task_run_id, ip))`,
		`CREATE TABLE scan_task_run_ports (scan_task_run_id INTEGER NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, service_type TEXT NOT NULL, product TEXT, banner TEXT, PRIMARY KEY(scan_task_run_id, ip, port))`,
		`CREATE TABLE scan_task_run_protocol_evidence (scan_task_run_id INTEGER NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL, evidence_type TEXT NOT NULL, probe_name TEXT NOT NULL DEFAULT '', protocol TEXT NOT NULL, responded INTEGER NOT NULL DEFAULT 0, outcome TEXT NOT NULL DEFAULT '', diagnostic TEXT NOT NULL DEFAULT '', status_code INTEGER, server TEXT, title TEXT, banner_captured_length INTEGER NOT NULL DEFAULT 0, banner_sha256 TEXT, banner_truncated INTEGER NOT NULL DEFAULT 0, header_captured_length INTEGER NOT NULL DEFAULT 0, header_sha256 TEXT, header_truncated INTEGER NOT NULL DEFAULT 0, body_captured_length INTEGER NOT NULL DEFAULT 0, body_sha256 TEXT, body_truncated INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(scan_task_run_id, ip, port, evidence_type, protocol, probe_name))`,
		`CREATE TABLE scan_task_run_validation (scan_task_run_id INTEGER PRIMARY KEY, status TEXT NOT NULL, identified_product_count INTEGER NOT NULL DEFAULT 0, mapped_product_count INTEGER NOT NULL DEFAULT 0, unmapped_products_json TEXT NOT NULL DEFAULT '[]', candidate_endpoint_count INTEGER NOT NULL DEFAULT 0, executed_endpoint_count INTEGER NOT NULL DEFAULT 0, template_count INTEGER NOT NULL DEFAULT 0, executed_template_count INTEGER NOT NULL DEFAULT 0, finding_count INTEGER NOT NULL DEFAULT 0, started_at TEXT, finished_at TEXT, error_message TEXT)`,
		`CREATE TABLE scan_task_run_vulnerabilities (scan_task_run_id INTEGER NOT NULL, finding_key TEXT NOT NULL, template_id TEXT, name TEXT, severity TEXT, target TEXT NOT NULL, target_ip TEXT, target_port INTEGER, matched_at TEXT, description TEXT, evidence TEXT, PRIMARY KEY(scan_task_run_id, finding_key))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create scan task API schema: %v", err)
		}
	}
	return db
}
