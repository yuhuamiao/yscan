package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/planner"
	"golandproject/yscan/internal/report"
	"golandproject/yscan/internal/schedule"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/workflow"
)

func TestT322PreviousDatabaseFivePortUserJourney(t *testing.T) {
	workspace := t.TempDir()
	databasePath := filepath.Join(workspace, "previous-v2.db")
	db, err := storage.InitDBAt(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join("..", "storage", "testdata", "m11-v2-before-t320.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(fixture)); err != nil {
		t.Fatalf("load previous V2 database fixture: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = storage.InitDBAt(databasePath)
	if err != nil {
		t.Fatalf("upgrade previous V2 database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	servers := make([]*httptest.Server, 0, 5)
	for index := 0; index < 5; index++ {
		index := index
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "nginx/1.27.5")
			w.WriteHeader([]int{200, 201, 403, 404, 500}[index])
			_, _ = fmt.Fprintf(w, "<html><title>T322 endpoint %d</title><body>five-port-response</body></html>", index)
		})
		var server *httptest.Server
		if index == 4 {
			server = httptest.NewTLSServer(handler)
		} else {
			server = httptest.NewServer(handler)
		}
		servers = append(servers, server)
		t.Cleanup(server.Close)
	}
	ports := make([]int, 0, len(servers))
	securePort := 0
	for index, server := range servers {
		port, err := strconv.Atoi(server.URL[strings.LastIndexByte(server.URL, ':')+1:])
		if err != nil {
			t.Fatalf("parse fixture port from %s: %v", server.URL, err)
		}
		ports = append(ports, port)
		if index == 4 {
			securePort = port
		}
	}
	sort.Ints(ports)

	templateRoot := filepath.Join(workspace, "templates")
	if err := os.MkdirAll(templateRoot, 0750); err != nil {
		t.Fatal(err)
	}
	fixtureTemplate := []byte(`id: t322-process-fixture
info:
  name: T322 read-only process fixture
  severity: medium
  metadata:
    product:
      - http
      - https
  tags: nginx,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - five-port-response
`)
	if err := os.WriteFile(filepath.Join(templateRoot, "fixture.yaml"), fixtureTemplate, 0600); err != nil {
		t.Fatal(err)
	}
	templateIndex, err := planner.BuildNucleiTemplateIndex(templateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(templateIndex.Templates) != 1 || len(templateIndex.Select("http", "", "http")) != 1 || len(templateIndex.Select("https", "", "https")) != 1 {
		t.Fatalf("strict T322 template projection=%#v", templateIndex.Templates)
	}
	installT322NucleiProcessFixture(t, workspace)

	service := schedule.NewTaskService(db, schedule.ClockFunc(func() time.Time {
		return time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	}))
	portValues := make([]string, len(ports))
	for index, port := range ports {
		portValues[index] = strconv.Itoa(port)
	}
	task, run, err := service.Create(context.Background(), model.ScanTask{
		Target: "127.0.0.1", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce,
		Config: model.ScanTaskConfig{PortSpec: strings.Join(portValues, ","), VulnerabilityOn: true, NucleiTemplates: templateRoot, TemplateVersion: "t322-fixture-v1"},
	})
	if err != nil || run == nil {
		t.Fatalf("create T322 task task=%#v run=%#v err=%v", task, run, err)
	}
	executor := schedule.NewExecutor(db, workflow.NewTargetTaskRunExecutor(workflow.TargetTaskRunOptions{DB: db, Run: *run, Network: "tcp"}))
	if err := executor.ExecuteRun(context.Background(), run.ID); err != nil {
		t.Fatalf("execute T322 task: %v", err)
	}

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workspace); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(workingDirectory) })
	if _, err := report.GenerateScanTaskRunReport(db, task.ID, run.ID, report.DefaultDirectory); err != nil {
		t.Fatalf("generate T322 report pair: %v", err)
	}

	handler, err := newHandlerWithScanTasks(db, func(string, string) (int64, error) { return 1, nil }, service, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	assetBody := t322HTTPBody(t, server.URL+"/api/assets/127.0.0.1")
	var asset model.AssetDetail
	if err := json.Unmarshal(assetBody, &asset); err != nil {
		t.Fatal(err)
	}
	if len(asset.Ports) != 5 {
		t.Fatalf("asset ports=%#v", asset.Ports)
	}
	for _, port := range asset.Ports {
		webResponse := false
		for _, evidence := range port.ProtocolEvidence {
			webResponse = webResponse || (evidence.EvidenceType == model.ProtocolEvidenceWeb && evidence.Responded && evidence.StatusCode > 0 && evidence.Server != "" && evidence.Title != "" && evidence.BodyCapturedLength > 0)
			if port.Port == securePort && evidence.EvidenceType == model.ProtocolEvidenceWeb && evidence.Protocol != "https" {
				t.Fatalf("secure endpoint evidence=%#v", evidence)
			}
		}
		if !webResponse {
			t.Fatalf("port %d has no complete Web response: %#v", port.Port, port.ProtocolEvidence)
		}
	}

	baseRunPath := fmt.Sprintf("/api/scan-tasks/%d/runs/%d", task.ID, run.ID)
	findingsBody := t322HTTPBody(t, server.URL+baseRunPath+"/findings?page=1&page_size=100")
	var findings struct {
		Validation model.ScanTaskRunValidation      `json:"validation"`
		Items      []model.ScanTaskRunVulnerability `json:"items"`
		Total      int                              `json:"total"`
	}
	if err := json.Unmarshal(findingsBody, &findings); err != nil {
		t.Fatal(err)
	}
	if findings.Validation.Status != model.ScanTaskRunValidationSuccess || findings.Validation.ExecutedEndpointCount != 5 || findings.Total != 5 || len(findings.Items) != 5 {
		t.Fatalf("T322 findings=%#v", findings)
	}
	if strings.Contains(string(findingsBody), `"evidence"`) || !strings.Contains(string(findingsBody), "T322 process-level finding") {
		t.Fatalf("unsafe or incomplete findings API: %s", findingsBody)
	}

	page := string(t322HTTPBody(t, server.URL+"/assets"))
	userReport := string(t322HTTPBody(t, server.URL+baseRunPath+"/report"))
	auditReport := string(t322HTTPBody(t, server.URL+baseRunPath+"/audit-report"))
	if !strings.Contains(page, "showAssetDetail") || !strings.Contains(page, "protocol_evidence") {
		t.Fatalf("asset page is not wired to structured protocol evidence")
	}
	for _, expected := range []string{"T322 process-level finding", "Validation executed successfully", "nginx"} {
		if !strings.Contains(userReport, expected) {
			t.Fatalf("user report missing %q", expected)
		}
	}
	if strings.Contains(userReport, `{"template-id"`) || !strings.Contains(auditReport, "Frozen Fingerprint Revisions") || !strings.Contains(auditReport, "m11-v2-projection") {
		t.Fatalf("report boundary user=%q audit=%q", userReport, auditReport)
	}
}

func installT322NucleiProcessFixture(t *testing.T, directory string) {
	t.Helper()
	binDirectory := filepath.Join(directory, "bin")
	if err := os.MkdirAll(binDirectory, 0750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(binDirectory, "nuclei")
	script := `#!/bin/sh
target_file=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-l" ]; then
    shift
    target_file="$1"
  fi
  shift
done
target=$(sed -n '1p' "$target_file")
printf '{"template-id":"t322-process-fixture","type":"http","host":"%s","matched-at":"%s","info":{"name":"T322 Fixture","severity":"medium","description":"T322 process-level finding"}}\n' "$target" "$target"
`
	if err := os.WriteFile(path, []byte(script), 0750); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func t322HTTPBody(t *testing.T, url string) []byte {
	t.Helper()
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status=%d body=%s", url, response.StatusCode, body)
	}
	return body
}
