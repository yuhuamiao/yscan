package workflow

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golandproject/yscan/internal/fingerprint"
	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/report"
	"golandproject/yscan/internal/schedule"
	"golandproject/yscan/internal/storage"
)

func TestT293RealLegacyUpgradeAndScan(t *testing.T) {
	if os.Getenv("YSCAN_REAL_E2E") != "1" {
		t.Skip("set YSCAN_REAL_E2E=1 to run the real protocol and Nuclei acceptance")
	}
	if _, err := exec.LookPath("nuclei"); err != nil {
		t.Fatalf("real T293 acceptance requires nuclei in PATH: %v", err)
	}

	databasePath := createLegacyDatabaseCopy(t)
	db, err := storage.InitDBAt(databasePath)
	if err != nil {
		t.Fatalf("upgrade v1/M10 database copy: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := fingerprint.BootstrapEmbeddedSources(context.Background(), db); err != nil {
		t.Fatalf("bootstrap embedded sources on upgraded database: %v", err)
	}
	assertLegacyUpgradeAndSourceBootstrap(t, db)

	httpServer := httptest.NewServer(jenkinsFixtureHandler())
	t.Cleanup(httpServer.Close)
	httpsServer := httptest.NewTLSServer(jenkinsFixtureHandler())
	t.Cleanup(httpsServer.Close)
	nginxServer := httptest.NewServer(fingerprintFixtureHandler("nginx/1.25.4", "<html><title>nginx</title></html>"))
	t.Cleanup(nginxServer.Close)
	harborServer := httptest.NewServer(fingerprintFixtureHandler("", "<html><title>Harbor</title></html>"))
	t.Cleanup(harborServer.Close)
	seeyonServer := httptest.NewServer(fingerprintFixtureHandler("", `<html><body><script src="/seeyon/common/app.js"></script></body></html>`))
	t.Cleanup(seeyonServer.Close)
	httpPort := serverPort(t, httpServer.URL)
	httpsPort := serverPort(t, httpsServer.URL)
	nginxPort := serverPort(t, nginxServer.URL)
	harborPort := serverPort(t, harborServer.URL)
	seeyonPort := serverPort(t, seeyonServer.URL)
	sshPort, closeSSH := startTCPFixture(t, "SSH-2.0-OpenSSH_9.6 FreeBSD-14\r\n", false)
	t.Cleanup(closeSSH)
	mysqlPort, closeMySQL := startTCPFixture(t, "\x15\x00\x00\x00\x0a5.7.44\x00", false)
	t.Cleanup(closeMySQL)

	verifyRedirectBoundaryWithRealServers(t, httpServer.URL)
	templateRoot := filepath.Join("testdata", "t293", "templates")
	templateName := "caasm-t293-local.yaml"
	importReviewedTemplateMapping(t, db, templateRoot, templateName)

	service := schedule.NewTaskService(db, schedule.ClockFunc(func() time.Time {
		return time.Date(2026, 8, 6, 1, 0, 0, 0, time.UTC)
	}))
	task, run, err := service.Create(context.Background(), model.ScanTask{
		Target:   "127.0.0.1",
		ScanType: model.ScanTypeIP,
		Mode:     model.ScanTaskModeOnce,
		Status:   model.ScanTaskStatusEnabled,
		Config: model.ScanTaskConfig{
			PortSpec:        fmt.Sprintf("%d,%d,%d,%d,%d,%d,%d", httpPort, httpsPort, nginxPort, harborPort, seeyonPort, sshPort, mysqlPort),
			VulnerabilityOn: true,
			NucleiTemplates: templateRoot,
			TemplateVersion: "t293-local-v1",
		},
	})
	if err != nil || run == nil {
		t.Fatalf("create real target task: task=%#v run=%#v err=%v", task, run, err)
	}
	executor := schedule.NewExecutor(db, NewTargetTaskRunExecutor(TargetTaskRunOptions{DB: db, Run: *run, Network: "tcp"}))
	if err := executor.ExecuteRun(context.Background(), run.ID); err != nil {
		t.Fatalf("execute real scan: %v", err)
	}
	reportDirectory := filepath.Join(t.TempDir(), "reports")
	reportPath, err := report.GenerateScanTaskRunReport(db, task.ID, run.ID, reportDirectory)
	if err != nil {
		t.Fatalf("generate successful run report: %v", err)
	}
	if err := executor.FinalizeSuccessfulRun(run.ID, ""); err != nil {
		t.Fatalf("finalize successful run: %v", err)
	}
	assertSuccessfulRealRun(t, db, task, run.ID, httpPort, httpsPort, nginxPort, harborPort, seeyonPort, sshPort, mysqlPort)
	assertAuditReport(t, reportPath, false)
	verifyCanceledPartialRun(t, db, reportDirectory)
}

func TestT293RealProductServices(t *testing.T) {
	if os.Getenv("YSCAN_PRODUCT_E2E") != "1" {
		t.Skip("set YSCAN_PRODUCT_E2E=1 after starting the fixed T293 product compose stack")
	}
	if _, err := exec.LookPath("nuclei"); err != nil {
		t.Fatalf("real-product T293 acceptance requires nuclei in PATH: %v", err)
	}
	const target = "127.0.0.1"
	ports := []int{22, 80, 443, 3306, 6379, 8080}
	for _, port := range ports {
		connection, err := net.DialTimeout("tcp", net.JoinHostPort(target, strconv.Itoa(port)), time.Second)
		if err != nil {
			t.Fatalf("T293 product endpoint %s:%d is unavailable: %v", target, port, err)
		}
		_ = connection.Close()
	}

	databasePath := createLegacyDatabaseCopy(t)
	db, err := storage.InitDBAt(databasePath)
	if err != nil {
		t.Fatalf("upgrade v1/M10 database copy: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := fingerprint.BootstrapEmbeddedSources(context.Background(), db); err != nil {
		t.Fatalf("bootstrap embedded sources: %v", err)
	}
	assertLegacyUpgradeAndSourceBootstrap(t, db)
	templateRoot := filepath.Join("testdata", "t293", "templates")
	importReviewedTemplateMapping(t, db, templateRoot, "caasm-t293-local.yaml")
	service := schedule.NewTaskService(db, schedule.ClockFunc(func() time.Time {
		return time.Date(2026, 8, 6, 2, 0, 0, 0, time.UTC)
	}))
	task, run, err := service.Create(context.Background(), model.ScanTask{
		Target: target, ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce, Status: model.ScanTaskStatusEnabled,
		Config: model.ScanTaskConfig{PortSpec: "22,80,443,3306,6379,8080", VulnerabilityOn: true, NucleiTemplates: templateRoot, TemplateVersion: "t293-products-v1"},
	})
	if err != nil || run == nil {
		t.Fatalf("create product task: task=%#v run=%#v err=%v", task, run, err)
	}
	executor := schedule.NewExecutor(db, NewTargetTaskRunExecutor(TargetTaskRunOptions{DB: db, Run: *run, Network: "tcp"}))
	if err := executor.ExecuteRun(context.Background(), run.ID); err != nil {
		t.Fatalf("execute product scan: %v", err)
	}
	reportPath, err := report.GenerateScanTaskRunReport(db, task.ID, run.ID, filepath.Join(t.TempDir(), "reports"))
	if err != nil {
		t.Fatalf("generate product report: %v", err)
	}
	if err := executor.FinalizeSuccessfulRun(run.ID, ""); err != nil {
		t.Fatalf("finalize product run: %v", err)
	}
	assertRealProductRun(t, db, task, run.ID)
	assertAuditReport(t, reportPath, false)
}

func assertRealProductRun(t *testing.T, db *sql.DB, task model.ScanTask, runID int64) {
	t.Helper()
	run, err := storage.GetScanTaskRun(db, runID)
	if err != nil || run.Status != model.ScanTaskRunStatusSuccess {
		t.Fatalf("product run=%#v err=%v", run, err)
	}
	matches, err := storage.ListFingerprintRunMatches(db, runID)
	if err != nil {
		t.Fatal(err)
	}
	wants := map[int]string{22: "openssh", 80: "jenkins", 443: "nginx", 3306: "mysql", 6379: "redis", 8080: "nginx"}
	found := make(map[int]bool)
	activeRedisProbe, versionedSSH, versionedMySQL := false, false, false
	for _, match := range matches {
		port, _ := match["port"].(int)
		product, _ := match["product_key"].(string)
		if product == wants[port] {
			found[port] = true
		}
		summary, _ := match["evidence_summary"].(string)
		activeRedisProbe = activeRedisProbe || (port == 6379 && product == "redis" && strings.Contains(summary, "tcp probe=redis-server"))
		version, _ := match["version"].(string)
		cpe, _ := match["cpe"].(string)
		versionedSSH = versionedSSH || (port == 22 && product == "openssh" && version != "" && strings.Contains(cpe, "openssh"))
		versionedMySQL = versionedMySQL || (port == 3306 && product == "mysql" && version != "" && strings.Contains(cpe, "mysql"))
	}
	for port, product := range wants {
		if !found[port] {
			t.Fatalf("real %s fingerprint missing on port %d; matches=%#v", product, port, matches)
		}
	}
	if !activeRedisProbe || !versionedSSH || !versionedMySQL {
		t.Fatalf("product metadata/probe active_redis=%t ssh_version=%t mysql_version=%t", activeRedisProbe, versionedSSH, versionedMySQL)
	}
	snapshot, err := storage.GetScanTaskRunSnapshot(db, runID)
	if err != nil {
		t.Fatal(err)
	}
	activeProbeEvidence := false
	for _, evidence := range snapshot.ProtocolEvidence {
		activeProbeEvidence = activeProbeEvidence || (evidence.Port == 6379 && evidence.EvidenceType == model.ProtocolEvidenceActiveProbe && evidence.ProbeName != "" && evidence.Responded && evidence.BannerCapturedLength > 0)
	}
	if !activeProbeEvidence {
		t.Fatalf("active probe response was not preserved in protocol evidence: %#v", snapshot.ProtocolEvidence)
	}
	finding, candidate := false, false
	for _, value := range snapshot.Vulnerabilities {
		finding = finding || (value.TemplateID == "caasm-t293-local" && value.TargetPort == 80)
	}
	for _, value := range snapshot.TemplateCandidates {
		candidate = candidate || (value.TemplateID == "caasm-t293-local" && value.IP == task.Target && value.Port == 80 && value.Protocol == "http")
	}
	if !finding || !candidate {
		t.Fatalf("real product validation findings=%#v candidates=%#v", snapshot.Vulnerabilities, snapshot.TemplateCandidates)
	}
}

func createLegacyDatabaseCopy(t *testing.T) string {
	t.Helper()
	temporary := t.TempDir()
	seedPath := filepath.Join(temporary, "m10-seed.db")
	schema, err := os.ReadFile(filepath.Join("testdata", "t293", "m10-legacy.sql"))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := sql.Open("sqlite3", seedPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Exec(string(schema)); err != nil {
		_ = seed.Close()
		t.Fatalf("create v1/M10 seed database: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(temporary, "asm.db")
	if err := os.WriteFile(copyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return copyPath
}

func assertLegacyUpgradeAndSourceBootstrap(t *testing.T, db *sql.DB) {
	t.Helper()
	var legacyBanner, bannerTotal, legacyRun, activeImports, rawRules int
	if err := db.QueryRow(`SELECT COUNT(*) FROM banner WHERE id = 9001 AND service_name = 'legacy-t293-ssh' AND banner_pattern = 'OpenSSH_9.6'`).Scan(&legacyBanner); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM scan_task_runs WHERE id = 1 AND status = 'success' AND config_hash = 'm10-fixture-config'`).Scan(&legacyRun); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM banner`).Scan(&bannerTotal); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports WHERE is_active = 1`).Scan(&activeImports); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT SUM(rule_total) FROM fingerprint_imports WHERE is_active = 1`).Scan(&rawRules); err != nil {
		t.Fatal(err)
	}
	if legacyBanner != 1 || legacyRun != 1 || activeImports != 10 || rawRules != 41192+bannerTotal {
		t.Fatalf("legacy/source state banner=%d total_banners=%d run=%d imports=%d rules=%d", legacyBanner, bannerTotal, legacyRun, activeImports, rawRules)
	}
	var before, after int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := fingerprint.BootstrapEmbeddedSources(context.Background(), db); err != nil {
		t.Fatalf("idempotent embedded upgrade: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("idempotent source bootstrap changed import count %d -> %d", before, after)
	}
}

func jenkinsFixtureHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/favicon.ico" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("X-Jenkins", "2.452.3")
		writer.Header().Set("X-Jenkins-Session", "t293-session")
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(writer, "<html><title>Jenkins</title><body>jenkins-agent-protocols T293-NUCLEI-MARKER</body></html>")
	})
}

func fingerprintFixtureHandler(server, body string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/favicon.ico" {
			http.NotFound(writer, request)
			return
		}
		if server != "" {
			writer.Header().Set("Server", server)
		}
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(writer, body)
	})
}

func verifyRedirectBoundaryWithRealServers(t *testing.T, destination string) {
	t.Helper()
	destinationPort := serverPort(t, destination)
	crossPort := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination, http.StatusFound)
	}))
	defer crossPort.Close()
	crossPortOrigin := serverPort(t, crossPort.URL)
	blocked, err := fingerprint.CollectWebEvidence(context.Background(), "127.0.0.1", crossPortOrigin, "http", fingerprint.WebEvidenceOptions{AllowedPorts: map[int]struct{}{crossPortOrigin: {}, destinationPort: {}}})
	if err != nil || blocked.Evidence.StatusCode != http.StatusFound || strings.Contains(blocked.Evidence.Body, "jenkins-agent-protocols") {
		t.Fatalf("cross-port redirect evidence=%#v err=%v", blocked, err)
	}

	samePort := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/final" {
			_, _ = io.WriteString(writer, "same-port-redirect-final")
			return
		}
		http.Redirect(writer, request, "/final", http.StatusFound)
	}))
	defer samePort.Close()
	samePortNumber := serverPort(t, samePort.URL)
	allowed, err := fingerprint.CollectWebEvidence(context.Background(), "127.0.0.1", samePortNumber, "http", fingerprint.WebEvidenceOptions{AllowedPorts: map[int]struct{}{samePortNumber: {}}})
	if err != nil || allowed.Evidence.StatusCode != http.StatusOK || !strings.Contains(allowed.Evidence.Body, "same-port-redirect-final") {
		t.Fatalf("same-port redirect evidence=%#v err=%v", allowed, err)
	}
}

func importReviewedTemplateMapping(t *testing.T, db *sql.DB, root, name string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	templateSum := sha256.Sum256(raw)
	manifestSum := sha256.Sum256([]byte(`{"revision":"t293-local-v1"}`))
	_, err = storage.ImportTemplateMappingBatch(db, storage.TemplateMappingBatch{
		Import: model.TemplateMappingImport{
			Revision:      "t293-local-v1",
			ContentSHA256: hex.EncodeToString(manifestSum[:]),
			ManifestJSON:  `{"revision":"t293-local-v1","scope":"local-read-only"}`,
		},
		Mappings: []model.FingerprintTemplateMapping{{
			ProductKey:          "jenkins",
			TemplateID:          "caasm-t293-local",
			TemplatePath:        name,
			TemplateSHA256:      hex.EncodeToString(templateSum[:]),
			TemplateSetRevision: "t293-local-v1",
			SideEffect:          "read_only",
			ReviewStatus:        "approved",
		}},
	})
	if err != nil {
		t.Fatalf("import reviewed mapping: %v", err)
	}
}

func assertSuccessfulRealRun(t *testing.T, db *sql.DB, task model.ScanTask, runID int64, httpPort, httpsPort, nginxPort, harborPort, seeyonPort, sshPort, mysqlPort int) {
	t.Helper()
	run, err := storage.GetScanTaskRun(db, runID)
	if err != nil || run.Status != model.ScanTaskRunStatusSuccess {
		t.Fatalf("real run status=%#v err=%v", run, err)
	}
	snapshot, err := storage.GetScanTaskRunSnapshot(db, runID)
	if err != nil {
		t.Fatal(err)
	}
	services := make(map[int]string)
	for _, port := range snapshot.Ports {
		services[port.Port] = port.ServiceType
	}
	if services[httpPort] != "http" || services[httpsPort] != "https" || services[nginxPort] != "http" || services[harborPort] != "http" || services[seeyonPort] != "http" || services[sshPort] != "openssh" {
		t.Fatalf("real service inventory=%v", services)
	}
	imports, err := storage.ListFingerprintImportsForRun(db, runID)
	if err != nil || len(imports) != 10 {
		t.Fatalf("frozen imports=%d err=%v", len(imports), err)
	}
	matches, err := storage.ListFingerprintRunMatches(db, runID)
	if err != nil {
		t.Fatal(err)
	}
	jenkinsSources := map[string]struct{}{}
	mysqlDetails := make([]string, 0)
	sshDetails := make([]string, 0)
	jenkinsDetails := make([]string, 0)
	foundHTTPS, foundOpenSSH, foundLegacy, foundNginx, foundHarbor, foundSeeyon, foundMySQL := false, false, false, false, false, false, false
	for _, match := range matches {
		product, _ := match["product_key"].(string)
		protocol, _ := match["protocol"].(string)
		port := match["port"].(int)
		if product == "jenkins" && port == httpPort {
			jenkinsSources[match["source_key"].(string)] = struct{}{}
		}
		if port == httpPort {
			jenkinsDetails = append(jenkinsDetails, fmt.Sprintf("%s protocol=%v source=%v rule=%v", product, match["protocol"], match["source_key"], match["source_rule_id"]))
		}
		if product == "jenkins" && port == httpsPort && protocol == "https" {
			foundHTTPS = true
		}
		if product == "openssh" && port == sshPort {
			version, _ := match["version"].(string)
			cpe, _ := match["cpe"].(string)
			foundOpenSSH = foundOpenSSH || (strings.Contains(version, "9.6") && strings.Contains(cpe, "openbsd:openssh"))
		}
		if product == "legacy-t293-ssh" && port == sshPort && protocol == "tcp" {
			foundLegacy = true
		}
		foundNginx = foundNginx || (product == "nginx" && port == nginxPort && protocol == "http")
		foundHarbor = foundHarbor || (product == "harbor" && port == harborPort && protocol == "http")
		foundSeeyon = foundSeeyon || (product == "致远oa" && port == seeyonPort && protocol == "http")
		if product == "mysql" && port == mysqlPort && protocol == "tcp" {
			version, _ := match["version"].(string)
			cpe, _ := match["cpe"].(string)
			foundMySQL = foundMySQL || (version == "5.7.44" && strings.Contains(cpe, "mysql:mysql:5.7.44"))
		}
		if port == mysqlPort {
			mysqlDetails = append(mysqlDetails, fmt.Sprintf("%s protocol=%v version=%v cpe=%v source=%v", product, match["protocol"], match["version"], match["cpe"], match["source_key"]))
		}
		if port == sshPort {
			sshDetails = append(sshDetails, fmt.Sprintf("%s protocol=%v version=%v cpe=%v source=%v", product, match["protocol"], match["version"], match["cpe"], match["source_key"]))
		}
	}
	if len(jenkinsSources) < 2 || !foundHTTPS || !foundOpenSSH || !foundLegacy || !foundNginx || !foundHarbor || !foundSeeyon || !foundMySQL {
		t.Fatalf("real fingerprints jenkins_sources=%v https=%t openssh=%t legacy=%t nginx=%t harbor=%t seeyon=%t mysql=%t ssh_details=%v mysql_details=%v", jenkinsSources, foundHTTPS, foundOpenSSH, foundLegacy, foundNginx, foundHarbor, foundSeeyon, foundMySQL, sshDetails, mysqlDetails)
	}
	conclusions, err := storage.ListFingerprintRunConclusions(db, runID)
	if err != nil {
		t.Fatal(err)
	}
	corroborated, opensshService, legacyService, conflicted := false, false, false, false
	for _, conclusion := range conclusions {
		port := conclusion["port"].(int)
		product := conclusion["product_key"].(string)
		status := conclusion["conclusion_status"].(string)
		corroborated = corroborated || (port == httpPort && product == "jenkins" && status == "corroborated")
		opensshService = opensshService || (port == sshPort && product == "openssh" && status == "corroborated" && conclusion["exclusive_group"] == "network_service")
		legacyService = legacyService || (port == sshPort && product == "legacy-t293-ssh" && status == "matched")
		conflicted = conflicted || (port == sshPort && status == "conflicted")
	}
	if !corroborated || !opensshService || !legacyService || conflicted {
		t.Fatalf("fingerprint conclusions=%#v jenkins_details=%v", conclusions, jenkinsDetails)
	}
	foundFinding, foundCandidate := false, false
	for _, finding := range snapshot.Vulnerabilities {
		foundFinding = foundFinding || (finding.TemplateID == "caasm-t293-local" && finding.TargetPort == httpPort)
	}
	for _, candidate := range snapshot.TemplateCandidates {
		foundCandidate = foundCandidate || (candidate.TemplateID == "caasm-t293-local" && candidate.IP == task.Target && candidate.Port == httpPort && candidate.Protocol == "http" && candidate.TemplateSHA256 != "")
	}
	if !foundFinding || !foundCandidate {
		t.Fatalf("real nuclei findings=%#v candidates=%#v", snapshot.Vulnerabilities, snapshot.TemplateCandidates)
	}
}

func verifyCanceledPartialRun(t *testing.T, db *sql.DB, reportDirectory string) {
	t.Helper()
	fastPort, closeFast := startTCPFixture(t, "SSH-2.0-T293-CANCEL-FAST\r\n", false)
	defer closeFast()
	slowPort, closeSlow := startTCPFixture(t, "", true)
	defer closeSlow()
	service := schedule.NewTaskService(db, schedule.ClockFunc(func() time.Time {
		return time.Date(2026, 8, 6, 1, 5, 0, 0, time.UTC)
	}))
	task, run, err := service.Create(context.Background(), model.ScanTask{
		Target: "127.0.0.1", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce, Status: model.ScanTaskStatusEnabled,
		Config: model.ScanTaskConfig{PortSpec: fmt.Sprintf("%d,%d", fastPort, slowPort)},
	})
	if err != nil || run == nil {
		t.Fatalf("create cancellation task: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	// The fast banner closes within milliseconds while the second fixture holds
	// for five seconds, leaving a deterministic partial-result cancellation window.
	time.AfterFunc(time.Second, cancel)
	executor := schedule.NewExecutor(db, NewTargetTaskRunExecutor(TargetTaskRunOptions{DB: db, Run: *run, Network: "tcp"}))
	if err := executor.ExecuteRun(ctx, run.ID); err != nil {
		t.Fatalf("execute canceled run: %v", err)
	}
	finished, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || finished.Status != model.ScanTaskRunStatusCanceled {
		t.Fatalf("canceled run=%#v err=%v", finished, err)
	}
	snapshot, err := storage.GetScanTaskRunSnapshot(db, run.ID)
	if err != nil {
		t.Fatalf("read canceled partial snapshot: %v", err)
	}
	foundFast := false
	for _, port := range snapshot.Ports {
		foundFast = foundFast || port.Port == fastPort
	}
	if !foundFast {
		t.Fatalf("canceled partial snapshot=%#v", snapshot)
	}
	reportPath, err := report.GenerateScanTaskRunReport(db, task.ID, run.ID, reportDirectory)
	if err != nil {
		t.Fatalf("generate canceled report: %v", err)
	}
	assertAuditReport(t, reportPath, true)
}

func assertAuditReport(t *testing.T, reportPath string, canceled bool) {
	t.Helper()
	userRaw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	userText := string(userRaw)
	if strings.Contains(userText, "Frozen Fingerprint Revisions") || strings.Index(userText, "Vulnerability Validation") > strings.Index(userText, "Endpoint Profiles") {
		t.Fatalf("user report is not result-first or contains audit internals: %s", reportPath)
	}
	auditPath := strings.TrimSuffix(reportPath, ".md") + "-audit.md"
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, required := range []string{"Frozen Fingerprint Revisions", "Fingerprint Conclusions", "Fingerprint Evidence", "Validation Plan"} {
		if !strings.Contains(text, required) {
			t.Fatalf("audit report %s missing %q", auditPath, required)
		}
	}
	if canceled && !strings.Contains(userText, "canceled") {
		t.Fatalf("partial report does not show canceled status: %s", reportPath)
	}
	if strings.Contains(text, "jenkins-agent-protocols") {
		t.Fatalf("report leaked raw fingerprint response: %s", reportPath)
	}
}

func startTCPFixture(t *testing.T, banner string, hold bool) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	var wait sync.WaitGroup
	done := make(chan struct{})
	wait.Add(1)
	go func() {
		defer wait.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				if banner != "" {
					_, _ = io.WriteString(connection, banner)
				}
				if hold {
					select {
					case <-done:
					case <-time.After(5 * time.Second):
					}
				}
			}()
		}
	}()
	var once sync.Once
	return port, func() {
		once.Do(func() {
			close(done)
			_ = listener.Close()
			wait.Wait()
		})
	}
}

func serverPort(t *testing.T, rawURL string) int {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	_, text, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(text)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
