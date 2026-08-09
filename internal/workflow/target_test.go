package workflow

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golandproject/yscan/internal/fingerprint"
	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/planner"
	"golandproject/yscan/internal/scan"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/vuln"
)

func TestRunFingerprintCollectorLoadsOnlyForFirstOpenEndpoint(t *testing.T) {
	db := openWorkflowDB(t)
	loads := 0
	collector := newRunFingerprintCollectorWithLoader(db, model.ScanTaskRun{ID: 44}, func(*sql.DB, int64) (*fingerprint.Engine, error) {
		loads++
		return &fingerprint.Engine{}, nil
	})
	if _, _, err := collector(context.Background(), db, model.ScanTaskRun{}, "192.168.80.1", nil); err != nil || loads != 0 {
		t.Fatalf("empty endpoint loads=%d err=%v", loads, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	result := []model.ScanResult{{Address: "192.168.80.1:65534", Open: true}}
	if _, _, err := collector(canceled, db, model.ScanTaskRun{}, "192.168.80.1", result); !errors.Is(err, context.Canceled) || loads != 1 {
		t.Fatalf("first open endpoint loads=%d err=%v", loads, err)
	}
	if _, _, err := collector(canceled, db, model.ScanTaskRun{}, "192.168.80.1", result); !errors.Is(err, context.Canceled) || loads != 1 {
		t.Fatalf("cached open endpoint loads=%d err=%v", loads, err)
	}
}

func TestFiveWebEndpointsKeepProtocolResponsesWhenPassiveBannersAreEmpty(t *testing.T) {
	results := make([]model.ScanResult, 0, 5)
	servers := make([]*httptest.Server, 0, 5)
	for index := 0; index < 5; index++ {
		index := index
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if index != 3 {
				w.Header().Set("Server", "nginx")
			}
			w.WriteHeader([]int{http.StatusNotFound, http.StatusOK, http.StatusForbidden, http.StatusOK, http.StatusInternalServerError}[index])
			_, _ = w.Write([]byte("<html><title>fixture " + strconv.Itoa(index) + "</title><body>response</body></html>"))
		}))
		servers = append(servers, server)
		t.Cleanup(server.Close)
		host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
		if err != nil || host != "127.0.0.1" {
			t.Fatalf("test endpoint=%s err=%v", server.URL, err)
		}
		results = append(results, model.ScanResult{Address: net.JoinHostPort(host, portText), Open: true, Service: "http"})
	}
	collected, _, err := collectRunFingerprintMatchesWithEngine(context.Background(), &fingerprint.Engine{}, "127.0.0.1", results)
	if err != nil {
		t.Fatal(err)
	}
	for index, result := range collected {
		if result.Banner != "" || len(result.ProtocolEvidence) != 2 || result.ProtocolEvidence[0].EvidenceType != model.ProtocolEvidencePassiveBanner || result.ProtocolEvidence[0].Protocol != "tcp" || result.ProtocolEvidence[0].Responded || result.ProtocolEvidence[1].EvidenceType != model.ProtocolEvidenceWeb || result.ProtocolEvidence[1].Protocol != "http" || !result.ProtocolEvidence[1].Responded || result.ProtocolEvidence[1].StatusCode == 0 || result.ProtocolEvidence[1].BodyCapturedLength == 0 {
			t.Fatalf("endpoint %d evidence=%#v", index, result.ProtocolEvidence)
		}
	}
}

func TestActiveProbeResponseEvidenceSurvivesWithoutRuleMatch(t *testing.T) {
	evidence := fingerprint.NewBannerEvidence("unmatched active response", false)
	observation := protocolEvidenceFromProbe("GenericLines", evidence)
	if observation.EvidenceType != model.ProtocolEvidenceActiveProbe || observation.ProbeName != "GenericLines" || observation.Protocol != "tcp" || !observation.Responded || observation.BannerCapturedLength != len("unmatched active response") || observation.BannerSHA256 == "" {
		t.Fatalf("active probe observation = %#v", observation)
	}
}

func TestActiveProbeReadTimeoutLeavesMarginInsideEndpointBudget(t *testing.T) {
	if nmapProbeReadBudget >= nmapProbeEndpointBudget {
		t.Fatalf("probe read budget %s must be shorter than endpoint budget %s", nmapProbeReadBudget, nmapProbeEndpointBudget)
	}
}

func TestEndpointServiceUnknownClassification(t *testing.T) {
	for _, service := range []string{"", "unknown", "None_unknown", "tcp-unknown"} {
		if !endpointServiceUnknown(service) {
			t.Fatalf("service %q should be unknown", service)
		}
	}
	if endpointServiceUnknown("redis") {
		t.Fatal("identified Redis service must not be unknown")
	}
}

func TestActiveProbeDiagnosticsCoverRefusalReadTimeoutAndZeroResponse(t *testing.T) {
	refused, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedPort := refused.Addr().(*net.TCPAddr).Port
	_ = refused.Close()
	_, err = fingerprint.ExecuteNmapTCPProbe(context.Background(), "127.0.0.1", refusedPort, fingerprint.NmapTCPProbe{Name: "Refused", Timeout: 100 * time.Millisecond})
	if err == nil || nmapProbeFailureOutcome(err) != model.ProtocolProbeOutcomeConnectFailed {
		t.Fatalf("refused outcome=%q err=%v", nmapProbeFailureOutcome(err), err)
	}

	timeoutListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = timeoutListener.Close() })
	go func() {
		conn, acceptErr := timeoutListener.Accept()
		if acceptErr == nil {
			defer conn.Close()
			time.Sleep(250 * time.Millisecond)
		}
	}()
	timeoutPort := timeoutListener.Addr().(*net.TCPAddr).Port
	_, err = fingerprint.ExecuteNmapTCPProbe(context.Background(), "127.0.0.1", timeoutPort, fingerprint.NmapTCPProbe{Name: "Timeout", Payload: []byte("PING"), Timeout: 40 * time.Millisecond})
	if err == nil || nmapProbeFailureOutcome(err) != model.ProtocolProbeOutcomeReadTimeout {
		t.Fatalf("timeout outcome=%q err=%v", nmapProbeFailureOutcome(err), err)
	}

	emptyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = emptyListener.Close() })
	go func() {
		conn, acceptErr := emptyListener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()
	emptyPort := emptyListener.Addr().(*net.TCPAddr).Port
	response, err := fingerprint.ExecuteNmapTCPProbe(context.Background(), "127.0.0.1", emptyPort, fingerprint.NmapTCPProbe{Name: "Empty", Timeout: 100 * time.Millisecond})
	if err != nil || len(response) != 0 {
		t.Fatalf("empty response=%q err=%v", response, err)
	}
	observation := protocolEvidenceFromProbe("Empty", fingerprint.NewBannerEvidence(string(response), false))
	if observation.Responded || observation.Outcome != model.ProtocolProbeOutcomeNoResponse || observation.Diagnostic != model.ProtocolProbeOutcomeNoResponse {
		t.Fatalf("empty observation=%#v", observation)
	}
}

func TestRunTargetTaskRunBuildsSnapshotIndependentOfInventory(t *testing.T) {
	db := openWorkflowDB(t)
	snapshot, err := runTargetTaskRun(context.Background(), TargetTaskRunOptions{
		DB: db,
		Run: model.ScanTaskRun{
			ID:         91,
			ScanTaskID: 12,
			ScanType:   model.ScanTypeIP,
			Target:     "192.168.80.10",
			Config:     model.ScanTaskConfig{},
		},
	}, targetDependencies{
		scanHost: func(context.Context, string, string) (scan.PortScanOutcome, error) {
			return scan.PortScanOutcome{Results: []model.ScanResult{{Address: "192.168.80.10:8443", Open: true, Service: "https", Product: "nginx"}}, AttemptedPorts: 65535, TotalPorts: 65535}, nil
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("run target task run: %v", err)
	}
	if snapshot.RunID != 91 {
		t.Fatalf("snapshot run ID = %d", snapshot.RunID)
	}
	if want := []model.ScanTaskRunHost{{IP: "192.168.80.10", IsActive: true}}; !reflect.DeepEqual(snapshot.Hosts, want) {
		t.Fatalf("snapshot hosts = %#v, want %#v", snapshot.Hosts, want)
	}
	if want := []model.ScanTaskRunPort{{IP: "192.168.80.10", Port: 8443, ServiceType: "https", Product: "nginx"}}; !reflect.DeepEqual(snapshot.Ports, want) {
		t.Fatalf("snapshot ports = %#v, want %#v", snapshot.Ports, want)
	}
	if len(snapshot.Vulnerabilities) != 0 || snapshot.Validation.Status != model.ScanTaskRunValidationDisabled {
		t.Fatalf("snapshot validation = %#v", snapshot.Validation)
	}
}

func TestNonStandardHTTPSNoTemplatesIsNotSuccessfulValidation(t *testing.T) {
	db := openFullWorkflowDB(t)
	const ip = "192.168.80.17"
	root, templateIndex := workflowTemplateIndexFixture(t, workflowTemplateSpec{id: "nginx-safe", product: "nginx", protocol: "http"})
	snapshot, err := runTargetTaskRun(context.Background(), TargetTaskRunOptions{
		DB: db, Run: model.ScanTaskRun{ID: 97, ScanTaskID: 12, ScanType: model.ScanTypeIP, Target: ip, Config: model.ScanTaskConfig{VulnerabilityOn: true}},
	}, targetDependencies{
		scanHost: func(context.Context, string, string) (scan.PortScanOutcome, error) {
			return scan.PortScanOutcome{Results: []model.ScanResult{{Address: ip + ":30957", Open: true, Service: "https"}}, AttemptedPorts: 65535, TotalPorts: 65535}, nil
		},
		collectFingerprints: func(_ context.Context, _ *sql.DB, _ model.ScanTaskRun, host string, results []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error) {
			return results, []model.FingerprintRunMatch{{IP: host, Port: 30957, Protocol: "https", Product: "nginx"}}, nil
		},
		loadTemplateIndex: func(string) (string, *planner.NucleiTemplateIndex, error) { return root, templateIndex, nil },
		executeTemplatePaths: func(context.Context, string, []model.ScanResult, []string) vuln.NucleiExecutionResult {
			return vuln.NucleiExecutionResult{Started: true, Err: vuln.ErrNoTemplates}
		},
	})
	if err != nil {
		t.Fatalf("no-template validation must not fail asset collection: %v", err)
	}
	if snapshot.Validation.Status != model.ScanTaskRunValidationNoCandidates || snapshot.Validation.CandidateEndpointCount != 1 || snapshot.Validation.ExecutedEndpointCount != 0 || snapshot.Validation.TemplateCount == 0 {
		t.Fatalf("validation state = %#v", snapshot.Validation)
	}
	if len(snapshot.TemplateCandidates) == 0 || snapshot.TemplateCandidates[0].Protocol != "https" {
		t.Fatalf("non-standard HTTPS candidates = %#v", snapshot.TemplateCandidates)
	}
}

func TestPortScanFailureLeavesValidationNotStarted(t *testing.T) {
	db := openWorkflowDB(t)
	const ip = "192.168.80.19"
	scanErr := errors.New("forced incomplete discovery")
	snapshot, err := runTargetTaskRun(context.Background(), TargetTaskRunOptions{
		DB: db, Run: model.ScanTaskRun{ID: 99, ScanTaskID: 12, ScanType: model.ScanTypeIP, Target: ip, Config: model.ScanTaskConfig{VulnerabilityOn: true}},
	}, targetDependencies{
		scanHost: func(context.Context, string, string) (scan.PortScanOutcome, error) {
			return scan.PortScanOutcome{Results: []model.ScanResult{{Address: ip + ":80", Open: true, Service: "http"}}, AttemptedPorts: 80, TotalPorts: 65535}, scanErr
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
	})
	if !errors.Is(err, scanErr) || snapshot.Validation.Status != model.ScanTaskRunValidationNotStarted || snapshot.Validation.StartedAt != "" || snapshot.Validation.CandidateEndpointCount != 0 {
		t.Fatalf("partial scan err=%v validation=%#v", err, snapshot.Validation)
	}
}

func TestValidationKeepsEarlierExecutedEndpointWhenLaterEndpointHasNoTemplates(t *testing.T) {
	db := openFullWorkflowDB(t)
	const ip = "192.168.80.18"
	calls := 0
	root, templateIndex := workflowTemplateIndexFixture(t,
		workflowTemplateSpec{id: "nginx-safe", product: "nginx", protocol: "http"},
		workflowTemplateSpec{id: "php-safe", product: "php", protocol: "http"},
	)
	snapshot, err := runTargetTaskRun(context.Background(), TargetTaskRunOptions{
		DB: db, Run: model.ScanTaskRun{ID: 98, ScanTaskID: 12, ScanType: model.ScanTypeIP, Target: ip, Config: model.ScanTaskConfig{VulnerabilityOn: true}},
	}, targetDependencies{
		scanHost: func(context.Context, string, string) (scan.PortScanOutcome, error) {
			return scan.PortScanOutcome{Results: []model.ScanResult{
				{Address: ip + ":80", Open: true, Service: "http"},
				{Address: ip + ":443", Open: true, Service: "https"},
			}, AttemptedPorts: 65535, TotalPorts: 65535}, nil
		},
		collectFingerprints: func(_ context.Context, _ *sql.DB, _ model.ScanTaskRun, host string, results []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error) {
			return results, []model.FingerprintRunMatch{{IP: host, Port: 80, Protocol: "http", Product: "nginx"}, {IP: host, Port: 443, Protocol: "https", Product: "php"}}, nil
		},
		loadTemplateIndex: func(string) (string, *planner.NucleiTemplateIndex, error) { return root, templateIndex, nil },
		executeTemplatePaths: func(_ context.Context, _ string, ports []model.ScanResult, _ []string) vuln.NucleiExecutionResult {
			calls++
			if strings.HasSuffix(ports[0].Address, ":443") {
				return vuln.NucleiExecutionResult{Started: true, Err: vuln.ErrNoTemplates}
			}
			return vuln.NucleiExecutionResult{Started: true, Executed: true, Findings: []model.NucleiFinding{{TemplateID: "first-success", Name: "First", Description: "parsed description", Target: "http://" + ip, TargetIP: ip, TargetPort: 80}}}
		},
	})
	if err != nil {
		t.Fatalf("mixed validation must preserve successful endpoint: %v", err)
	}
	if calls != 2 || snapshot.Validation.Status != model.ScanTaskRunValidationSuccess || snapshot.Validation.CandidateEndpointCount != 2 || snapshot.Validation.ExecutedEndpointCount != 1 || snapshot.Validation.FindingCount != 1 || len(snapshot.Vulnerabilities) != 1 || snapshot.Vulnerabilities[0].Description != "parsed description" {
		t.Fatalf("mixed validation calls=%d state=%#v findings=%#v", calls, snapshot.Validation, snapshot.Vulnerabilities)
	}
}

func TestRunTargetTaskRunCollectsFingerprintsBeforeSnapshot(t *testing.T) {
	db := openWorkflowDB(t)
	called := false
	snapshot, err := runTargetTaskRun(context.Background(), TargetTaskRunOptions{
		DB:  db,
		Run: model.ScanTaskRun{ID: 92, ScanTaskID: 12, ScanType: model.ScanTypeIP, Target: "192.168.80.11"},
	}, targetDependencies{
		scanHost: func(context.Context, string, string) (scan.PortScanOutcome, error) {
			return scan.PortScanOutcome{Results: []model.ScanResult{{Address: "192.168.80.11:32123", Open: true, Service: "unknown", Banner: "fixture"}}, AttemptedPorts: 65535, TotalPorts: 65535}, nil
		},
		collectFingerprints: func(_ context.Context, _ *sql.DB, run model.ScanTaskRun, ip string, results []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error) {
			called = run.ID == 92 && ip == "192.168.80.11"
			results[0].Service = "http"
			results[0].Product = "fixture-product"
			return results, []model.FingerprintRunMatch{{IP: ip, Port: 32123, Product: "fixture-product"}}, nil
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("run target task run: %v", err)
	}
	if !called || len(snapshot.Ports) != 1 || snapshot.Ports[0].ServiceType != "http" || snapshot.Ports[0].Product != "fixture-product" || len(snapshot.FingerprintMatches) != 1 {
		t.Fatalf("fingerprint collection was not reflected in snapshot: called=%t snapshot=%#v", called, snapshot)
	}
}

func TestRunTargetTaskRunReturnsFingerprintPartialOnCancellation(t *testing.T) {
	db := openWorkflowDB(t)
	const ip = "192.168.80.15"
	snapshot, err := runTargetTaskRun(context.Background(), TargetTaskRunOptions{
		DB:  db,
		Run: model.ScanTaskRun{ID: 95, ScanTaskID: 12, ScanType: model.ScanTypeIP, Target: ip},
	}, targetDependencies{
		scanHost: func(context.Context, string, string) (scan.PortScanOutcome, error) {
			return scan.PortScanOutcome{Results: []model.ScanResult{{Address: ip + ":8080", Open: true, Service: "unknown"}}, AttemptedPorts: 65535, TotalPorts: 65535}, nil
		},
		collectFingerprints: func(_ context.Context, _ *sql.DB, _ model.ScanTaskRun, _ string, results []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error) {
			results[0].Service = "http"
			results[0].Product = "partial-product"
			return results, []model.FingerprintRunMatch{{IP: ip, Port: 8080, Protocol: "http", Product: "partial-product"}}, context.Canceled
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context.Canceled", err)
	}
	if len(snapshot.Hosts) != 1 || snapshot.Hosts[0].IP != ip || len(snapshot.Ports) != 1 || snapshot.Ports[0].Port != 8080 || snapshot.Ports[0].Product != "partial-product" || len(snapshot.FingerprintMatches) != 1 {
		t.Fatalf("fingerprint cancellation partial snapshot=%#v", snapshot)
	}
}

func TestRunTargetTaskRunReturnsPortsWhenCanceledAfterDiscovery(t *testing.T) {
	db := openWorkflowDB(t)
	const ip = "192.168.80.16"
	checks := 0
	snapshot, err := runTargetTaskRun(context.Background(), TargetTaskRunOptions{
		DB: db, Run: model.ScanTaskRun{ID: 96, ScanTaskID: 12, ScanType: model.ScanTypeIP, Target: ip},
		CheckCanceled: func() (bool, error) {
			checks++
			return checks > 1, nil
		},
	}, targetDependencies{
		scanHost: func(context.Context, string, string) (scan.PortScanOutcome, error) {
			return scan.PortScanOutcome{Results: []model.ScanResult{{Address: ip + ":32123", Open: true, Service: "ssh"}}, AttemptedPorts: 65535, TotalPorts: 65535}, nil
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
	})
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("error=%v, want ErrCanceled", err)
	}
	if len(snapshot.Hosts) != 1 || snapshot.Hosts[0].IP != ip || len(snapshot.Ports) != 1 || snapshot.Ports[0].Port != 32123 {
		t.Fatalf("post-discovery cancellation snapshot=%#v", snapshot)
	}
}

func TestCollectedWebServiceClassifiesUnknownPort(t *testing.T) {
	for _, test := range []struct {
		current, protocol, want string
	}{
		{current: "None_unknown", protocol: "http", want: "http"},
		{current: "unknown", protocol: "https", want: "https"},
		{current: "http-unknown", protocol: "https", want: "https"},
		{current: "ssh", protocol: "http", want: "ssh"},
	} {
		if got := collectedWebService(test.current, test.protocol); got != test.want {
			t.Fatalf("collectedWebService(%q, %q) = %q, want %q", test.current, test.protocol, got, test.want)
		}
	}
}

func TestResolvedHardProductDoesNotChooseConflictByOrder(t *testing.T) {
	if product, source := resolvedHardProduct(map[string]hardProductCandidate{"nginx": {role: "web_server", source: "ehole"}, "apache": {role: "web_server", source: "nmap"}}); product != "" || source != "" {
		t.Fatalf("conflicting products must remain unresolved: product=%q source=%q", product, source)
	}
	if product, source := resolvedHardProduct(map[string]hardProductCandidate{"nginx": {role: "web_server"}}); product != "nginx" || source != "" {
		t.Fatalf("corroborated product should be retained without an arbitrary source: product=%q source=%q", product, source)
	}
	if product, _ := resolvedHardProduct(map[string]hardProductCandidate{"nginx": {role: "web_server"}, "html5": {role: "markup"}, "bt-panel": {role: "control_panel"}}); product != "nginx" {
		t.Fatalf("layered web stack resolved as %q", product)
	}
}

func TestIncompleteFullScanDoesNotCloseInventoryPorts(t *testing.T) {
	db := openWorkflowDB(t)
	const ip = "192.168.80.12"
	if err := storage.SyncOpenPorts(db, ip, []model.ScanResult{{Address: ip + ":32123", Open: true, Service: "ssh"}}, storage.FullPortScanCoverage()); err != nil {
		t.Fatalf("seed inventory port: %v", err)
	}
	_, err := runTargetTaskRun(context.Background(), TargetTaskRunOptions{
		DB: db, Run: model.ScanTaskRun{ID: 93, ScanTaskID: 12, ScanType: model.ScanTypeIP, Target: ip},
	}, targetDependencies{
		scanHost: func(context.Context, string, string) (scan.PortScanOutcome, error) {
			return scan.PortScanOutcome{AttemptedPorts: 1000, TotalPorts: 65535}, nil
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
	})
	if err == nil {
		t.Fatal("incomplete full scan must fail")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM current_port_inventory WHERE ip = ? AND port = 32123`, ip).Scan(&count); err != nil || count != 1 {
		t.Fatalf("inventory port changed after incomplete scan: count=%d err=%v", count, err)
	}
}

func TestRunTargetTaskRunUsesConfiguredPortSpecOnly(t *testing.T) {
	db := openWorkflowDB(t)
	selectedCalled := false
	snapshot, err := runTargetTaskRun(context.Background(), TargetTaskRunOptions{DB: db, Run: model.ScanTaskRun{ID: 94, ScanTaskID: 12, ScanType: model.ScanTypeIP, Target: "192.168.80.14", Config: model.ScanTaskConfig{PortSpec: "80,443"}}}, targetDependencies{
		scanHost: func(context.Context, string, string) (scan.PortScanOutcome, error) {
			t.Fatal("default full scan must not run for explicit port_spec")
			return scan.PortScanOutcome{}, nil
		},
		scanSelected: func(_ context.Context, ip, network string, ports []int) (scan.PortScanOutcome, error) {
			selectedCalled = ip == "192.168.80.14" && network == "tcp" && reflect.DeepEqual(ports, []int{80, 443})
			return scan.PortScanOutcome{Results: []model.ScanResult{{Address: ip + ":443", Open: true, Service: "https"}}, AttemptedPorts: 2, TotalPorts: 2}, nil
		},
		runNuclei: func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error) {
			return nil, nil
		},
	})
	if err != nil || !selectedCalled || len(snapshot.Ports) != 1 || snapshot.Ports[0].Port != 443 {
		t.Fatalf("selected=%t snapshot=%#v err=%v", selectedCalled, snapshot, err)
	}
}
