package fingerprint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFingerprintHubSnapshot(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "fingerprinthub.yaml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	result, err := ParseFingerprintHubSnapshot("FingerprintHub", data)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(result.Rules) != 4 {
		t.Fatalf("parsed rules = %d, want 4: %#v", len(result.Rules), result.Rules)
	}

	rules := make(map[string]Rule, len(result.Rules))
	for _, rule := range result.Rules {
		rules[rule.ID] = rule
	}
	bodyRule := rules["fingerprinthub/acme-web/http-0/matcher-0"]
	if bodyRule.MatchMode != MatchAny || len(bodyRule.Matchers) != 2 || !bodyRule.Matchers[0].CaseInsensitive || bodyRule.Matchers[0].Target != EvidenceBody {
		t.Fatalf("body rule lost FingerprintHub semantics: %#v", bodyRule)
	}
	headerRule := rules["fingerprinthub/acme-web/http-0/matcher-1"]
	if len(headerRule.Matchers) != 1 || headerRule.Matchers[0].Target != EvidenceHeader || headerRule.Matchers[0].HeaderName != "" {
		t.Fatalf("header rule = %#v", headerRule)
	}
	faviconRule := rules["fingerprinthub/acme-web/http-0/matcher-2"]
	if len(faviconRule.Matchers) != 1 || faviconRule.Matchers[0].HashAlgorithm != FaviconHashMD5 {
		t.Fatalf("favicon rule = %#v", faviconRule)
	}
	tcpRule := rules["fingerprinthub/acme-tcp/tcp-0/extractor-0"]
	if len(tcpRule.Matchers) != 1 || tcpRule.Protocols[0] != ProtocolTCP || tcpRule.Matchers[0].Target != EvidenceBanner {
		t.Fatalf("tcp rule = %#v", tcpRule)
	}

	assertDiagnosticCode(t, result.Diagnostics, "unsupported_negative_matcher")
	assertDiagnosticCode(t, result.Diagnostics, "unsupported_http_matcher")
	assertDiagnosticCode(t, result.Diagnostics, "unsupported_matcher_condition")
	assertDiagnosticCode(t, result.Diagnostics, "unsupported_tcp_probe")
	assertDiagnosticCode(t, result.Diagnostics, "unsupported_tcp_port_filter")
}

func TestParseFingerprintHubSnapshotRejectsMalformedYAML(t *testing.T) {
	if _, err := ParseFingerprintHubSnapshot("fingerprinthub", []byte("id: [")); err == nil {
		t.Fatal("malformed YAML must fail")
	}
}

func TestParseFingerprintHubSnapshotCheckedInSnapshot(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "data", "fingerprints", "fingerprinthub", "rules.yaml"))
	if err != nil {
		t.Fatalf("read checked-in snapshot: %v", err)
	}
	result, err := ParseFingerprintHubSnapshot("fingerprinthub", data)
	if err != nil {
		t.Fatalf("parse checked-in snapshot: %v", err)
	}
	if len(result.Rules) != 4 {
		t.Fatalf("checked-in snapshot rules = %d, want 4: %#v", len(result.Rules), result.Rules)
	}
	assertDiagnosticCode(t, result.Diagnostics, "unsupported_tcp_probe")
	assertDiagnosticCode(t, result.Diagnostics, "unsupported_tcp_port_filter")
}

func assertDiagnosticCode(t *testing.T, diagnostics []ParseDiagnostic, code string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code && diagnostic.Reason != "" {
			return
		}
	}
	t.Fatalf("diagnostic %q not found in %#v", code, diagnostics)
}
