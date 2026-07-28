package fingerprint

import (
	"net/http"
	"testing"
)

func TestMatchRulesRanksIndependentEvidenceAndPreservesSummary(t *testing.T) {
	highConfidence := Rule{
		ID:       "fingerprinthub/acme-gateway",
		SourceID: "fingerprinthub",
		Product:  ProductIdentity{Vendor: "acme", Name: "gateway"},
		Protocols: []Protocol{
			ProtocolHTTP,
		},
		MatchMode: MatchAll,
		Matchers: []Matcher{
			{Target: EvidenceHeader, HeaderName: "Server", Operator: MatchContains, Pattern: "acme", CaseInsensitive: true},
			{Target: EvidenceBody, Operator: MatchRegex, Pattern: `console-[0-9]+`},
			{Target: EvidenceFaviconHash, Operator: MatchEquals, HashAlgorithm: FaviconHashMD5, Pattern: "7cddabe5df64daaa6924a5613dd2150a"},
		},
	}
	lowConfidence := Rule{
		ID:       "fingerprinthub/acme-console",
		SourceID: "fingerprinthub",
		Product:  ProductIdentity{Vendor: "acme", Name: "console"},
		Protocols: []Protocol{
			ProtocolHTTP,
		},
		Matchers: []Matcher{{Target: EvidenceBody, Operator: MatchContains, Pattern: "console-42"}},
	}
	evidence := ServiceEvidence{
		Protocol: ProtocolHTTP,
		Headers:  http.Header{"Server": []string{"Acme Gateway"}},
		Body:     "<body>console-42</body>",
		Favicon:  FaviconEvidence{Status: FaviconAvailable, MD5: "7cddabe5df64daaa6924a5613dd2150a"},
	}

	matches, err := MatchRules([]Rule{lowConfidence, highConfidence}, evidence)
	if err != nil {
		t.Fatalf("match rules: %v", err)
	}
	if len(matches) != 2 || matches[0].RuleID != highConfidence.ID || matches[0].Confidence != 95 || matches[1].Confidence != 55 {
		t.Fatalf("matches = %#v", matches)
	}
	for _, hit := range matches[0].Evidence {
		if hit.Summary == "" || hit.Summary == evidence.Body || hit.Summary == evidence.Headers.Get("Server") {
			t.Fatalf("raw response content leaked into match summary: %#v", hit)
		}
	}
	persisted, err := matches[0].ToAssetFingerprint("192.168.10.10", 443)
	if err != nil || persisted.Product != "gateway" || persisted.Protocol != "http" || len(persisted.Evidence) != len(matches[0].Evidence) {
		t.Fatalf("persistence conversion = %#v, %v", persisted, err)
	}
}

func TestMatchRulesHandlesAnyMatcherAndProtocolScope(t *testing.T) {
	anyRule := Rule{
		ID:       "fingerprinthub/acme-any",
		SourceID: "fingerprinthub",
		Product:  ProductIdentity{Name: "acme"},
		Protocols: []Protocol{
			ProtocolHTTP,
		},
		MatchMode: MatchAny,
		Matchers: []Matcher{
			{Target: EvidenceHeader, Operator: MatchContains, Pattern: "x-acme"},
			{Target: EvidenceBody, Operator: MatchContains, Pattern: "product=acme"},
		},
	}
	tcpRule := Rule{
		ID:       "fingerprinthub/acme-tcp",
		SourceID: "fingerprinthub",
		Product:  ProductIdentity{Name: "acme"},
		Protocols: []Protocol{
			ProtocolTCP,
		},
		Matchers: []Matcher{{Target: EvidenceBanner, Operator: MatchContains, Pattern: "ACME"}},
	}
	evidence := ServiceEvidence{Protocol: ProtocolHTTP, Body: "product=acme", Banner: "ACME"}

	matches, err := MatchRules([]Rule{tcpRule, anyRule}, evidence)
	if err != nil {
		t.Fatalf("match rules: %v", err)
	}
	if len(matches) != 1 || matches[0].RuleID != anyRule.ID || len(matches[0].Evidence) != 1 || matches[0].Confidence != 55 {
		t.Fatalf("protocol-scoped any match = %#v", matches)
	}
}

func TestMatchRulesTreatsAuditedTCPBannerAsCandidateEvidence(t *testing.T) {
	rule := Rule{ID: "fingerprinthub/redis", SourceID: "fingerprinthub", Product: ProductIdentity{Name: "redis"}, Protocols: []Protocol{ProtocolTCP}, Matchers: []Matcher{{Target: EvidenceBanner, Operator: MatchContains, Pattern: "redis"}}}
	matches, err := MatchRules([]Rule{rule}, ServiceEvidence{Protocol: ProtocolTCP, Banner: "redis_version:7.2"})
	if err != nil || len(matches) != 1 || matches[0].Confidence != 70 {
		t.Fatalf("banner match = %#v, err=%v", matches, err)
	}
}

func TestMatchRulesRejectsInvalidEvidenceProtocol(t *testing.T) {
	if _, err := MatchRules(nil, ServiceEvidence{Protocol: "udp"}); err == nil {
		t.Fatal("invalid evidence protocol must be rejected")
	}
}
