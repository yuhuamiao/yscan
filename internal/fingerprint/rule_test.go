package fingerprint

import "testing"

func TestRuleValidatesAllSupportedEvidenceTargets(t *testing.T) {
	rule := validRule()
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate rule: %v", err)
	}
	if rule.MatchMode != MatchAll {
		t.Fatalf("default match mode = %q", rule.MatchMode)
	}
	if len(rule.Protocols) != 2 || rule.Protocols[0] != ProtocolHTTP || rule.Protocols[1] != ProtocolHTTPS {
		t.Fatalf("normalized protocols = %#v", rule.Protocols)
	}
	if rule.Matchers[0].HeaderName != "server" {
		t.Fatalf("normalized header = %q", rule.Matchers[0].HeaderName)
	}
}

func TestRuleRejectsInvalidDefinitions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Rule)
	}{
		{
			name: "missing product name",
			mutate: func(rule *Rule) {
				rule.Product.Name = ""
			},
		},
		{
			name: "unsupported protocol",
			mutate: func(rule *Rule) {
				rule.Protocols = []Protocol{"udp"}
			},
		},
		{
			name: "invalid cpe",
			mutate: func(rule *Rule) {
				rule.Product.CPE = "cpe:2.3:a:nginx"
			},
		},
		{
			name: "invalid regex",
			mutate: func(rule *Rule) {
				rule.Matchers[1].Pattern = "(nginx"
			},
		},
		{
			name: "header malformed name",
			mutate: func(rule *Rule) {
				rule.Matchers[0].HeaderName = "bad header"
			},
		},
		{
			name: "favicon hash is not exact mmh3",
			mutate: func(rule *Rule) {
				rule.Matchers[3].Operator = MatchRegex
			},
		},
		{
			name: "http evidence on tcp only rule",
			mutate: func(rule *Rule) {
				rule.Protocols = []Protocol{ProtocolTCP}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rule := validRule()
			test.mutate(&rule)
			if err := rule.Validate(); err == nil {
				t.Fatal("invalid rule must be rejected")
			}
		})
	}
}

func TestRuleAllowsBannerOnlyTCPEvidence(t *testing.T) {
	rule := Rule{
		ID:       "fingerprinthub/openssh",
		SourceID: "fingerprinthub",
		Product:  ProductIdentity{Vendor: "openbsd", Name: "openssh"},
		Protocols: []Protocol{
			ProtocolTCP,
		},
		Matchers: []Matcher{{
			Target:   EvidenceBanner,
			Operator: MatchRegex,
			Pattern:  `^SSH-[0-9.]+-OpenSSH_`,
		}},
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate banner rule: %v", err)
	}
}

func TestRulePreservesWhitespaceSensitivePatterns(t *testing.T) {
	rule := validRule()
	rule.Matchers[2].Pattern = " nginx "
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate whitespace-sensitive rule: %v", err)
	}
	if rule.Matchers[2].Pattern != " nginx " {
		t.Fatalf("pattern was unexpectedly normalized: %q", rule.Matchers[2].Pattern)
	}
}

func TestRuleAllowsCompleteHeaderAndMD5FaviconMatchers(t *testing.T) {
	rule := validRule()
	rule.Matchers[0].HeaderName = ""
	rule.Matchers[3] = Matcher{
		Target:        EvidenceFaviconHash,
		Operator:      MatchEquals,
		HashAlgorithm: FaviconHashMD5,
		Pattern:       "f49c4a4bde1eec6c0b80c2277c76e3db",
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("validate rule with imported FingerprintHub semantics: %v", err)
	}
}

func validRule() Rule {
	return Rule{
		ID:       "fingerprinthub/nginx",
		SourceID: "fingerprinthub",
		Product: ProductIdentity{
			Vendor:  "nginx",
			Name:    "nginx",
			Version: "1.25",
			CPE:     "cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*",
		},
		Protocols: []Protocol{ProtocolHTTPS, ProtocolHTTP},
		Matchers: []Matcher{
			{Target: EvidenceHeader, Operator: MatchContains, HeaderName: "Server", Pattern: "nginx"},
			{Target: EvidenceBody, Operator: MatchRegex, Pattern: `(?i)<title>.*nginx.*</title>`},
			{Target: EvidenceBanner, Operator: MatchContains, Pattern: "nginx"},
			{Target: EvidenceFaviconHash, Operator: MatchEquals, HashAlgorithm: FaviconHashMMH3, Pattern: "-1460529976"},
		},
	}
}
