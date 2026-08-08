package fingerprint

import (
	"fmt"
	"strings"
	"testing"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

func TestFingerprintHubYAMLRealRulesPreserveWebAndPassiveTCPConditions(t *testing.T) {
	webSnapshot := embeddedVerifiedSnapshot(t, "fingerprinthub-web-yaml")
	webAdapter := fingerprintHubWebYAMLSourceAdapter{}
	webRules, err := webAdapter.Adapt(snapshotSubset(webSnapshot,
		"web-fingerprint/jenkins/jenkins.yaml",
		"web-fingerprint/goharbor/harbor.yaml",
	))
	if err != nil || len(webRules) != 2 || webRules[0].ImportStatus != "executable" || webRules[1].ImportStatus != "executable" {
		t.Fatalf("web YAML rules=%#v err=%v", webRules, err)
	}
	webEngine := projectedRulesEngine(t, webAdapter.SourceKey(), webAdapter, webRules)
	if hasProduct(webEngine.Match(Evidence{Protocol: "http", Headers: map[string]string{"X-Jenkins": "2.452"}}), "jenkins") {
		t.Fatal("Jenkins AND header group matched with one missing condition")
	}
	if !hasProduct(webEngine.Match(Evidence{Protocol: "http", Headers: map[string]string{"X-Jenkins": "2.452", "X-Jenkins-Session": "fixture"}}), "jenkins") {
		t.Fatal("real Jenkins AND header group did not match")
	}
	if !hasProduct(webEngine.Match(Evidence{Protocol: "http", FaviconMD5: "23e8c7bd78e8cd826c5a6073b15068b1"}), "jenkins") {
		t.Fatal("real Jenkins favicon branch did not match")
	}
	if !hasProduct(webEngine.Match(Evidence{Protocol: "https", Body: "<TITLE>Harbor Registry</TITLE>"}), "harbor") {
		t.Fatal("real Harbor case-insensitive regex did not match HTTPS evidence")
	}

	serviceSnapshot := embeddedVerifiedSnapshot(t, "fingerprinthub-service-yaml")
	serviceAdapter := fingerprintHubServiceYAMLSourceAdapter{}
	serviceRules, err := serviceAdapter.Adapt(snapshotSubset(serviceSnapshot, "service-fingerprint/null/ftp/1002551213.yaml"))
	if err != nil || len(serviceRules) != 1 || serviceRules[0].ImportStatus != "executable" {
		t.Fatalf("service YAML rules=%#v err=%v", serviceRules, err)
	}
	serviceEngine := projectedRulesEngine(t, serviceAdapter.SourceKey(), serviceAdapter, serviceRules)
	matches := serviceEngine.Match(NewBannerEvidence("220 fixture FTP server (lukemftpd 1.2) ready.\r\n", false))
	if len(matches) != 1 || matches[0].Product != "lukemftpd" || matches[0].Version != "1.2" {
		t.Fatalf("real passive FTP rule matches=%#v", matches)
	}
}

func TestWhatWebRealJenkinsRuleExtractsHeaderVersion(t *testing.T) {
	snapshot := embeddedVerifiedSnapshot(t, "whatweb")
	adapter := whatWebSourceAdapter{}
	rules, err := adapter.Adapt(snapshotSubset(snapshot, "plugins/jenkins.rb"))
	if err != nil || len(rules) != 1 || rules[0].ImportStatus != "executable" {
		t.Fatalf("WhatWeb Jenkins rules=%#v err=%v", rules, err)
	}
	engine := projectedRulesEngine(t, adapter.SourceKey(), adapter, rules)
	matches := engine.Match(Evidence{Protocol: "http", Headers: map[string]string{"X-Jenkins": "2.452.1"}})
	if len(matches) != 1 || matches[0].Product != "jenkins" || matches[0].Version != "2.452.1" {
		t.Fatalf("WhatWeb Jenkins matches=%#v", matches)
	}
}

func TestWhatWebRealOffsetAndWeakMatchersPreserveUpstreamSemantics(t *testing.T) {
	snapshot := embeddedVerifiedSnapshot(t, "whatweb")
	adapter := whatWebSourceAdapter{}
	rules, err := adapter.Adapt(snapshotSubset(snapshot, "plugins/4d.rb", "plugins/360-web-manager.rb"))
	if err != nil || len(rules) != 2 {
		t.Fatalf("WhatWeb offset/weak rules=%#v err=%v", rules, err)
	}
	byID := make(map[string]model.FingerprintSourceRule, len(rules))
	for _, rule := range rules {
		byID[rule.SourceRuleID] = rule
	}
	if byID["4d"].ImportStatus != "executable" {
		t.Fatalf("4D offset rule=%#v", byID["4d"])
	}
	if byID["360-web-manager"].ImportStatus != "unsupported" || !strings.Contains(byID["360-web-manager"].ImportError, "mixed strong and weak") {
		t.Fatalf("mixed-certainty rule must remain unsupported: %#v", byID["360-web-manager"])
	}
	engine := projectedRulesEngine(t, adapter.SourceKey(), adapter, []model.FingerprintSourceRule{byID["4d"]})
	matches := engine.Match(Evidence{Protocol: "http", Headers: map[string]string{"Server": "4D_v19_SQL/12.3"}})
	if len(matches) != 1 || matches[0].Version != "12.3" {
		t.Fatalf("WhatWeb offset match=%#v", matches)
	}
}

func TestWhatWebWholeHeaderSearchIsNotReclassifiedAsBody(t *testing.T) {
	rule := model.FingerprintSourceRule{
		SourceRuleID: "whole-headers",
		RawContent:   `name "whole-headers"; matches [{ :search=>"headers", :regexp=>/Server: fixture/ }]`,
	}
	if _, err := projectWhatWeb(rule); err == nil || !strings.Contains(err.Error(), "search target") {
		t.Fatalf("whole-header matcher must be unsupported, err=%v", err)
	}
}

func TestWappalyzerRealRulesCoverHeaderMetaScriptURLCookieAndVersion(t *testing.T) {
	snapshot := embeddedVerifiedSnapshot(t, "wappalyzer")
	adapter := wappalyzerAdapter{}
	rules, err := adapter.Adapt(snapshotSubset(snapshot, "src/technologies/n.json"))
	if err != nil {
		t.Fatal(err)
	}
	rules = selectedSourceRules(t, rules, "NagaCommerce", "Naver Maps", "Neos CMS", "NetSuite", "Netlify")
	engine := projectedRulesEngine(t, adapter.SourceKey(), adapter, rules)
	cases := []struct {
		name     string
		evidence Evidence
		product  string
		version  string
	}{
		{"header version", Evidence{Protocol: "http", Headers: map[string]string{"X-Flow-Powered": "Neos/8.3"}}, "neos cms", "8.3"},
		{"meta", Evidence{Protocol: "http", Meta: map[string]string{"generator": "NagaCommerce"}}, "nagacommerce", ""},
		{"script version", Evidence{Protocol: "http", Body: `<script src="https://openapi.map.naver.com/openapi/v3.0/maps.js"></script>`}, "naver maps", "3.0"},
		{"url", Evidence{Protocol: "https", URL: "https://fixture.netlify.app/"}, "netlify", ""},
		{"cookie existence", Evidence{Protocol: "http", Cookies: map[string]string{"ns_ver": ""}}, "netsuite", ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			matches := engine.Match(testCase.evidence)
			match, ok := productMatch(matches, testCase.product)
			if !ok || match.Version != testCase.version {
				t.Fatalf("matches=%#v", matches)
			}
		})
	}
	if hasProduct(engine.Match(Evidence{Protocol: "http", Cookies: map[string]string{}}), "netsuite") {
		t.Fatal("cookie existence matcher matched a missing cookie")
	}
}

func TestWappalyzerEmptyPatternsOnlyMeanNamedFieldExists(t *testing.T) {
	unsupported := model.FingerprintSourceRule{SourceRuleID: "empty-body", RawContent: `{"html":"","url":"","scriptSrc":""}`}
	if _, err := projectWappalyzer(unsupported); err == nil {
		t.Fatal("empty body, URL, and script patterns must not become unconditional exists matchers")
	}
	header := model.FingerprintSourceRule{SourceRuleID: "header-exists", RawContent: `{"headers":{"X-Fixture":""}}`}
	projection, err := projectWappalyzer(header)
	if err != nil || len(projection.Root.Matchers) != 1 || projection.Root.Matchers[0].Operator != "exists" || projection.Root.Matchers[0].Target != "x-fixture" {
		t.Fatalf("named header existence projection=%#v err=%v", projection, err)
	}
}

func TestWappalyzerRealDependencyRulesRemainUnsupported(t *testing.T) {
	snapshot := embeddedVerifiedSnapshot(t, "wappalyzer")
	adapter := wappalyzerAdapter{}
	rules, err := adapter.Adapt(snapshotSubset(snapshot, "src/technologies/a.json"))
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]model.FingerprintSourceRule, len(rules))
	for _, rule := range rules {
		byID[rule.SourceRuleID] = rule
	}
	dependent := byID["AFThemes CoverNews"]
	if dependent.ImportStatus != "unsupported" || !strings.Contains(dependent.ImportError, "requires dependency semantics") {
		t.Fatalf("dependent Wappalyzer rule=%#v", dependent)
	}
	if _, err := projectWappalyzer(dependent); err == nil {
		t.Fatal("dependent Wappalyzer matcher must not be executable without WordPress evidence")
	}
}

func TestProductNormalizationAliasesPreserveSourceNames(t *testing.T) {
	for _, sourceName := range []string{"apache", "Apache HTTP Server", "Apache httpd"} {
		product := normalizedProduct(model.FingerprintProduct{CanonicalName: sourceName})
		if product.CanonicalName != "apache http server" {
			t.Fatalf("source product %q normalized to %q", sourceName, product.CanonicalName)
		}
		if !strings.EqualFold(sourceName, product.CanonicalName) && !strings.Contains(strings.ToLower(product.AliasesJSON), strings.ToLower(sourceName)) {
			t.Fatalf("source product %q missing from aliases %s", sourceName, product.AliasesJSON)
		}
	}
}

func TestApacheCrossSourceTCPAndWebRulesConvergeWithoutLosingSourceNames(t *testing.T) {
	db := openFingerprintTestDB(t)
	fixtures := []struct {
		sourceKey, sourceProduct, protocol, evidenceType, target string
	}{
		{"source-tcp", "Apache httpd", "tcp", "tcp_banner", "banner"},
		{"source-header", "apache", "http", "http_header", "server"},
		{"source-body", "Apache HTTP Server", "http", "http_body", "body"},
	}
	for index, fixture := range fixtures {
		content := fmt.Sprintf("apache-%d", index)
		product := normalizedProduct(model.FingerprintProduct{CanonicalName: fixture.sourceProduct})
		_, err := storage.ImportFingerprintBatch(db, storage.FingerprintImportBatch{
			Source:      model.FingerprintSource{SourceKey: fixture.sourceKey, RepositoryURL: "local://" + fixture.sourceKey, Status: "enabled"},
			Import:      model.FingerprintImport{Commit: "fixture", ContentSHA256: content, AdapterVersion: "alias-fixture-v1", ManifestJSON: `{}`, RuleTotal: 1, ExecutableTotal: 1},
			Rules:       []model.FingerprintSourceRule{{SourceRuleID: content, SourcePath: content, ContentSHA256: content, RawContent: fixture.sourceProduct, ImportStatus: "executable"}},
			Projections: []model.FingerprintRuleProjection{{SourcePath: content, ContentSHA256: content, SourceProduct: fixture.sourceProduct, Product: product, Protocol: fixture.protocol, Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: fixture.evidenceType, Target: fixture.target, Operator: "contains_ci", Value: "Apache"}}}}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	engine, err := LoadActiveEngine(db)
	if err != nil {
		t.Fatal(err)
	}
	matches := append(engine.Match(Evidence{Protocol: "tcp", Banner: "Apache httpd 2.4.62"}), engine.Match(Evidence{Protocol: "http", Headers: map[string]string{"Server": "Apache/2.4.62"}, Body: "Apache HTTP Server"})...)
	sourceProducts := make(map[string]struct{})
	for _, match := range matches {
		if match.Product != "apache http server" {
			t.Fatalf("cross-source Apache product=%q match=%#v", match.Product, match)
		}
		sourceProducts[match.SourceProduct] = struct{}{}
	}
	if len(matches) != 3 || len(sourceProducts) != 3 {
		t.Fatalf("Apache matches=%d source products=%v", len(matches), sourceProducts)
	}
}

func TestWappalyzerApacheKeepsCanonicalIdentitySourceNameAndCPE(t *testing.T) {
	snapshot := embeddedVerifiedSnapshot(t, "wappalyzer")
	adapter := wappalyzerAdapter{}
	rules, err := adapter.Adapt(snapshotSubset(snapshot, "src/technologies/a.json"))
	if err != nil {
		t.Fatal(err)
	}
	rules = selectedSourceRules(t, rules, "Apache HTTP Server")
	engine := projectedRulesEngine(t, adapter.SourceKey(), adapter, rules)
	match, ok := productMatch(engine.Match(Evidence{Protocol: "http", Headers: map[string]string{"Server": "Apache/2.4.62"}}), "apache http server")
	if !ok || match.SourceProduct != "Apache HTTP Server" || match.Version != "2.4.62" || match.CPE != "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*" {
		t.Fatalf("Apache Wappalyzer match=%#v ok=%t", match, ok)
	}
}

func TestWappalyzerConfidenceAndConditionalVersionRemainFaithful(t *testing.T) {
	low := model.FingerprintSourceRule{SourceRuleID: "low", RawContent: `{"html":"fixture\\;confidence:50"}`}
	projection, err := projectWappalyzer(low)
	if err != nil || !projection.SoftMatch {
		t.Fatalf("low-confidence projection=%#v err=%v", projection, err)
	}
	mixed := model.FingerprintSourceRule{SourceRuleID: "mixed", RawContent: `{"html":["strong","weak\\;confidence:50"]}`}
	if _, err := projectWappalyzer(mixed); err == nil || !strings.Contains(err.Error(), "mixed strong") {
		t.Fatalf("mixed confidence must be unsupported, err=%v", err)
	}

	snapshot := embeddedVerifiedSnapshot(t, "wappalyzer")
	adapter := wappalyzerAdapter{}
	rules, err := adapter.Adapt(snapshotSubset(snapshot, "src/technologies/j.json"))
	if err != nil {
		t.Fatal(err)
	}
	rules = selectedSourceRules(t, rules, "jQuery Migrate")
	engine := projectedRulesEngine(t, adapter.SourceKey(), adapter, rules)
	match, ok := productMatch(engine.Match(Evidence{Protocol: "http", Body: `<script src="jquery-migrate.min.js?ver=3.4.1"></script>`}), "jquery migrate")
	if !ok || match.Version != "3.4.1" {
		t.Fatalf("conditional version match=%#v ok=%t", match, ok)
	}
}

func embeddedVerifiedSnapshot(t *testing.T, sourceKey string) VerifiedSnapshot {
	t.Helper()
	registry, err := NewEmbeddedRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	source, ok := registry.source(sourceKey)
	if !ok {
		t.Fatalf("embedded source %s not found", sourceKey)
	}
	snapshot, err := VerifyArchive(source, registry.EmbeddedArchives[sourceKey])
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func snapshotSubset(snapshot VerifiedSnapshot, paths ...string) VerifiedSnapshot {
	files := make(map[string][]byte, len(paths))
	for _, sourcePath := range paths {
		files[sourcePath] = append([]byte(nil), snapshot.Files[sourcePath]...)
	}
	return VerifiedSnapshot{Manifest: snapshot.Manifest, Files: files}
}

func selectedSourceRules(t *testing.T, rules []model.FingerprintSourceRule, sourceRuleIDs ...string) []model.FingerprintSourceRule {
	t.Helper()
	byID := make(map[string]model.FingerprintSourceRule, len(rules))
	for _, rule := range rules {
		byID[rule.SourceRuleID] = rule
	}
	selected := make([]model.FingerprintSourceRule, 0, len(sourceRuleIDs))
	for _, sourceRuleID := range sourceRuleIDs {
		rule, exists := byID[sourceRuleID]
		if !exists || rule.ImportStatus != "executable" {
			t.Fatalf("source rule %s is not executable", sourceRuleID)
		}
		selected = append(selected, rule)
	}
	return selected
}

func projectedRulesEngine(t *testing.T, sourceKey string, adapter SourceAdapter, rules []model.FingerprintSourceRule) *Engine {
	t.Helper()
	db := openFingerprintTestDB(t)
	projections, err := projectExecutableRules(adapter, rules)
	if err != nil {
		t.Fatal(err)
	}
	_, err = storage.ImportFingerprintBatch(db, storage.FingerprintImportBatch{
		Source: model.FingerprintSource{SourceKey: sourceKey, RepositoryURL: "local://real-fixture", Status: "enabled"},
		Import: model.FingerprintImport{Commit: "embedded-real-fixture", ContentSHA256: "embedded-real-fixture", AdapterVersion: adapterVersion(adapter), ManifestJSON: `{}`, RuleTotal: len(rules), ExecutableTotal: len(rules)},
		Rules:  rules, Projections: projections,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := LoadActiveEngine(db)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func productMatch(matches []Match, product string) (Match, bool) {
	for _, match := range matches {
		if match.Product == product {
			return match, true
		}
	}
	return Match{}, false
}
