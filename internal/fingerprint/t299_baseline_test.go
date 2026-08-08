package fingerprint

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type t299Baseline struct {
	Revision         string                `json:"revision"`
	Fixtures         []t299Fixture         `json:"fixtures"`
	SemanticFixtures []t299SemanticFixture `json:"semantic_fixtures"`
}

type t299Fixture struct {
	Category        string `json:"category"`
	SourceKey       string `json:"source_key"`
	SourceCommit    string `json:"source_commit"`
	SourceRuleID    string `json:"source_rule_id"`
	Protocol        string `json:"protocol"`
	EvidenceType    string `json:"evidence_type"`
	Target          string `json:"target"`
	Operator        string `json:"operator"`
	ObservedValue   string `json:"observed_value"`
	ExpectedProduct string `json:"expected_product"`
	ExpectedVersion string `json:"expected_version"`
	ExpectedCPE     string `json:"expected_cpe"`
}

type t299EvidenceFixture struct {
	Protocol      string            `json:"protocol"`
	Banner        string            `json:"banner"`
	Headers       map[string]string `json:"headers"`
	Meta          map[string]string `json:"meta"`
	Cookies       map[string]string `json:"cookies"`
	Title         string            `json:"title"`
	Body          string            `json:"body"`
	URL           string            `json:"url"`
	FaviconMD5    string            `json:"favicon_md5"`
	FaviconMMH3   string            `json:"favicon_mmh3"`
	FaviconSHA256 string            `json:"favicon_sha256"`
}

type t299SemanticFixture struct {
	CaseID          string              `json:"case_id"`
	Category        string              `json:"category"`
	SourceKey       string              `json:"source_key"`
	SourceCommit    string              `json:"source_commit"`
	SourceRuleID    string              `json:"source_rule_id"`
	Mode            string              `json:"mode"`
	ProbeName       string              `json:"probe_name"`
	ProbePort       int                 `json:"probe_port"`
	Service         string              `json:"service"`
	Evidence        t299EvidenceFixture `json:"evidence"`
	Negative        t299EvidenceFixture `json:"negative_evidence"`
	Features        []string            `json:"features"`
	EvidenceOrigin  string              `json:"evidence_origin"`
	ExpectedProduct string              `json:"expected_product"`
	ExpectedVersion string              `json:"expected_version"`
	ExpectedCPE     string              `json:"expected_cpe"`
	ExpectedSoft    bool                `json:"expected_soft"`
}

func TestT299FixedExecutableCoverageBaseline(t *testing.T) {
	raw, err := os.ReadFile("testdata/t299/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var baseline t299Baseline
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.Revision != "t299-v3" || len(baseline.Fixtures) != 120 || len(baseline.SemanticFixtures) != 31 {
		t.Fatalf("baseline revision=%q fixtures=%d semantic=%d", baseline.Revision, len(baseline.Fixtures), len(baseline.SemanticFixtures))
	}

	db := openFingerprintTestDB(t)
	registry, err := NewEmbeddedRegistry(db)
	if err != nil {
		t.Fatal(err)
	}
	commits := make(map[string]string, len(registry.Manifest.Sources))
	for _, source := range registry.Manifest.Sources {
		commits[source.SourceKey] = source.Commit
		if _, err := registry.Import(context.Background(), source.SourceKey, ""); err != nil {
			t.Fatalf("import %s: %v", source.SourceKey, err)
		}
	}
	engine, err := LoadActiveEngine(db)
	if err != nil {
		t.Fatal(err)
	}

	categoryCounts := make(map[string]int)
	seen := make(map[string]struct{}, len(baseline.Fixtures))
	for _, fixture := range baseline.Fixtures {
		fixture := fixture
		t.Run(fixture.Category+"/"+fixture.SourceKey+"/"+fixture.SourceRuleID, func(t *testing.T) {
			key := fixture.SourceKey + "\x00" + fixture.SourceRuleID
			if _, exists := seen[key]; exists {
				t.Fatalf("duplicate fixed rule %s/%s", fixture.SourceKey, fixture.SourceRuleID)
			}
			seen[key] = struct{}{}
			categoryCounts[fixture.Category]++
			if fixture.SourceCommit == "" || commits[fixture.SourceKey] != fixture.SourceCommit {
				t.Fatalf("source commit=%q, active frozen commit=%q", fixture.SourceCommit, commits[fixture.SourceKey])
			}
			if fixture.SourceRuleID == "" || fixture.ExpectedProduct == "" || fixture.Protocol == "" || fixture.EvidenceType == "" || fixture.Operator == "" {
				t.Fatalf("incomplete fixed fixture: %#v", fixture)
			}
			matches := engine.Match(t299Evidence(fixture))
			for _, match := range matches {
				if match.SourceKey != fixture.SourceKey || match.SourceRuleID != fixture.SourceRuleID {
					continue
				}
				if match.Product != fixture.ExpectedProduct || match.Version != fixture.ExpectedVersion || match.CPE != fixture.ExpectedCPE {
					t.Fatalf("match product/version/CPE=%q/%q/%q, want %q/%q/%q", match.Product, match.Version, match.CPE, fixture.ExpectedProduct, fixture.ExpectedVersion, fixture.ExpectedCPE)
				}
				return
			}
			t.Fatalf("fixed executable rule did not match evidence: %#v", fixture)
		})
	}
	for _, category := range []string{"web_framework", "middleware", "database_cache", "remote_management", "container_k8s", "china_common"} {
		if categoryCounts[category] != 20 {
			t.Fatalf("category %s fixtures=%d, want 20", category, categoryCounts[category])
		}
	}

	featureCounts := make(map[string]int)
	sourceCounts := make(map[string]int)
	protocolCounts := make(map[string]int)
	for _, fixture := range baseline.Fixtures {
		sourceCounts[fixture.SourceKey]++
		protocolCounts[fixture.Protocol]++
	}
	caseIDs := make(map[string]struct{}, len(baseline.SemanticFixtures))
	for _, fixture := range baseline.SemanticFixtures {
		fixture := fixture
		sourceCounts[fixture.SourceKey]++
		if fixture.Mode == "nmap_active" {
			protocolCounts["nmap_active"]++
		} else {
			protocolCounts[fixture.Evidence.Protocol]++
		}
		t.Run("semantic/"+fixture.CaseID, func(t *testing.T) {
			if _, duplicate := caseIDs[fixture.CaseID]; duplicate || fixture.CaseID == "" {
				t.Fatalf("duplicate or empty semantic case ID %q", fixture.CaseID)
			}
			caseIDs[fixture.CaseID] = struct{}{}
			if commits[fixture.SourceKey] != fixture.SourceCommit {
				t.Fatalf("source commit=%q, active frozen commit=%q", fixture.SourceCommit, commits[fixture.SourceKey])
			}
			if fixture.EvidenceOrigin != "curated-real-response" {
				t.Fatalf("semantic fixture %s has non-curated evidence origin %q", fixture.CaseID, fixture.EvidenceOrigin)
			}
			var status string
			if err := db.QueryRow(`
				SELECT source_rule.import_status
				FROM fingerprint_source_rules AS source_rule
				JOIN fingerprint_imports AS fingerprint_import ON fingerprint_import.id = source_rule.fingerprint_import_id AND fingerprint_import.is_active = 1
				JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id
				WHERE source.source_key = ? AND source_rule.source_rule_id = ?`, fixture.SourceKey, fixture.SourceRuleID).Scan(&status); err != nil || status != "executable" {
				t.Fatalf("fixed semantic rule status=%q err=%v", status, err)
			}
			match, ok := t299SemanticMatch(engine, fixture, fixture.Evidence)
			if !ok || match.Product != fixture.ExpectedProduct || match.Version != fixture.ExpectedVersion || match.CPE != fixture.ExpectedCPE || match.Soft != fixture.ExpectedSoft {
				t.Fatalf("semantic match=%#v ok=%t, fixture=%#v", match, ok, fixture)
			}
			if _, matched := t299SemanticMatch(engine, fixture, fixture.Negative); matched {
				t.Fatal("fixed negative evidence unexpectedly matched the exact source rule")
			}
			for _, feature := range fixture.Features {
				featureCounts[feature]++
				assertT299Feature(t, db, fixture, feature, match)
			}
		})
	}
	for sourceKey := range commits {
		if sourceCounts[sourceKey] < 1 {
			t.Fatalf("source %s has no fixed executable baseline fixture", sourceKey)
		}
	}
	for protocol, minimum := range map[string]int{"http": 20, "tcp": 10, "nmap_active": 5} {
		if protocolCounts[protocol] < minimum {
			t.Fatalf("protocol %s fixtures=%d, want at least %d", protocol, protocolCounts[protocol], minimum)
		}
	}
	for feature, minimum := range map[string]int{
		"tcp_banner": 10, "nmap_active": 5, "http_header": 3, "http_body": 3,
		"favicon_hash": 1, "html_meta": 1, "http_cookie": 1, "http_url": 1,
		"group_all": 2, "group_any": 2, "regex": 20, "version": 10, "cpe": 10,
	} {
		if featureCounts[feature] < minimum {
			t.Fatalf("semantic feature %s fixtures=%d, want at least %d", feature, featureCounts[feature], minimum)
		}
	}
}

func t299SemanticMatch(engine *Engine, fixture t299SemanticFixture, observed t299EvidenceFixture) (Match, bool) {
	var matches []Match
	if fixture.Mode == "nmap_active" {
		allowed := false
		for _, probe := range engine.NmapTCPProbesForEndpoint(fixture.ProbePort, fixture.Service) {
			if probe.Name == fixture.ProbeName {
				allowed = true
				break
			}
		}
		if !allowed {
			return Match{}, false
		}
		matches = engine.MatchNmapTCPProbeResponse(fixture.ProbeName, []byte(observed.Banner))
	} else {
		matches = engine.Match(Evidence{
			Protocol: observed.Protocol, Banner: observed.Banner, Headers: observed.Headers, Meta: observed.Meta,
			Cookies: observed.Cookies, Title: observed.Title, Body: observed.Body, URL: observed.URL,
			FaviconMD5: observed.FaviconMD5, FaviconMMH3: observed.FaviconMMH3, FaviconSHA256: observed.FaviconSHA256,
		})
	}
	for _, match := range matches {
		if match.SourceKey == fixture.SourceKey && match.SourceRuleID == fixture.SourceRuleID {
			return match, true
		}
	}
	return Match{}, false
}

func assertT299Feature(t *testing.T, db queryRower, fixture t299SemanticFixture, feature string, match Match) {
	t.Helper()
	switch feature {
	case "version":
		if match.Version == "" {
			t.Fatal("version fixture returned an empty version")
		}
	case "cpe":
		if match.CPE == "" {
			t.Fatal("CPE fixture returned an empty CPE")
		}
	case "soft":
		if !match.Soft {
			t.Fatal("soft upstream rule became a hard match")
		}
	case "group_all", "group_any", "regex":
		operator := strings.TrimPrefix(feature, "group_")
		query := `
			SELECT COUNT(*)
			FROM fingerprint_source_rules AS source_rule
			JOIN fingerprint_imports AS fingerprint_import ON fingerprint_import.id = source_rule.fingerprint_import_id AND fingerprint_import.is_active = 1
			JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id
			JOIN fingerprint_rules AS rule ON rule.fingerprint_source_rule_id = source_rule.id
			JOIN fingerprint_match_groups AS match_group ON match_group.fingerprint_rule_id = rule.id
			WHERE source.source_key = ? AND source_rule.source_rule_id = ?`
		args := []interface{}{fixture.SourceKey, fixture.SourceRuleID}
		if feature == "regex" {
			query += ` AND EXISTS (SELECT 1 FROM fingerprint_matchers AS matcher WHERE matcher.fingerprint_match_group_id = match_group.id AND matcher.operator IN ('regex', 'regex_ci'))`
		} else {
			query += ` AND match_group.operator = ?`
			args = append(args, operator)
		}
		var count int
		if err := db.QueryRow(query, args...).Scan(&count); err != nil || count == 0 {
			t.Fatalf("feature %s is not present in frozen projection: count=%d err=%v", feature, count, err)
		}
	case "tcp_banner", "http_header", "http_body", "favicon_hash", "html_meta", "http_cookie", "http_url":
		for _, hit := range match.MatcherHits {
			if hit.EvidenceType == feature {
				return
			}
		}
		t.Fatalf("feature %s is not present in matcher evidence: %#v", feature, match.MatcherHits)
	}
}

type queryRower interface {
	QueryRow(query string, args ...interface{}) *sql.Row
}

func t299Evidence(fixture t299Fixture) Evidence {
	evidence := Evidence{Protocol: fixture.Protocol, Headers: map[string]string{}, Meta: map[string]string{}, Cookies: map[string]string{}}
	switch fixture.EvidenceType {
	case "http_body":
		evidence.Body = fixture.ObservedValue
	case "http_header":
		if fixture.Target == "" {
			evidence.Headers["X-T299"] = fixture.ObservedValue
		} else {
			evidence.Headers[fixture.Target] = fixture.ObservedValue
		}
	case "http_cookie":
		evidence.Cookies[strings.ToLower(fixture.Target)] = fixture.ObservedValue
	case "html_meta":
		evidence.Meta[strings.ToLower(fixture.Target)] = fixture.ObservedValue
	case "html_title":
		evidence.Title = fixture.ObservedValue
	case "http_url":
		evidence.URL = fixture.ObservedValue
	case "favicon_hash":
		switch fixture.Target {
		case "md5":
			evidence.FaviconMD5 = fixture.ObservedValue
		case "mmh3":
			evidence.FaviconMMH3 = fixture.ObservedValue
		case "sha256":
			evidence.FaviconSHA256 = fixture.ObservedValue
		}
	case "status_code":
		// The fixed simple baseline currently contains no status-only rule.
	case "tcp_banner":
		evidence.Banner = fixture.ObservedValue
	}
	return evidence
}
