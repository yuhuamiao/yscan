package fingerprint

import (
	"context"
	"database/sql"
	"regexp"
	"strings"
	"testing"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

func TestActiveEngineMatchesEmbeddedFingerprintHubAndEHoleRules(t *testing.T) {
	db := openFingerprintTestDB(t)
	registry, err := NewEmbeddedRegistry(db)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	for _, source := range registry.Manifest.Sources {
		if _, err := registry.Import(context.Background(), source.SourceKey, ""); err != nil {
			t.Fatalf("import %s: %v", source.SourceKey, err)
		}
	}
	engine, err := LoadActiveEngine(db)
	if err != nil {
		t.Fatalf("load engine: %v", err)
	}
	if !hasSourceProduct(engine.Match(Evidence{Body: `powered by <a href="http://dotclear.org/`}), "fingerprinthub-web-v4", "dotclear") {
		t.Fatal("FingerprintHub word matcher did not match dotclear")
	}
	if !hasSourceProduct(engine.Match(Evidence{Body: `powered by <a href="http://dotclear.org/`}), "fingerprinthub-web-v3", "dotclear") {
		t.Fatal("FingerprintHub v3 keyword matcher did not match dotclear")
	}
	if !hasProduct(engine.Match(Evidence{Body: `/seeyon/USER-DATA/IMAGES/LOGIN/login.gif`}), "致远oa") {
		t.Fatal("EHole keyword matcher did not match")
	}
	if !hasSourceProduct(engine.Match(Evidence{FaviconMMH3: "463802404"}), "fingerprinthub-web-v4", "ray") {
		t.Fatal("FingerprintHub real MMH3 favicon rule did not match")
	}
	if !hasSourceProduct(engine.Match(Evidence{FaviconMMH3: "-748565678"}), "ehole", "dreamer cms") {
		t.Fatal("EHole real MMH3 favicon rule did not match")
	}
	var rawExecutable, normalized int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_source_rules WHERE import_status = 'executable'`).Scan(&rawExecutable); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_rules WHERE status = 'executable'`).Scan(&normalized); err != nil {
		t.Fatal(err)
	}
	if normalized != rawExecutable {
		t.Fatalf("normalized rules = %d, want every executable source rule (%d)", normalized, rawExecutable)
	}
}

func TestFingerprintHubV3PreservesStatusHeaderAndKeywordRelations(t *testing.T) {
	engine := fixtureProjectedEngine(t, "fingerprinthub-web-v3", fingerprintHubV3Adapter{}, `{"name":"Fixture","status_code":200,"headers":{"Server":"fixture"},"keyword":["first","second"]}`)
	if !hasProduct(engine.Match(Evidence{StatusCode: 200, Headers: map[string]string{"Server": "fixture server"}, Body: "first second"}), "fixture") {
		t.Fatal("complete v3 evidence must match")
	}
	if hasProduct(engine.Match(Evidence{StatusCode: 200, Headers: map[string]string{"Server": "fixture server"}, Body: "first"}), "fixture") {
		t.Fatal("v3 keyword relation must preserve all declared values")
	}
}

func TestStructuredFieldRegexRequiresTheNamedFieldToExist(t *testing.T) {
	matcher := compiledMatcher{evidenceType: "http_header", target: "x-fixture", operator: "regex", value: "^(.*)$", expression: regexp.MustCompile("^(.*)$")}
	if outcome := matchNormalizedMatcher(matcher, Evidence{Headers: map[string]string{}}, ""); outcome.matched {
		t.Fatal("header regex matched a missing named header")
	}
	if outcome := matchNormalizedMatcher(matcher, Evidence{Headers: map[string]string{"X-Fixture": ""}}, ""); !outcome.matched {
		t.Fatal("header regex did not match an explicitly present empty header")
	}
}

func TestFscanNativeRuleAndMD5Matching(t *testing.T) {
	regexEngine := fixtureProjectedEngine(t, "fscan-native-web", fscanAdapter{}, `{Name: "宝塔", Type: "code", Rule: "(安全入口校验失败)"}`)
	if !hasProduct(regexEngine.Match(Evidence{Body: "安全入口校验失败"}), "宝塔") {
		t.Fatal("fscan code regex did not match body evidence")
	}
	md5Engine := fixtureProjectedEngine(t, "fscan-native-web", fscanAdapter{}, `{"BIG-IP", "04d9541338e525258daf47cc844d59f3"}`)
	if !hasProduct(md5Engine.Match(Evidence{FaviconMD5: "04d9541338e525258daf47cc844d59f3"}), "big-ip") {
		t.Fatal("fscan MD5 rule did not match favicon evidence")
	}
}

func TestActiveEnginePreservesLegacyBannerBehavior(t *testing.T) {
	db := openFingerprintTestDB(t)
	_, err := storage.ImportFingerprintBatch(db, storage.FingerprintImportBatch{
		Source:      model.FingerprintSource{SourceKey: legacyBannerSourceKey, RepositoryURL: "local://banner", Status: "enabled"},
		Import:      model.FingerprintImport{Commit: "fixture", ContentSHA256: "fixture", ManifestJSON: `{}`, RuleTotal: 1, ExecutableTotal: 1},
		Rules:       []model.FingerprintSourceRule{{SourceRuleID: "banner:1", SourcePath: "banner/1.json", ContentSHA256: "rule", RawContent: `{"service_name":"nginx","banner_pattern":"nginx","match_type":"contains"}`, ImportStatus: "executable"}},
		Projections: []model.FingerprintRuleProjection{{SourcePath: "banner/1.json", ContentSHA256: "rule", Product: model.FingerprintProduct{CanonicalName: "nginx"}, Protocol: "tcp", Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: "tcp_banner", Target: "banner", Operator: "contains_ci", Value: "nginx"}}}}},
	})
	if err != nil {
		t.Fatalf("import legacy fixture: %v", err)
	}
	engine, err := LoadActiveEngine(db)
	if err != nil {
		t.Fatalf("load engine: %v", err)
	}
	if got := engine.MatchBanner("HTTP/1.1 200 OK\r\nServer: nginx\r\n"); got != "nginx" {
		t.Fatalf("legacy banner match = %q", got)
	}
}

func TestLegacyBannerEngineExcludesThirdPartyRules(t *testing.T) {
	db := openFingerprintTestDB(t)
	for _, batch := range []storage.FingerprintImportBatch{
		{
			Source:      model.FingerprintSource{SourceKey: legacyBannerSourceKey, RepositoryURL: "local://banner", Status: "enabled"},
			Import:      model.FingerprintImport{Commit: "legacy", ContentSHA256: "legacy", ManifestJSON: `{}`, RuleTotal: 1, ExecutableTotal: 1},
			Rules:       []model.FingerprintSourceRule{{SourceRuleID: "legacy", SourcePath: "legacy", ContentSHA256: "legacy", RawContent: "legacy", ImportStatus: "executable"}},
			Projections: []model.FingerprintRuleProjection{{SourcePath: "legacy", ContentSHA256: "legacy", Product: model.FingerprintProduct{CanonicalName: "legacy-product"}, Protocol: "tcp", Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: "tcp_banner", Operator: "contains", Value: "LEGACY"}}}}},
		},
		{
			Source:      model.FingerprintSource{SourceKey: "third-party", RepositoryURL: "local://third-party", Status: "enabled"},
			Import:      model.FingerprintImport{Commit: "third", ContentSHA256: "third", ManifestJSON: `{}`, RuleTotal: 1, ExecutableTotal: 1},
			Rules:       []model.FingerprintSourceRule{{SourceRuleID: "third", SourcePath: "third", ContentSHA256: "third", RawContent: "third", ImportStatus: "executable"}},
			Projections: []model.FingerprintRuleProjection{{SourcePath: "third", ContentSHA256: "third", Product: model.FingerprintProduct{CanonicalName: "third-product"}, Protocol: "tcp", Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: "tcp_banner", Operator: "contains", Value: "THIRD"}}}}},
		},
	} {
		if _, err := storage.ImportFingerprintBatch(db, batch); err != nil {
			t.Fatal(err)
		}
	}
	engine, err := LoadActiveLegacyBannerEngine(db)
	if err != nil {
		t.Fatal(err)
	}
	if got := engine.MatchBanner("LEGACY"); got != "legacy-product" {
		t.Fatalf("legacy match=%q", got)
	}
	if got := engine.MatchBanner("THIRD"); got != "" {
		t.Fatalf("third-party rule leaked into legacy engine: %q", got)
	}
}

func TestPassiveIndexSeparatesProtocolAndEvidenceType(t *testing.T) {
	db := openFingerprintTestDB(t)
	_, err := storage.ImportFingerprintBatch(db, storage.FingerprintImportBatch{
		Source: model.FingerprintSource{SourceKey: "index-fixture", RepositoryURL: "local://index", Status: "enabled"},
		Import: model.FingerprintImport{Commit: "index", ContentSHA256: "index", ManifestJSON: `{}`, RuleTotal: 3, ExecutableTotal: 3},
		Rules: []model.FingerprintSourceRule{
			{SourceRuleID: "tcp", SourcePath: "tcp", ContentSHA256: "tcp", RawContent: "tcp", ImportStatus: "executable"},
			{SourceRuleID: "body", SourcePath: "body", ContentSHA256: "body", RawContent: "body", ImportStatus: "executable"},
			{SourceRuleID: "header", SourcePath: "header", ContentSHA256: "header", RawContent: "header", ImportStatus: "executable"},
		},
		Projections: []model.FingerprintRuleProjection{
			{SourcePath: "tcp", ContentSHA256: "tcp", Product: model.FingerprintProduct{CanonicalName: "tcp-product"}, Protocol: "tcp", Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: "tcp_banner", Operator: "contains", Value: "TCP"}}}},
			{SourcePath: "body", ContentSHA256: "body", Product: model.FingerprintProduct{CanonicalName: "body-product"}, Protocol: "http", Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: "http_body", Operator: "contains", Value: "BODY"}}}},
			{SourcePath: "header", ContentSHA256: "header", Product: model.FingerprintProduct{CanonicalName: "header-product"}, Protocol: "http", Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: "http_header", Target: "server", Operator: "contains", Value: "HEADER"}}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := LoadActiveEngine(db)
	if err != nil {
		t.Fatal(err)
	}
	httpEvidence := Evidence{Protocol: "http", Body: "BODY"}
	if candidates := engine.candidateRules(httpEvidence); len(candidates) != 1 || candidates[0].product != "body-product" {
		t.Fatalf("HTTP candidates=%v", candidateProducts(candidates))
	}
	if !hasProduct(engine.Match(Evidence{Protocol: "https", Body: "BODY"}), "body-product") {
		t.Fatal("HTTPS evidence did not reuse HTTP rules")
	}
	tcpEvidence := NewBannerEvidence("TCP", false)
	if candidates := engine.candidateRules(tcpEvidence); len(candidates) != 1 || candidates[0].product != "tcp-product" {
		t.Fatalf("TCP candidates=%v", candidateProducts(candidates))
	}
}

func candidateProducts(rules []*compiledRule) []string {
	result := make([]string, 0, len(rules))
	for _, rule := range rules {
		result = append(result, rule.product)
	}
	return result
}

func TestRunEngineCacheReusesRevisionAndEvictsAtCapacity(t *testing.T) {
	db := openFingerprintTestDB(t)
	first, err := storage.ImportFingerprintBatch(db, projectionRevisionFixture("adapter-a", "alpha", "HELLO"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE scan_task_run_fingerprint_imports (scan_task_run_id INTEGER NOT NULL, fingerprint_import_id INTEGER NOT NULL, PRIMARY KEY (scan_task_run_id, fingerprint_import_id))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO scan_task_run_fingerprint_imports VALUES (1, ?), (2, ?)`, first.ID, first.ID); err != nil {
		t.Fatal(err)
	}
	cache := NewRunEngineCache(1)
	firstEngine, err := cache.Load(db, 1)
	if err != nil {
		t.Fatal(err)
	}
	sameEngine, err := cache.Load(db, 2)
	if err != nil || sameEngine != firstEngine {
		t.Fatalf("same revision was not reused: same=%t err=%v", sameEngine == firstEngine, err)
	}
	second, err := storage.ImportFingerprintBatch(db, projectionRevisionFixture("adapter-b", "beta", "HELLO"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO scan_task_run_fingerprint_imports VALUES (3, ?)`, second.ID); err != nil {
		t.Fatal(err)
	}
	secondEngine, err := cache.Load(db, 3)
	if err != nil || secondEngine == firstEngine || len(cache.entries) != 1 {
		t.Fatalf("bounded cache second=%p first=%p entries=%d err=%v", secondEngine, firstEngine, len(cache.entries), err)
	}
	reloaded, err := cache.Load(db, 1)
	if err != nil || reloaded == firstEngine || !hasProduct(reloaded.Match(NewBannerEvidence("HELLO", false)), "alpha") {
		t.Fatalf("evicted frozen revision was not correctly reloaded: err=%v", err)
	}
}

func TestRunEngineUsesRoleFrozenInRuleProjection(t *testing.T) {
	db := openFingerprintTestDB(t)
	firstBatch := projectionRoleRevisionFixture("role-a", "web_server", "web_server")
	first, err := storage.ImportFingerprintBatch(db, firstBatch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE scan_task_run_fingerprint_imports (scan_task_run_id INTEGER NOT NULL, fingerprint_import_id INTEGER NOT NULL, PRIMARY KEY (scan_task_run_id, fingerprint_import_id))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO scan_task_run_fingerprint_imports VALUES (1, ?)`, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.ImportFingerprintBatch(db, projectionRoleRevisionFixture("role-b", "application", "")); err != nil {
		t.Fatal(err)
	}

	historical, err := LoadRunEngine(db, 1)
	if err != nil {
		t.Fatal(err)
	}
	historicalMatches := historical.Match(NewBannerEvidence("ROLE-FIXTURE", false))
	if len(historicalMatches) != 1 || historicalMatches[0].ProductRole != "web_server" || historicalMatches[0].ExclusiveGroup != "web_server" {
		t.Fatalf("historical role changed after import upgrade: %#v", historicalMatches)
	}
	active, err := LoadActiveEngine(db)
	if err != nil {
		t.Fatal(err)
	}
	activeMatches := active.Match(NewBannerEvidence("ROLE-FIXTURE", false))
	if len(activeMatches) != 1 || activeMatches[0].ProductRole != "application" || activeMatches[0].ExclusiveGroup != "" {
		t.Fatalf("active role did not use new projection: %#v", activeMatches)
	}
}

func BenchmarkT307IndexedActiveMatch(b *testing.B) {
	db := openFingerprintBenchmarkDB(b)
	registry, err := NewEmbeddedRegistry(db)
	if err != nil {
		b.Fatal(err)
	}
	for _, source := range registry.Manifest.Sources {
		if _, err := registry.Import(context.Background(), source.SourceKey, ""); err != nil {
			b.Fatal(err)
		}
	}
	engine, err := LoadActiveEngine(db)
	if err != nil {
		b.Fatal(err)
	}
	evidence := Evidence{Protocol: "http", StatusCode: 200, Headers: map[string]string{"Server": "nginx/1.27.5", "X-Jenkins": "2.452.1"}, Title: "Jenkins", Body: "Jenkins nginx", URL: "http://127.0.0.1/"}
	totalRules := len(engine.passiveRules)
	candidateRules := len(engine.candidateRules(evidence))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		_ = engine.Match(evidence)
	}
	b.StopTimer()
	b.ReportMetric(float64(totalRules), "total_rules")
	b.ReportMetric(float64(candidateRules), "candidate_rules")
}

func openFingerprintBenchmarkDB(b *testing.B) *sql.DB {
	b.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE fingerprint_sources (id INTEGER PRIMARY KEY AUTOINCREMENT, source_key TEXT NOT NULL UNIQUE, repository_url TEXT NOT NULL, license TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')))`,
		`CREATE TABLE fingerprint_source_bootstrap_diagnostics (source_key TEXT PRIMARY KEY, last_error TEXT NOT NULL DEFAULT '', last_failed_at TEXT, resolved_at TEXT, updated_at TEXT NOT NULL DEFAULT (datetime('now')))`,
		`CREATE TABLE fingerprint_imports (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint_source_id INTEGER NOT NULL, commit_hash TEXT NOT NULL, content_sha256 TEXT NOT NULL, upstream_content_sha256 TEXT NOT NULL DEFAULT '', adapter_version TEXT NOT NULL DEFAULT 'legacy-v1', projection_sha256 TEXT NOT NULL DEFAULT '', manifest_json TEXT NOT NULL, rule_total INTEGER NOT NULL, executable_total INTEGER NOT NULL, unsupported_total INTEGER NOT NULL, import_error_total INTEGER NOT NULL, error_summary TEXT, is_active INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(fingerprint_source_id, commit_hash, content_sha256))`,
		`CREATE TABLE fingerprint_source_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint_import_id INTEGER NOT NULL, source_rule_id TEXT, source_path TEXT NOT NULL, content_sha256 TEXT NOT NULL, raw_content TEXT NOT NULL, raw_structure TEXT, import_status TEXT NOT NULL, import_error TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(fingerprint_import_id, source_path, content_sha256))`,
		`CREATE TABLE fingerprint_products (id INTEGER PRIMARY KEY AUTOINCREMENT, canonical_name TEXT NOT NULL UNIQUE, vendor TEXT, aliases_json TEXT, cpe TEXT, product_role TEXT NOT NULL DEFAULT 'application', exclusive_group TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE fingerprint_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint_source_rule_id INTEGER NOT NULL UNIQUE, fingerprint_product_id INTEGER NOT NULL, source_product_name TEXT NOT NULL DEFAULT '', protocol TEXT NOT NULL, soft_match INTEGER NOT NULL DEFAULT 0, version_template TEXT, cpe TEXT, tags_json TEXT NOT NULL DEFAULT '[]', product_role TEXT NOT NULL DEFAULT 'application', exclusive_group TEXT NOT NULL DEFAULT '', status TEXT NOT NULL)`,
		`CREATE TABLE fingerprint_match_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint_rule_id INTEGER NOT NULL, parent_id INTEGER, operator TEXT NOT NULL, position INTEGER NOT NULL, UNIQUE(fingerprint_rule_id, parent_id, position))`,
		`CREATE TABLE fingerprint_matchers (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint_match_group_id INTEGER NOT NULL, evidence_type TEXT NOT NULL, target TEXT, operator TEXT NOT NULL, value TEXT NOT NULL, version_capture TEXT, position INTEGER NOT NULL, UNIQUE(fingerprint_match_group_id, position))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			b.Fatal(err)
		}
	}
	return db
}

func TestFingerprintHubMultipleMatchersDefaultToOR(t *testing.T) {
	engine := fixtureProjectedEngine(t, "fingerprinthub-web-v4", fingerprintHubV4Adapter{}, `{"id":"fixture","info":{"name":"fixture"},"http":[{"matchers":[{"type":"word","words":["first"]},{"type":"word","words":["second"]}]}]}`)
	if !hasProduct(engine.Match(Evidence{Body: "second"}), "fixture") {
		t.Fatal("default matcher relation must be OR")
	}
}

func TestNmapSoftMatchKeepsMetadataWithoutDefiniteProduct(t *testing.T) {
	engine := fixtureProjectedEngine(t, "nmap-service-probes", nmapAdapter{}, `softmatch Jenkins m|^Jenkins ([0-9.]+)$| p/Jenkins/ v/$1/ cpe:/a:jenkins:jenkins:$1/`)
	matches := engine.Match(Evidence{Protocol: "tcp", Banner: "Jenkins 2.452.1"})
	if len(matches) != 1 || !matches[0].Soft || matches[0].Product != "jenkins" || matches[0].Version != "2.452.1" || matches[0].CPE != "cpe:/a:jenkins:jenkins:2.452.1" {
		t.Fatalf("soft Nmap match = %#v", matches)
	}
}

func TestRuleDoesNotInheritCPEFromSharedProductCatalog(t *testing.T) {
	db := openFingerprintTestDB(t)
	_, err := storage.ImportFingerprintBatch(db, storage.FingerprintImportBatch{
		Source: model.FingerprintSource{SourceKey: "fixture-cpe", RepositoryURL: "local://fixture", Status: "enabled"},
		Import: model.FingerprintImport{Commit: "fixture", ContentSHA256: "fixture", ManifestJSON: `{}`, RuleTotal: 2, ExecutableTotal: 2},
		Rules: []model.FingerprintSourceRule{
			{SourceRuleID: "generic", SourcePath: "generic", ContentSHA256: "generic", RawContent: "generic", ImportStatus: "executable"},
			{SourceRuleID: "specific", SourcePath: "specific", ContentSHA256: "specific", RawContent: "specific", ImportStatus: "executable"},
		},
		Projections: []model.FingerprintRuleProjection{
			{SourcePath: "generic", ContentSHA256: "generic", Product: model.FingerprintProduct{CanonicalName: "http"}, Protocol: "http", Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: "http_header", Target: "server", Operator: "contains_ci", Value: "generic"}}}},
			{SourcePath: "specific", ContentSHA256: "specific", Product: model.FingerprintProduct{CanonicalName: "http", CPE: "cpe:/a:golang:go"}, Protocol: "http", CPE: "cpe:/a:golang:go", Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: "http_header", Target: "server", Operator: "contains_ci", Value: "go-http-server"}}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := LoadActiveEngine(db)
	if err != nil {
		t.Fatal(err)
	}
	matches := engine.Match(Evidence{Protocol: "http", Headers: map[string]string{"Server": "generic"}})
	if len(matches) != 1 || matches[0].CPE != "" {
		t.Fatalf("generic rule inherited catalog CPE: %#v", matches)
	}
}

func TestProjectionRevisionIsImmutableAndRunsKeepFrozenSemantics(t *testing.T) {
	db := openFingerprintTestDB(t)
	firstBatch := projectionRevisionFixture("adapter-a", "alpha", "HELLO")
	first, err := storage.ImportFingerprintBatch(db, firstBatch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE scan_task_run_fingerprint_imports (scan_task_run_id INTEGER NOT NULL, fingerprint_import_id INTEGER NOT NULL, PRIMARY KEY (scan_task_run_id, fingerprint_import_id))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO scan_task_run_fingerprint_imports VALUES (1, ?)`, first.ID); err != nil {
		t.Fatal(err)
	}

	secondBatch := projectionRevisionFixture("adapter-b", "beta", "HELLO")
	second, err := storage.ImportFingerprintBatch(db, secondBatch)
	if err != nil {
		t.Fatal(err)
	}
	first, err = storage.GetFingerprintImport(db, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || first.ProjectionSHA256 == second.ProjectionSHA256 || first.IsActive || !second.IsActive {
		t.Fatalf("projection revisions first=%#v second=%#v", first, second)
	}
	oldEngine, err := LoadRunEngine(db, 1)
	if err != nil || !hasProduct(oldEngine.Match(NewBannerEvidence("HELLO", false)), "alpha") {
		t.Fatalf("old run lost frozen semantics: err=%v", err)
	}
	activeEngine, err := LoadActiveEngine(db)
	if err != nil || !hasProduct(activeEngine.Match(NewBannerEvidence("HELLO", false)), "beta") {
		t.Fatalf("new active semantics missing: err=%v", err)
	}

	reactivated, err := storage.ImportFingerprintBatch(db, firstBatch)
	if err != nil || reactivated.ID != first.ID || !reactivated.IsActive {
		t.Fatalf("reactivate A = %#v err=%v", reactivated, err)
	}
	oldEngine, err = LoadRunEngine(db, 1)
	if err != nil || !hasProduct(oldEngine.Match(NewBannerEvidence("HELLO", false)), "alpha") {
		t.Fatalf("historical run changed after reactivation: err=%v", err)
	}
}

func projectionRevisionFixture(adapterVersion, product, banner string) storage.FingerprintImportBatch {
	return storage.FingerprintImportBatch{
		Source:      model.FingerprintSource{SourceKey: "revision-fixture", RepositoryURL: "local://revision", Status: "enabled"},
		Import:      model.FingerprintImport{Commit: "same-upstream", ContentSHA256: "same-upstream-sha", UpstreamContentSHA256: "same-upstream-sha", AdapterVersion: adapterVersion, ManifestJSON: `{}`, RuleTotal: 1, ExecutableTotal: 1},
		Rules:       []model.FingerprintSourceRule{{SourceRuleID: "rule", SourcePath: "rule", ContentSHA256: "rule", RawContent: "same raw", ImportStatus: "executable"}},
		Projections: []model.FingerprintRuleProjection{{SourcePath: "rule", ContentSHA256: "rule", Product: model.FingerprintProduct{CanonicalName: product}, Protocol: "tcp", Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: "tcp_banner", Target: "banner", Operator: "contains", Value: banner}}}}},
	}
}

func projectionRoleRevisionFixture(adapterVersion, role, group string) storage.FingerprintImportBatch {
	return storage.FingerprintImportBatch{
		Source: model.FingerprintSource{SourceKey: "role-revision-fixture", RepositoryURL: "local://role-revision", Status: "enabled"},
		Import: model.FingerprintImport{Commit: adapterVersion, ContentSHA256: adapterVersion, UpstreamContentSHA256: adapterVersion, AdapterVersion: adapterVersion, ManifestJSON: `{}`, RuleTotal: 1, ExecutableTotal: 1},
		Rules:  []model.FingerprintSourceRule{{SourceRuleID: "role-rule", SourcePath: "role-rule", ContentSHA256: "role-rule", RawContent: "same raw", ImportStatus: "executable"}},
		Projections: []model.FingerprintRuleProjection{{
			SourcePath: "role-rule", ContentSHA256: "role-rule", Product: model.FingerprintProduct{CanonicalName: "role-product", Role: role, ExclusiveGroup: group}, Protocol: "tcp",
			Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: "tcp_banner", Target: "banner", Operator: "contains", Value: "ROLE-FIXTURE"}}},
		}},
	}
}

func fixtureProjectedEngine(t *testing.T, sourceKey string, adapter SourceAdapter, raw string) *Engine {
	t.Helper()
	db := openFingerprintTestDB(t)
	sourceRuleID := "fixture"
	if strings.HasPrefix(raw, "softmatch ") || strings.HasPrefix(raw, "match ") {
		sourceRuleID = "tcp:NULL:fixture"
	} else if strings.Contains(raw, "Md5") || strings.HasPrefix(raw, `{"`) {
		if sourceKey == "fscan-native-web" {
			sourceRuleID = "md5:fixture"
		}
	}
	rule := model.FingerprintSourceRule{SourceRuleID: sourceRuleID, SourcePath: "fixture/rule", ContentSHA256: "fixture-rule", RawContent: raw, ImportStatus: "executable"}
	projection, err := adapter.Project(rule)
	if err != nil {
		t.Fatalf("project fixture: %v", err)
	}
	projection.SourcePath, projection.ContentSHA256 = rule.SourcePath, rule.ContentSHA256
	projection.Product = normalizedProduct(projection.Product)
	_, err = storage.ImportFingerprintBatch(db, storage.FingerprintImportBatch{
		Source: model.FingerprintSource{SourceKey: sourceKey, RepositoryURL: "local://fixture", Status: "enabled"},
		Import: model.FingerprintImport{Commit: "fixture", ContentSHA256: "fixture-import", ManifestJSON: `{}`, RuleTotal: 1, ExecutableTotal: 1},
		Rules:  []model.FingerprintSourceRule{rule}, Projections: []model.FingerprintRuleProjection{projection},
	})
	if err != nil {
		t.Fatalf("import projected fixture: %v", err)
	}
	engine, err := LoadActiveEngine(db)
	if err != nil {
		t.Fatalf("load projected engine: %v", err)
	}
	return engine
}

func hasProduct(matches []Match, product string) bool {
	for _, match := range matches {
		if match.Product == product {
			return true
		}
	}
	return false
}

func hasSourceProduct(matches []Match, source, product string) bool {
	for _, match := range matches {
		if match.SourceKey == source && match.Product == product {
			return true
		}
	}
	return false
}
