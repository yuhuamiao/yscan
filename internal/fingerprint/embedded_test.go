package fingerprint

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

type keyedFixtureAdapter struct{ sourceKey string }

func (adapter keyedFixtureAdapter) SourceKey() string      { return adapter.sourceKey }
func (adapter keyedFixtureAdapter) AdapterVersion() string { return "recovery-fixture-v1" }
func (adapter keyedFixtureAdapter) Adapt(snapshot VerifiedSnapshot) ([]model.FingerprintSourceRule, error) {
	return fixtureAdapter{}.Adapt(snapshot)
}
func (adapter keyedFixtureAdapter) Project(rule model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	return fixtureAdapter{}.Project(rule)
}

func TestEmbeddedRealSourcesImportAllRulesAndRemainIdempotent(t *testing.T) {
	db := openFingerprintTestDB(t)
	registry, err := NewEmbeddedRegistry(db)
	if err != nil {
		t.Fatalf("load embedded registry: %v", err)
	}
	for _, source := range registry.Manifest.Sources {
		if _, err := registry.Import(context.Background(), source.SourceKey, ""); err != nil {
			t.Fatalf("import %s: %v", source.SourceKey, err)
		}
	}
	imports, err := storage.ListActiveFingerprintImports(db)
	if err != nil {
		t.Fatalf("list active imports: %v", err)
	}
	if len(imports) != 9 {
		t.Fatalf("active import count = %d, want 9", len(imports))
	}
	var panelRole, panelGroup string
	if err := db.QueryRow(`SELECT product_role, exclusive_group FROM fingerprint_products WHERE canonical_name = '宝塔-bt.cn'`).Scan(&panelRole, &panelGroup); err != nil {
		t.Fatalf("read control-panel role: %v", err)
	}
	if panelRole != "control_panel" || panelGroup != "" {
		t.Fatalf("control-panel role=%q group=%q", panelRole, panelGroup)
	}
	for _, fingerprintImport := range imports {
		var rawRuleCount int
		if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_source_rules WHERE fingerprint_import_id = ?`, fingerprintImport.ID).Scan(&rawRuleCount); err != nil {
			t.Fatalf("count imported rules: %v", err)
		}
		if rawRuleCount != fingerprintImport.RuleTotal {
			t.Fatalf("import %s raw count = %d, want %d", fingerprintImport.Commit, rawRuleCount, fingerprintImport.RuleTotal)
		}
	}
	var total, executable, unsupported int
	if err := db.QueryRow(`
		SELECT rule_total, executable_total, unsupported_total
		FROM fingerprint_imports AS fingerprint_import
		JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id
		WHERE source.source_key = 'nmap-service-probes'`).Scan(&total, &executable, &unsupported); err != nil {
		t.Fatalf("read Nmap import stats: %v", err)
	}
	if total != 12171 || executable != 9409 || unsupported != 2762 {
		t.Fatalf("Nmap import stats = total=%d executable=%d unsupported=%d", total, executable, unsupported)
	}
	if err := db.QueryRow(`SELECT SUM(rule_total), SUM(executable_total), SUM(unsupported_total) FROM fingerprint_imports WHERE is_active = 1`).Scan(&total, &executable, &unsupported); err != nil {
		t.Fatalf("read aggregate import stats: %v", err)
	}
	if total != 41192 || executable != 28509 || unsupported != 12683 {
		t.Fatalf("aggregate stats = total=%d executable=%d unsupported=%d", total, executable, unsupported)
	}
	projectedSources := map[string]struct {
		total       int
		executable  int
		unsupported int
	}{
		"fingerprinthub-web-yaml":     {3312, 3305, 7},
		"fingerprinthub-service-yaml": {11938, 3981, 7957},
		"whatweb":                     {1832, 1307, 525},
		"wappalyzer":                  {3931, 2514, 1417},
	}
	for sourceKey, expected := range projectedSources {
		var count, executableCount, unsupportedCount, diagnosedCount int
		if err := db.QueryRow(`
			SELECT COUNT(*), SUM(CASE WHEN rule.import_status = 'executable' THEN 1 ELSE 0 END),
				SUM(CASE WHEN rule.import_status = 'unsupported' THEN 1 ELSE 0 END),
				SUM(CASE WHEN rule.import_status = 'unsupported' AND COALESCE(rule.import_error, '') <> '' THEN 1 ELSE 0 END)
			FROM fingerprint_source_rules AS rule
			JOIN fingerprint_imports AS fingerprint_import ON fingerprint_import.id = rule.fingerprint_import_id AND fingerprint_import.is_active = 1
			JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id
			WHERE source.source_key = ?`, sourceKey).Scan(&count, &executableCount, &unsupportedCount, &diagnosedCount); err != nil {
			t.Fatalf("read %s unsupported rules: %v", sourceKey, err)
		}
		if count != expected.total || executableCount != expected.executable || unsupportedCount != expected.unsupported || diagnosedCount != expected.unsupported {
			t.Fatalf("source %s count=%d executable=%d unsupported=%d diagnosed=%d", sourceKey, count, executableCount, unsupportedCount, diagnosedCount)
		}
	}
	var license, rawContent, sourcePath string
	if err := db.QueryRow(`
		SELECT source.license, rule.raw_content, rule.source_path
		FROM fingerprint_source_rules AS rule
		JOIN fingerprint_imports AS fingerprint_import ON fingerprint_import.id = rule.fingerprint_import_id AND fingerprint_import.is_active = 1
		JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id
		WHERE source.source_key = 'wappalyzer' ORDER BY rule.id LIMIT 1`).Scan(&license, &rawContent, &sourcePath); err != nil {
		t.Fatalf("read archived Wappalyzer rule: %v", err)
	}
	if license != "GPL-3.0-only" || !strings.HasPrefix(sourcePath, "src/technologies/") || !jsonObject(rawContent) {
		t.Fatalf("Wappalyzer archive license=%q path=%q raw=%q", license, sourcePath, rawContent)
	}
	for _, source := range registry.Manifest.Sources {
		if _, err := registry.Import(context.Background(), source.SourceKey, ""); err != nil {
			t.Fatalf("repeat import %s: %v", source.SourceKey, err)
		}
	}
	var importCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports`).Scan(&importCount); err != nil {
		t.Fatalf("count immutable imports: %v", err)
	}
	if importCount != 9 {
		t.Fatalf("repeat import created %d rows, want 9", importCount)
	}
}

func jsonObject(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	return strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")
}

func TestBootstrapSourceFailuresAreIsolatedAndDiagnosed(t *testing.T) {
	db := openFingerprintTestDB(t)
	called := make([]string, 0, 3)
	err := bootstrapSourceImports(context.Background(), db, []string{"source-a", "source-b", "source-c"}, func(_ context.Context, source string) error {
		called = append(called, source)
		if source == "source-b" {
			return errors.New("adapter upgrade failed")
		}
		return nil
	})
	if err != nil || !reflect.DeepEqual(called, []string{"source-a", "source-b", "source-c"}) {
		t.Fatalf("bootstrap called=%v err=%v", called, err)
	}
	var message string
	var resolved interface{}
	if err := db.QueryRow(`SELECT last_error, resolved_at FROM fingerprint_source_bootstrap_diagnostics WHERE source_key = 'source-b'`).Scan(&message, &resolved); err != nil {
		t.Fatal(err)
	}
	if message != "adapter upgrade failed" || resolved != nil {
		t.Fatalf("failure diagnostic message=%q resolved=%v", message, resolved)
	}
	var resolvedCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_source_bootstrap_diagnostics WHERE source_key IN ('source-a', 'source-c') AND resolved_at IS NOT NULL`).Scan(&resolvedCount); err != nil || resolvedCount != 2 {
		t.Fatalf("resolved diagnostics=%d err=%v", resolvedCount, err)
	}
}

func TestMissingManifestSourceRecoversOnNextInitialization(t *testing.T) {
	db := openFingerprintTestDB(t)
	archive := fixtureArchive(t, map[string]string{"rules/fixture.json": `{"name":"fixture"}`})
	manifest := Manifest{Sources: []SourceManifest{
		{SourceKey: "source-a", RepositoryURL: "https://example.invalid/a", Commit: "a1", ArchivePath: "snapshots/a.tar.gz", ArchiveSHA256: sha256Hex(archive), Files: []ManifestFile{{Path: "rules/fixture.json", SHA256: sha256Hex([]byte(`{"name":"fixture"}`))}}, ExpectedStats: RuleStats{RuleTotal: 1, ExecutableTotal: 1}},
		{SourceKey: "source-b", RepositoryURL: "https://example.invalid/b", Commit: "b1", ArchivePath: "snapshots/b.tar.gz", ArchiveSHA256: sha256Hex(archive), Files: []ManifestFile{{Path: "rules/fixture.json", SHA256: sha256Hex([]byte(`{"name":"fixture"}`))}}, ExpectedStats: RuleStats{RuleTotal: 1, ExecutableTotal: 1}},
	}}
	adapters := []SourceAdapter{keyedFixtureAdapter{"source-a"}, keyedFixtureAdapter{"source-b"}}
	firstRegistry := NewRegistry(db, manifest, map[string][]byte{"source-a": archive, "source-b": []byte("broken")}, adapters)
	changed, err := initializeMissingManifestSources(context.Background(), firstRegistry)
	if err != nil || !changed {
		t.Fatalf("partial initialization changed=%t err=%v", changed, err)
	}
	var firstImportID int64
	if err := db.QueryRow(`SELECT fingerprint_import.id FROM fingerprint_imports AS fingerprint_import JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id WHERE source.source_key = 'source-a'`).Scan(&firstImportID); err != nil {
		t.Fatal(err)
	}
	sources, err := storage.ListFingerprintSources(db)
	if err != nil || len(sources) != 2 || sources[0].CatalogStatus != "active" || sources[1].CatalogStatus != "failed" || sources[1].LastError == "" {
		t.Fatalf("partial source diagnostics=%#v err=%v", sources, err)
	}

	secondRegistry := NewRegistry(db, manifest, map[string][]byte{"source-a": archive, "source-b": archive}, adapters)
	changed, err = initializeMissingManifestSources(context.Background(), secondRegistry)
	if err != nil || !changed {
		t.Fatalf("recovery initialization changed=%t err=%v", changed, err)
	}
	var currentFirstID, imports int64
	if err := db.QueryRow(`SELECT fingerprint_import.id FROM fingerprint_imports AS fingerprint_import JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id WHERE source.source_key = 'source-a'`).Scan(&currentFirstID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports`).Scan(&imports); err != nil {
		t.Fatal(err)
	}
	sources, err = storage.ListFingerprintSources(db)
	if err != nil || currentFirstID != firstImportID || imports != 2 || sources[0].CatalogStatus != "active" || sources[1].CatalogStatus != "active" || sources[1].LastError != "" {
		t.Fatalf("recovered sources=%#v first=%d/%d imports=%d err=%v", sources, firstImportID, currentFirstID, imports, err)
	}
}
