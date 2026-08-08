package fingerprint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

type fixtureAdapter struct{}

func (fixtureAdapter) SourceKey() string { return "fixture-source" }

func (fixtureAdapter) Adapt(snapshot VerifiedSnapshot) ([]model.FingerprintSourceRule, error) {
	content := snapshot.Files["rules/fixture.json"]
	sum := sha256.Sum256(content)
	return []model.FingerprintSourceRule{{
		SourceRuleID:  "fixture-rule",
		SourcePath:    "rules/fixture.json",
		ContentSHA256: hex.EncodeToString(sum[:]),
		RawContent:    string(content),
		ImportStatus:  "executable",
	}}, nil
}

func (fixtureAdapter) Project(rule model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	return model.FingerprintRuleProjection{
		Product:  model.FingerprintProduct{CanonicalName: "Fixture"},
		Protocol: "http",
		Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{
			EvidenceType: "http_body", Target: "body", Operator: "contains", Value: "fixture",
		}}},
	}, nil
}

type versionedFixtureAdapter struct{ version string }

func (adapter versionedFixtureAdapter) SourceKey() string { return fixtureAdapter{}.SourceKey() }
func (adapter versionedFixtureAdapter) AdapterVersion() string {
	return adapter.version
}
func (adapter versionedFixtureAdapter) Adapt(snapshot VerifiedSnapshot) ([]model.FingerprintSourceRule, error) {
	return fixtureAdapter{}.Adapt(snapshot)
}
func (adapter versionedFixtureAdapter) Project(rule model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	return fixtureAdapter{}.Project(rule)
}

func TestFingerprintCLIImportsOnlyRegisteredManifestSourceAndListsIt(t *testing.T) {
	db := openFingerprintTestDB(t)
	archive := fixtureArchive(t, map[string]string{"rules/fixture.json": `{"name":"fixture"}`})
	source := SourceManifest{
		SourceKey:     "fixture-source",
		RepositoryURL: "https://example.invalid/fingerprint",
		Commit:        "fixture-commit",
		ArchivePath:   "snapshots/fixture.tar.gz",
		ArchiveSHA256: sha256Hex(archive),
		Files:         []ManifestFile{{Path: "rules/fixture.json", SHA256: sha256Hex([]byte(`{"name":"fixture"}`))}},
		ExpectedStats: RuleStats{RuleTotal: 1, ExecutableTotal: 1},
	}
	registry := NewRegistry(db, Manifest{Sources: []SourceManifest{source}}, map[string][]byte{source.SourceKey: archive}, []SourceAdapter{fixtureAdapter{}})
	var output bytes.Buffer
	if err := RunCLI(context.Background(), registry, []string{"import", "--source", source.SourceKey}, &output); err != nil {
		t.Fatalf("import source: %v", err)
	}
	if output.Len() == 0 {
		t.Fatal("import output is empty")
	}
	if err := RunCLI(context.Background(), registry, []string{"upgrade", "--source", source.SourceKey}, &output); err != nil {
		t.Fatalf("idempotent upgrade: %v", err)
	}
	if err := RunCLI(context.Background(), registry, []string{"import", "--source", "unlisted"}, &output); err == nil {
		t.Fatal("unlisted source must be rejected")
	}
	output.Reset()
	if err := RunCLI(context.Background(), registry, []string{"list"}, &output); err != nil {
		t.Fatalf("list sources: %v", err)
	}
	if !bytes.Contains(output.Bytes(), []byte(source.SourceKey)) {
		t.Fatalf("list output = %q", output.String())
	}
}

func TestExistingCatalogChangesOnlyOnExplicitFingerprintUpgrade(t *testing.T) {
	db := openFingerprintTestDB(t)
	archive := fixtureArchive(t, map[string]string{"rules/fixture.json": `{"name":"fixture"}`})
	source := SourceManifest{
		SourceKey: "fixture-source", RepositoryURL: "https://example.invalid/fingerprint", Commit: "fixture-commit",
		ArchivePath: "snapshots/fixture.tar.gz", ArchiveSHA256: sha256Hex(archive),
		Files:         []ManifestFile{{Path: "rules/fixture.json", SHA256: sha256Hex([]byte(`{"name":"fixture"}`))}},
		ExpectedStats: RuleStats{RuleTotal: 1, ExecutableTotal: 1},
	}
	manifest := Manifest{Sources: []SourceManifest{source}}
	archives := map[string][]byte{source.SourceKey: archive}
	oldRegistry := NewRegistry(db, manifest, archives, []SourceAdapter{versionedFixtureAdapter{version: "fixture-adapter-v1"}})
	if _, err := oldRegistry.Import(context.Background(), source.SourceKey, ""); err != nil {
		t.Fatal(err)
	}
	newRegistry := NewRegistry(db, manifest, archives, []SourceAdapter{versionedFixtureAdapter{version: "fixture-adapter-v2"}})

	initialized, err := initializeMissingManifestSources(context.Background(), newRegistry)
	if err != nil || initialized {
		t.Fatalf("existing catalog initialized=%t err=%v", initialized, err)
	}
	var output bytes.Buffer
	if err := RunCLI(context.Background(), newRegistry, []string{"list"}, &output); err != nil {
		t.Fatal(err)
	}
	assertActiveAdapterVersion(t, db, "fixture-adapter-v1+"+ProductNormalizationRevision, 1)

	output.Reset()
	if err := RunCLI(context.Background(), newRegistry, []string{"upgrade"}, &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte("fixture-source revision fixture-commit active")) {
		t.Fatalf("upgrade diagnostics=%q", output.String())
	}
	assertActiveAdapterVersion(t, db, "fixture-adapter-v2+"+ProductNormalizationRevision, 2)
}

func TestEmptyCatalogInitializesEmbeddedSourcesExactlyOnce(t *testing.T) {
	db := openFingerprintTestDB(t)
	initialized, err := InitializeEmbeddedSourcesIfEmpty(context.Background(), db)
	if err != nil || !initialized {
		t.Fatalf("first initialization=%t err=%v", initialized, err)
	}
	var active, imports int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports WHERE is_active = 1`).Scan(&active); err != nil || active != 9 {
		t.Fatalf("active embedded imports=%d err=%v", active, err)
	}
	initialized, err = InitializeEmbeddedSourcesIfEmpty(context.Background(), db)
	if err != nil || initialized {
		t.Fatalf("repeat initialization=%t err=%v", initialized, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports`).Scan(&imports); err != nil || imports != 9 {
		t.Fatalf("immutable import count=%d err=%v", imports, err)
	}
}

func TestFingerprintCleanupDryRunAndApplyPreserveReferencedRevisions(t *testing.T) {
	db, err := storage.InitDBAt(filepath.Join(t.TempDir(), "cleanup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	first, err := storage.ImportFingerprintBatch(db, cleanupRevisionBatch("a"))
	if err != nil {
		t.Fatal(err)
	}
	task, err := storage.CreateScanTask(db, model.ScanTask{Target: "192.168.91.1", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-08-06T01:00:00Z"}); err != nil {
		t.Fatal(err)
	}

	second, err := storage.ImportFingerprintBatch(db, cleanupRevisionBatch("b"))
	if err != nil {
		t.Fatal(err)
	}
	matchTask, err := storage.CreateScanTask(db, model.ScanTask{Target: "192.168.91.1", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce})
	if err != nil {
		t.Fatal(err)
	}
	runWithMatch, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: matchTask.ID, ScheduledFor: "2026-08-06T02:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	var secondRule, secondMatcher int64
	if err := db.QueryRow(`SELECT id FROM fingerprint_source_rules WHERE fingerprint_import_id = ?`, second.ID).Scan(&secondRule); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT matcher.id FROM fingerprint_matchers AS matcher JOIN fingerprint_match_groups AS match_group ON match_group.id = matcher.fingerprint_match_group_id JOIN fingerprint_rules AS rule ON rule.id = match_group.fingerprint_rule_id WHERE rule.fingerprint_source_rule_id = ?`, secondRule).Scan(&secondMatcher); err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveFingerprintRunMatches(db, runWithMatch.ID, []model.FingerprintRunMatch{{
		FingerprintImportID: second.ID, FingerprintSourceRuleID: secondRule, IP: "192.168.91.1", Port: 80, Protocol: "http", Product: "cleanup-fixture",
		EvidenceSummary: "cleanup fixture", Evidence: []model.FingerprintMatchEvidence{{MatcherID: secondMatcher, EvidenceType: "http_body", Operator: "contains", ObservedSHA256: strings.Repeat("0", 64), ObservedLength: 7, Summary: "http_body bytes=7 sha256=" + strings.Repeat("0", 64)}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM scan_task_run_fingerprint_imports WHERE scan_task_run_id = ? AND fingerprint_import_id = ?`, runWithMatch.ID, second.ID); err != nil {
		t.Fatal(err)
	}

	third, err := storage.ImportFingerprintBatch(db, cleanupRevisionBatch("c"))
	if err != nil {
		t.Fatal(err)
	}
	fourth, err := storage.ImportFingerprintBatch(db, cleanupRevisionBatch("d"))
	if err != nil {
		t.Fatal(err)
	}
	registry := &Registry{DB: db}
	var output bytes.Buffer
	if err := RunCLI(context.Background(), registry, []string{"cleanup"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "DRY-RUN candidates=1 deleted=0") || !strings.Contains(output.String(), fmt.Sprintf("import=%d", third.ID)) {
		t.Fatalf("cleanup dry-run output=%q", output.String())
	}
	var imports int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports WHERE id IN (?, ?, ?, ?)`, first.ID, second.ID, third.ID, fourth.ID).Scan(&imports); err != nil || imports != 4 {
		t.Fatalf("dry-run changed imports=%d err=%v", imports, err)
	}
	output.Reset()
	if err := RunCLI(context.Background(), registry, []string{"cleanup", "--apply"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "APPLIED candidates=1 deleted=1") {
		t.Fatalf("cleanup apply output=%q", output.String())
	}
	for _, kept := range []int64{first.ID, second.ID, fourth.ID} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports WHERE id = ?`, kept).Scan(&count); err != nil || count != 1 {
			t.Fatalf("referenced/active import %d removed: count=%d err=%v", kept, count, err)
		}
	}
	var deletedImport, deletedRules int
	_ = db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports WHERE id = ?`, third.ID).Scan(&deletedImport)
	_ = db.QueryRow(`SELECT COUNT(*) FROM fingerprint_source_rules WHERE fingerprint_import_id = ?`, third.ID).Scan(&deletedRules)
	if deletedImport != 0 || deletedRules != 0 {
		t.Fatalf("eligible revision not fully deleted: import=%d rules=%d", deletedImport, deletedRules)
	}
	if err := RunCLI(context.Background(), registry, []string{"cleanup", "--force"}, &output); err == nil {
		t.Fatal("unsupported cleanup flag must be rejected")
	}
}

func TestFingerprintCleanupApplyRollsBackOnDeletionFailure(t *testing.T) {
	db, err := storage.InitDBAt(filepath.Join(t.TempDir(), "cleanup-rollback.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	first, err := storage.ImportFingerprintBatch(db, cleanupRevisionBatch("rollback-a"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := storage.ImportFingerprintBatch(db, cleanupRevisionBatch("rollback-b"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.ImportFingerprintBatch(db, cleanupRevisionBatch("rollback-active")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(fmt.Sprintf(`CREATE TRIGGER reject_cleanup BEFORE DELETE ON fingerprint_imports WHEN OLD.id = %d BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END`, second.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.ApplyFingerprintImportCleanup(db); err == nil || !strings.Contains(err.Error(), "injected cleanup failure") {
		t.Fatalf("cleanup failure=%v", err)
	}
	var remaining int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports WHERE id IN (?, ?)`, first.ID, second.ID).Scan(&remaining); err != nil || remaining != 2 {
		t.Fatalf("cleanup failure did not roll back: remaining=%d err=%v", remaining, err)
	}
}

func cleanupRevisionBatch(revision string) storage.FingerprintImportBatch {
	contentSHA := "cleanup-" + revision
	return storage.FingerprintImportBatch{
		Source:      model.FingerprintSource{SourceKey: "cleanup-fixture", RepositoryURL: "local://cleanup", Status: "enabled"},
		Import:      model.FingerprintImport{Commit: revision, ContentSHA256: contentSHA, UpstreamContentSHA256: contentSHA, AdapterVersion: "cleanup-" + revision, ManifestJSON: `{"revision":"` + revision + `"}`, RuleTotal: 1, ExecutableTotal: 1},
		Rules:       []model.FingerprintSourceRule{{SourceRuleID: revision, SourcePath: revision, ContentSHA256: contentSHA, RawContent: "cleanup " + revision, ImportStatus: "executable"}},
		Projections: []model.FingerprintRuleProjection{{SourcePath: revision, ContentSHA256: contentSHA, Product: model.FingerprintProduct{CanonicalName: "cleanup-fixture"}, Protocol: "http", Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: "http_body", Operator: "contains", Value: revision}}}}},
	}
}

func assertActiveAdapterVersion(t *testing.T, db *sql.DB, want string, wantImports int) {
	t.Helper()
	var active string
	if err := db.QueryRow(`SELECT adapter_version FROM fingerprint_imports WHERE is_active = 1`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	var imports int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports`).Scan(&imports); err != nil {
		t.Fatal(err)
	}
	if active != want || imports != wantImports {
		t.Fatalf("active adapter=%q imports=%d, want %q/%d", active, imports, want, wantImports)
	}
}

func openFingerprintTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
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
			t.Fatalf("create fingerprint CLI schema: %v", err)
		}
	}
	return db
}
