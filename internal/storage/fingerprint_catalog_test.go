package storage

import (
	"database/sql"
	"strings"
	"testing"

	"golandproject/yscan/internal/model"
)

func TestTemplateMappingImportIsAtomicAndCanBeDisabled(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	value, err := ImportTemplateMappingBatch(db, TemplateMappingBatch{Import: model.TemplateMappingImport{Revision: "templates-r1", ContentSHA256: "fixture-manifest-sha", ManifestJSON: `{"revision":"templates-r1"}`}, Mappings: []model.FingerprintTemplateMapping{{ProductKey: "nginx", TemplateID: "nginx-check", TemplatePath: "http/nginx.yaml", TemplateSHA256: "template-sha", TemplateSetRevision: "templates-r1", SideEffect: "read_only", ReviewStatus: "approved"}}})
	if err != nil {
		t.Fatalf("import mapping: %v", err)
	}
	if !value.IsActive {
		t.Fatalf("import must be active: %#v", value)
	}
	mappings, err := ListFingerprintTemplateMappings(db)
	if err != nil || len(mappings) != 1 {
		t.Fatalf("list mappings = %#v, %v", mappings, err)
	}
	if err := DisableFingerprintTemplateMapping(db, mappings[0].ID); err != nil {
		t.Fatalf("disable mapping: %v", err)
	}
	mappings, err = ListFingerprintTemplateMappings(db)
	if err != nil || mappings[0].Enabled {
		t.Fatalf("disabled mapping = %#v, %v", mappings, err)
	}
	_, err = ImportTemplateMappingBatch(db, TemplateMappingBatch{Import: model.TemplateMappingImport{Revision: "bad", ContentSHA256: "bad-sha", ManifestJSON: "{}"}, Mappings: []model.FingerprintTemplateMapping{{ProductKey: "nginx", TemplateID: "bad", TemplatePath: "bad", TemplateSHA256: "bad", TemplateSetRevision: "r", SideEffect: "write", ReviewStatus: "approved"}}})
	if err == nil {
		t.Fatal("write-capable mapping must be rejected")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM template_mapping_imports WHERE content_sha256 = 'bad-sha'`).Scan(&count); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed mapping import must not persist a partial revision")
	}
}

func TestFingerprintCatalogPreservesImportProvenanceAndCascadesRunResults(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("init schema: %v", err)
	}

	source, err := CreateFingerprintSource(db, model.FingerprintSource{
		SourceKey:     "ehole",
		RepositoryURL: "https://github.com/EdgeSecurityTeam/EHole",
		License:       "Apache-2.0",
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	fingerprintImport, err := CreateFingerprintImport(db, model.FingerprintImport{
		FingerprintSourceID: source.ID,
		Commit:              "9a91e0b3372537681d1b88a31cfab3d00620c1e5",
		ContentSHA256:       "fixture-sha-256",
		ManifestJSON:        `{"source_key":"ehole"}`,
		RuleTotal:           1,
		ExecutableTotal:     1,
	})
	if err != nil {
		t.Fatalf("create import: %v", err)
	}
	rule, err := CreateFingerprintSourceRule(db, model.FingerprintSourceRule{
		FingerprintImportID: fingerprintImport.ID,
		SourceRuleID:        "finger-1",
		SourcePath:          "finger.json",
		ContentSHA256:       "rule-sha-256",
		RawContent:          `{"cms":"fixture"}`,
		RawStructure:        `{"method":"keyword"}`,
		ImportStatus:        "executable",
	})
	if err != nil {
		t.Fatalf("create source rule: %v", err)
	}
	if rule.RawContent != `{"cms":"fixture"}` || rule.ImportStatus != "executable" {
		t.Fatalf("source rule lost raw provenance: %#v", rule)
	}

	task := createScheduledTaskForTest(t, db, "192.168.120.0/24")
	run, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-30T02:00:00Z"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := AssociateFingerprintImportWithRun(db, run.ID, fingerprintImport.ID); err != nil {
		t.Fatalf("associate import: %v", err)
	}
	if err := AssociateFingerprintImportWithRun(db, run.ID, fingerprintImport.ID); err != nil {
		t.Fatalf("repeat association: %v", err)
	}
	imports, err := ListFingerprintImportsForRun(db, run.ID)
	if err != nil {
		t.Fatalf("list frozen imports: %v", err)
	}
	if !containsFingerprintImport(imports, fingerprintImport.ID, fingerprintImport.Commit) {
		t.Fatalf("frozen imports = %#v", imports)
	}

	if _, err := db.Exec(`
		INSERT INTO asset_fingerprint_matches
			(scan_task_run_id, fingerprint_import_id, fingerprint_source_rule_id, ip, port, protocol, evidence_summary)
		VALUES (?, ?, ?, '192.168.120.10', 8443, 'https', 'header: server')`, run.ID, fingerprintImport.ID, rule.ID); err != nil {
		t.Fatalf("insert match: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO asset_fingerprint_conclusions
			(scan_task_run_id, ip, port, protocol, product_key, conclusion_status)
		VALUES (?, '192.168.120.10', 8443, 'https', 'fixture-product', 'matched')`, run.ID); err != nil {
		t.Fatalf("insert conclusion: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM scan_task_runs WHERE id = ?`, run.ID); err != nil {
		t.Fatalf("delete run: %v", err)
	}
	for _, table := range []string{"scan_task_run_fingerprint_imports", "asset_fingerprint_matches", "asset_fingerprint_conclusions"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s left orphaned rows: %d", table, count)
		}
	}
	if _, err := GetFingerprintImport(db, fingerprintImport.ID); err != nil {
		t.Fatalf("run cleanup must retain immutable import history: %v", err)
	}
}

func TestFingerprintCatalogMigrationWorksAgainstLegacySchema(t *testing.T) {
	db := openTestDB(t)
	legacyStatements := []string{
		`CREATE TABLE banner (id INTEGER PRIMARY KEY, service_name TEXT NOT NULL, banner_pattern TEXT NOT NULL, description TEXT)`,
		`CREATE TABLE domain_info (id INTEGER PRIMARY KEY, domain TEXT NOT NULL, subdomain TEXT NOT NULL UNIQUE, is_wildcard INTEGER NOT NULL DEFAULT 0, title TEXT, first_seen DATETIME NOT NULL, last_scan DATETIME, source TEXT)`,
		`CREATE TABLE domain_ips (id INTEGER PRIMARY KEY, domain_id INTEGER NOT NULL, subdomain TEXT NOT NULL, ip TEXT NOT NULL, ports TEXT, UNIQUE(domain_id, ip))`,
		`CREATE TABLE host_inventory (id INTEGER PRIMARY KEY, ip TEXT NOT NULL UNIQUE, source TEXT, first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL, last_scan DATETIME, is_active INTEGER NOT NULL DEFAULT 1)`,
		`CREATE TABLE scan_results (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, port INTEGER NOT NULL, service_id INTEGER, service_type TEXT NOT NULL, scan_time DATETIME, UNIQUE(ip, port))`,
		`CREATE TABLE tasks (id INTEGER PRIMARY KEY, task_type TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL, progress INTEGER NOT NULL DEFAULT 0, error_msg TEXT, started_at DATETIME, finished_at DATETIME, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)`,
	}
	for _, statement := range legacyStatements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create legacy schema: %v", err)
		}
	}
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("migrate legacy schema: %v", err)
	}
	for _, table := range []string{"fingerprint_sources", "fingerprint_imports", "fingerprint_source_rules", "scan_task_run_fingerprint_imports", "asset_fingerprint_matches", "asset_fingerprint_conclusions"} {
		var name string
		if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name); err != nil {
			t.Fatalf("migrated table %s missing: %v", table, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO fingerprint_sources (source_key, repository_url, status) VALUES ('legacy-fixture', 'https://example.invalid/fingerprint', 'enabled')`); err != nil {
		t.Fatalf("write fingerprint source after migration: %v", err)
	}
}

func TestLegacyBannerMigrationPreservesRulesWithoutChangingBannerRuntimeTable(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO banner (service_name, banner_pattern, match_type, protocol, description) VALUES ('unknown', '', 'contains', 'tcp', 'state row')`); err != nil {
		t.Fatalf("insert legacy state row: %v", err)
	}
	if err := MigrateLegacyBannerFingerprintRules(db); err != nil {
		t.Fatalf("migrate state row revision: %v", err)
	}
	var bannerCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM banner`).Scan(&bannerCount); err != nil {
		t.Fatalf("count banner rules: %v", err)
	}
	var migratedCount int
	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM fingerprint_source_rules AS rule
		JOIN fingerprint_imports AS fingerprint_import ON fingerprint_import.id = rule.fingerprint_import_id
		JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id
		WHERE source.source_key = ? AND fingerprint_import.is_active = 1`, legacyBannerSourceKey).Scan(&migratedCount); err != nil {
		t.Fatalf("count migrated banner rules: %v", err)
	}
	if migratedCount != bannerCount {
		t.Fatalf("migrated banner rule count = %d, want %d", migratedCount, bannerCount)
	}
	var rawContent, matcherTarget, matcherOperator, matcherValue string
	if err := db.QueryRow(`
		SELECT source_rule.raw_content, matcher.target, matcher.operator, matcher.value
		FROM fingerprint_source_rules AS source_rule
		JOIN fingerprint_rules AS rule ON rule.fingerprint_source_rule_id = source_rule.id
		JOIN fingerprint_match_groups AS match_group ON match_group.fingerprint_rule_id = rule.id
		JOIN fingerprint_matchers AS matcher ON matcher.fingerprint_match_group_id = match_group.id
		WHERE source_rule.source_rule_id = 'banner:1'`).Scan(&rawContent, &matcherTarget, &matcherOperator, &matcherValue); err != nil {
		t.Fatalf("read migrated banner rule: %v", err)
	}
	if rawContent == "" || matcherTarget != "banner" || matcherOperator != "contains" || matcherValue != "nginx" {
		t.Fatalf("migrated banner semantics = raw=%q target=%q operator=%q value=%q", rawContent, matcherTarget, matcherOperator, matcherValue)
	}
	var adapterVersion, unknownStatus, unknownReason string
	var unknownProjectionCount int
	if err := db.QueryRow(`SELECT adapter_version FROM fingerprint_imports AS fingerprint_import JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id WHERE source.source_key = ? AND fingerprint_import.is_active = 1`, legacyBannerSourceKey).Scan(&adapterVersion); err != nil {
		t.Fatal(err)
	}
	if adapterVersion != legacyBannerAdapterVersion {
		t.Fatalf("legacy adapter = %q, want %q", adapterVersion, legacyBannerAdapterVersion)
	}
	if err := db.QueryRow(`
		SELECT source_rule.import_status, COALESCE(source_rule.import_error, ''),
			(SELECT COUNT(*) FROM fingerprint_rules AS rule WHERE rule.fingerprint_source_rule_id = source_rule.id)
		FROM fingerprint_source_rules AS source_rule
		JOIN fingerprint_imports AS fingerprint_import ON fingerprint_import.id = source_rule.fingerprint_import_id AND fingerprint_import.is_active = 1
		JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id
		WHERE source.source_key = ? AND json_extract(source_rule.raw_content, '$.service_name') = 'unknown'
		LIMIT 1`, legacyBannerSourceKey).Scan(&unknownStatus, &unknownReason, &unknownProjectionCount); err != nil {
		t.Fatalf("read unsupported unknown banner row: %v", err)
	}
	if unknownStatus != "unsupported" || unknownReason == "" || unknownProjectionCount != 0 {
		t.Fatalf("unknown legacy rule = status %q reason %q projections %d", unknownStatus, unknownReason, unknownProjectionCount)
	}
	var importCountBefore int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports AS fingerprint_import JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id WHERE source.source_key = ?`, legacyBannerSourceKey).Scan(&importCountBefore); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyBannerFingerprintRules(db); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	var importCount int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM fingerprint_imports AS fingerprint_import
		JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id
		WHERE source.source_key = ?`, legacyBannerSourceKey).Scan(&importCount); err != nil {
		t.Fatalf("count legacy imports: %v", err)
	}
	if importCount != importCountBefore {
		t.Fatalf("repeat migration created %d revisions, want %d", importCount, importCountBefore)
	}
	var legacyBannerRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM banner WHERE service_name = 'nginx' AND banner_pattern = 'nginx'`).Scan(&legacyBannerRows); err != nil {
		t.Fatalf("read original banner: %v", err)
	}
	if legacyBannerRows != 1 {
		t.Fatalf("legacy banner table changed during migration: %d", legacyBannerRows)
	}
}

func TestLegacyBannerV2UpgradeKeepsHistoricalRunFrozenToOldImport(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatal(err)
	}
	var sourceID, v2ID int64
	if err := db.QueryRow(`SELECT fingerprint_import.fingerprint_source_id, fingerprint_import.id FROM fingerprint_imports AS fingerprint_import JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id WHERE source.source_key = ? AND fingerprint_import.is_active = 1`, legacyBannerSourceKey).Scan(&sourceID, &v2ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE fingerprint_imports SET is_active = 0 WHERE id = ?`, v2ID); err != nil {
		t.Fatal(err)
	}
	result, err := db.Exec(`
		INSERT INTO fingerprint_imports
			(fingerprint_source_id, commit_hash, content_sha256, upstream_content_sha256, adapter_version, projection_sha256, manifest_json, is_active)
		VALUES (?, 'v1-banner-migration', 'legacy-old-content', 'legacy-old-content', 'legacy-v1', 'legacy-old-projection', '{}', 1)`, sourceID)
	if err != nil {
		t.Fatal(err)
	}
	oldID, _ := result.LastInsertId()
	task := createScheduledTaskForTest(t, db, "192.168.122.0/24")
	run, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-08-07T01:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyBannerFingerprintRules(db); err != nil {
		t.Fatal(err)
	}
	var activeID int64
	if err := db.QueryRow(`SELECT id FROM fingerprint_imports WHERE fingerprint_source_id = ? AND is_active = 1`, sourceID).Scan(&activeID); err != nil || activeID != v2ID {
		t.Fatalf("active legacy import = %d, want v2 %d, err=%v", activeID, v2ID, err)
	}
	imports, err := ListFingerprintImportsForRun(db, run.ID)
	if err != nil || !containsFingerprintImport(imports, oldID, "v1-banner-migration") || containsFingerprintImport(imports, v2ID, "v1-banner-migration") {
		t.Fatalf("historical run imports = %#v, err=%v", imports, err)
	}
}

func TestLegacyBannerHistoricalRevisionCanBeReactivated(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatal(err)
	}
	var firstID int64
	if err := db.QueryRow(`SELECT fingerprint_import.id FROM fingerprint_imports AS fingerprint_import JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id WHERE source.source_key = ? AND fingerprint_import.is_active = 1`, legacyBannerSourceKey).Scan(&firstID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE banner SET banner_pattern = 'nginx-new' WHERE service_name = 'nginx'`); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyBannerFingerprintRules(db); err != nil {
		t.Fatal(err)
	}
	var secondID int64
	if err := db.QueryRow(`SELECT fingerprint_import.id FROM fingerprint_imports AS fingerprint_import JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id WHERE source.source_key = ? AND fingerprint_import.is_active = 1`, legacyBannerSourceKey).Scan(&secondID); err != nil || secondID == firstID {
		t.Fatalf("second revision=%d first=%d err=%v", secondID, firstID, err)
	}
	if _, err := db.Exec(`UPDATE banner SET banner_pattern = 'nginx' WHERE service_name = 'nginx'`); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyBannerFingerprintRules(db); err != nil {
		t.Fatal(err)
	}
	var activeID int64
	if err := db.QueryRow(`SELECT fingerprint_import.id FROM fingerprint_imports AS fingerprint_import JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id WHERE source.source_key = ? AND fingerprint_import.is_active = 1`, legacyBannerSourceKey).Scan(&activeID); err != nil || activeID != firstID {
		t.Fatalf("reactivated revision=%d want=%d err=%v", activeID, firstID, err)
	}
}

func TestImportFingerprintBatchAtomicallySwitchesActiveRevisionAndFreezesRuns(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	first, err := ImportFingerprintBatch(db, fingerprintBatchFixture("commit-one", "archive-one", "rule-one"))
	if err != nil {
		t.Fatalf("import first revision: %v", err)
	}
	if !first.IsActive {
		t.Fatalf("first import must become active: %#v", first)
	}
	task := createScheduledTaskForTest(t, db, "192.168.121.0/24")
	firstRun, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-30T03:00:00Z"})
	if err != nil {
		t.Fatalf("create first run: %v", err)
	}
	if imports, err := ListFingerprintImportsForRun(db, firstRun.ID); err != nil || !containsFingerprintImport(imports, first.ID, first.Commit) {
		t.Fatalf("first run imports = %#v, err=%v", imports, err)
	}

	second, err := ImportFingerprintBatch(db, fingerprintBatchFixture("commit-two", "archive-two", "rule-two"))
	if err != nil {
		t.Fatalf("import second revision: %v", err)
	}
	if !second.IsActive {
		t.Fatalf("second import must become active: %#v", second)
	}
	firstAfterUpgrade, err := ListFingerprintImportsForRun(db, firstRun.ID)
	if err != nil || !containsFingerprintImport(firstAfterUpgrade, first.ID, first.Commit) || containsFingerprintImport(firstAfterUpgrade, second.ID, second.Commit) {
		t.Fatalf("rule upgrade rewrote first run imports = %#v, err=%v", firstAfterUpgrade, err)
	}

	bad := fingerprintBatchFixture("commit-three", "archive-three", "rule-three")
	bad.Import.RuleTotal = 2
	bad.Import.ExecutableTotal = 2
	bad.Rules = append(bad.Rules, bad.Rules[0])
	if _, err := ImportFingerprintBatch(db, bad); err == nil {
		t.Fatal("duplicate raw rule must fail the complete batch")
	}
	var activeCommit string
	if err := db.QueryRow(`
		SELECT commit_hash FROM fingerprint_imports
		WHERE fingerprint_source_id = ? AND is_active = 1`, second.FingerprintSourceID).Scan(&activeCommit); err != nil {
		t.Fatalf("read active import after failed batch: %v", err)
	}
	if activeCommit != "commit-two" {
		t.Fatalf("failed batch changed active revision to %q", activeCommit)
	}
	var thirdCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports WHERE commit_hash = 'commit-three'`).Scan(&thirdCount); err != nil {
		t.Fatalf("count failed revision: %v", err)
	}
	if thirdCount != 0 {
		t.Fatalf("failed batch left partial import rows: %d", thirdCount)
	}

	secondRun, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-31T03:00:00Z"})
	if err != nil {
		t.Fatalf("create second run: %v", err)
	}
	if imports, err := ListFingerprintImportsForRun(db, secondRun.ID); err != nil || !containsFingerprintImport(imports, second.ID, second.Commit) {
		t.Fatalf("second run imports = %#v, err=%v", imports, err)
	}
}

func TestFingerprintSourceRulePageFiltersHistoryProductAndStatus(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatal(err)
	}
	first, err := ImportFingerprintBatch(db, fingerprintBatchFixture("page-a", "page-archive-a", "page-rule-a"))
	if err != nil {
		t.Fatal(err)
	}
	secondBatch := fingerprintBatchFixture("page-b", "page-archive-b", "page-rule-b")
	secondBatch.Rules[0].SourceRuleID = "page-rule-b"
	secondBatch.Projections[0].Product.CanonicalName = "page-product"
	second, err := ImportFingerprintBatch(db, secondBatch)
	if err != nil {
		t.Fatal(err)
	}
	page, err := ListFingerprintSourceRulesPage(db, FingerprintSourceRuleQuery{SourceKey: secondBatch.Source.SourceKey, ImportID: second.ID, RuleID: "page-rule-b", Product: "PAGE-PRODUCT", Status: "executable", Page: 1, PageSize: 1})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Product != "page-product" {
		t.Fatalf("filtered page=%#v err=%v", page, err)
	}
	history, err := ListFingerprintSourceRulesPage(db, FingerprintSourceRuleQuery{SourceKey: secondBatch.Source.SourceKey, ImportID: first.ID, Page: 1, PageSize: 10})
	if err != nil || history.Total != 1 || history.Items[0].FingerprintImportID != first.ID {
		t.Fatalf("historical page=%#v err=%v", history, err)
	}
}

func TestSaveFingerprintRunMatchesPreservesCorroborationAndConflicts(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	first, err := ImportFingerprintBatch(db, fingerprintBatchFixture("source-a", "archive-a", "rule-a"))
	if err != nil {
		t.Fatalf("import source a: %v", err)
	}
	secondBatch := fingerprintBatchFixture("source-b", "archive-b", "rule-b")
	secondBatch.Source.SourceKey = "fixture-source-b"
	secondBatch.Import.ManifestJSON = `{"source_key":"fixture-source-b"}`
	second, err := ImportFingerprintBatch(db, secondBatch)
	if err != nil {
		t.Fatalf("import source b: %v", err)
	}
	var firstRule, secondRule, firstMatcher, secondMatcher int64
	if err := db.QueryRow(`SELECT id FROM fingerprint_source_rules WHERE fingerprint_import_id = ?`, first.ID).Scan(&firstRule); err != nil {
		t.Fatalf("read source a rule: %v", err)
	}
	if err := db.QueryRow(`SELECT id FROM fingerprint_source_rules WHERE fingerprint_import_id = ?`, second.ID).Scan(&secondRule); err != nil {
		t.Fatalf("read source b rule: %v", err)
	}
	if err := db.QueryRow(`SELECT matcher.id FROM fingerprint_matchers matcher JOIN fingerprint_match_groups match_group ON match_group.id = matcher.fingerprint_match_group_id JOIN fingerprint_rules rule ON rule.id = match_group.fingerprint_rule_id WHERE rule.fingerprint_source_rule_id = ?`, firstRule).Scan(&firstMatcher); err != nil {
		t.Fatalf("read source a matcher: %v", err)
	}
	if err := db.QueryRow(`SELECT matcher.id FROM fingerprint_matchers matcher JOIN fingerprint_match_groups match_group ON match_group.id = matcher.fingerprint_match_group_id JOIN fingerprint_rules rule ON rule.id = match_group.fingerprint_rule_id WHERE rule.fingerprint_source_rule_id = ?`, secondRule).Scan(&secondMatcher); err != nil {
		t.Fatalf("read source b matcher: %v", err)
	}
	task := createScheduledTaskForTest(t, db, "192.168.122.0/24")
	run, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-07-30T04:00:00Z"})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	matches := []FingerprintRunMatch{
		{FingerprintImportID: first.ID, FingerprintSourceRuleID: firstRule, IP: "192.168.122.10", Port: 443, Protocol: "https", Product: "nginx", EvidenceSummary: "header: server", Evidence: fixtureMatchEvidence(firstMatcher)},
		{FingerprintImportID: second.ID, FingerprintSourceRuleID: secondRule, IP: "192.168.122.10", Port: 443, Protocol: "https", Product: "nginx", EvidenceSummary: "body: nginx", Evidence: fixtureMatchEvidence(secondMatcher)},
		{FingerprintImportID: first.ID, FingerprintSourceRuleID: firstRule, IP: "192.168.122.11", Port: 8443, Protocol: "https", Product: "nginx", EvidenceSummary: "header: server", Evidence: fixtureMatchEvidence(firstMatcher)},
		{FingerprintImportID: second.ID, FingerprintSourceRuleID: secondRule, IP: "192.168.122.11", Port: 8443, Protocol: "https", Product: "apache", EvidenceSummary: "body: apache", Evidence: fixtureMatchEvidence(secondMatcher)},
		{FingerprintImportID: first.ID, FingerprintSourceRuleID: firstRule, IP: "192.168.122.12", Port: 22, Protocol: "tcp", Product: "openssh", Version: "9.6", CPE: "cpe:/a:openbsd:openssh:9.6", EvidenceSummary: "banner: openssh-a", Evidence: fixtureMatchEvidence(firstMatcher)},
		{FingerprintImportID: second.ID, FingerprintSourceRuleID: secondRule, IP: "192.168.122.12", Port: 22, Protocol: "tcp", Product: "openssh", Version: "9.7", CPE: "cpe:/a:openbsd:openssh:9.7", EvidenceSummary: "banner: openssh-b", Evidence: fixtureMatchEvidence(secondMatcher)},
		{FingerprintImportID: first.ID, FingerprintSourceRuleID: firstRule, IP: "192.168.122.14", Port: 22, Protocol: "tcp", Product: "openssh", Version: "9.6", CPE: "cpe:/a:openbsd:openssh:9.6", EvidenceSummary: "banner: versioned", Evidence: fixtureMatchEvidence(firstMatcher)},
		{FingerprintImportID: second.ID, FingerprintSourceRuleID: secondRule, IP: "192.168.122.14", Port: 22, Protocol: "tcp", Product: "openssh", EvidenceSummary: "banner: product-only", Evidence: fixtureMatchEvidence(secondMatcher)},
		{FingerprintImportID: first.ID, FingerprintSourceRuleID: firstRule, IP: "192.168.122.15", Port: 22, Protocol: "tcp", Product: "openssh", Version: "9.6", CPE: "cpe:/a:openbsd:openssh:9.6", EvidenceSummary: "banner: same-a", Evidence: fixtureMatchEvidence(firstMatcher)},
		{FingerprintImportID: second.ID, FingerprintSourceRuleID: secondRule, IP: "192.168.122.15", Port: 22, Protocol: "tcp", Product: "openssh", Version: "9.6", CPE: "cpe:/a:openbsd:openssh:9.6", EvidenceSummary: "banner: same-b", Evidence: fixtureMatchEvidence(secondMatcher)},
		{FingerprintImportID: first.ID, FingerprintSourceRuleID: firstRule, IP: "192.168.122.16", Port: 82, Protocol: "http", Product: "nginx", EvidenceSummary: "header: nginx", Evidence: fixtureMatchEvidence(firstMatcher)},
		{FingerprintImportID: second.ID, FingerprintSourceRuleID: secondRule, IP: "192.168.122.16", Port: 82, Protocol: "http", Product: "html5", EvidenceSummary: "body: html5", Evidence: fixtureMatchEvidence(secondMatcher)},
		{FingerprintImportID: second.ID, FingerprintSourceRuleID: secondRule, IP: "192.168.122.16", Port: 82, Protocol: "http", Product: "script", EvidenceSummary: "body: script", Evidence: fixtureMatchEvidence(secondMatcher)},
	}
	if err := SaveFingerprintRunMatches(db, run.ID, matches); err != nil {
		t.Fatalf("save matches: %v", err)
	}
	rows, err := db.Query(`SELECT ip, product_key, conclusion_status FROM asset_fingerprint_conclusions WHERE scan_task_run_id = ? ORDER BY ip, product_key`, run.ID)
	if err != nil {
		t.Fatalf("query conclusions: %v", err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var ip, product, status string
		if err := rows.Scan(&ip, &product, &status); err != nil {
			t.Fatalf("scan conclusion: %v", err)
		}
		got[ip+"/"+product] = status
	}
	if got["192.168.122.10/nginx"] != "corroborated" || got["192.168.122.11/nginx"] != "conflicted" || got["192.168.122.11/apache"] != "conflicted" || got["192.168.122.12/openssh"] != "corroborated" {
		t.Fatalf("conclusions = %#v", got)
	}
	for _, product := range []string{"nginx", "html5", "script"} {
		if got["192.168.122.16/"+product] != "matched" {
			t.Fatalf("layered product %s was treated as a conflict: %#v", product, got)
		}
	}
	var conflictedVersion, conflictedCPE sql.NullString
	var productStatus, versionStatus, cpeStatus string
	var productSources, versionSources, cpeSources int
	if err := db.QueryRow(`SELECT version, cpe, product_status, product_source_count, version_status, version_source_count, cpe_status, cpe_source_count FROM asset_fingerprint_conclusions WHERE scan_task_run_id = ? AND ip = '192.168.122.12' AND product_key = 'openssh'`, run.ID).Scan(&conflictedVersion, &conflictedCPE, &productStatus, &productSources, &versionStatus, &versionSources, &cpeStatus, &cpeSources); err != nil {
		t.Fatalf("read conflicted metadata: %v", err)
	}
	if conflictedVersion.Valid || conflictedCPE.Valid || productStatus != "corroborated" || productSources != 2 || versionStatus != "conflicted" || versionSources != 2 || cpeStatus != "conflicted" || cpeSources != 2 {
		t.Fatalf("layered conflict conclusion: version=%#v cpe=%#v product=%s/%d version=%s/%d cpe=%s/%d", conflictedVersion, conflictedCPE, productStatus, productSources, versionStatus, versionSources, cpeStatus, cpeSources)
	}
	var versionValue, cpeValue string
	if err := db.QueryRow(`SELECT version, cpe, product_status, product_source_count, version_status, version_source_count, cpe_status, cpe_source_count FROM asset_fingerprint_conclusions WHERE scan_task_run_id = ? AND ip = '192.168.122.14'`, run.ID).Scan(&versionValue, &cpeValue, &productStatus, &productSources, &versionStatus, &versionSources, &cpeStatus, &cpeSources); err != nil {
		t.Fatal(err)
	}
	if versionValue != "9.6" || cpeValue != "cpe:/a:openbsd:openssh:9.6" || productStatus != "corroborated" || productSources != 2 || versionStatus != "matched" || versionSources != 1 || cpeStatus != "matched" || cpeSources != 1 {
		t.Fatalf("single-source metadata inherited product corroboration: version=%q cpe=%q product=%s/%d version=%s/%d cpe=%s/%d", versionValue, cpeValue, productStatus, productSources, versionStatus, versionSources, cpeStatus, cpeSources)
	}
	if err := db.QueryRow(`SELECT version_status, version_source_count, cpe_status, cpe_source_count FROM asset_fingerprint_conclusions WHERE scan_task_run_id = ? AND ip = '192.168.122.15'`, run.ID).Scan(&versionStatus, &versionSources, &cpeStatus, &cpeSources); err != nil {
		t.Fatal(err)
	}
	if versionStatus != "corroborated" || versionSources != 2 || cpeStatus != "corroborated" || cpeSources != 2 {
		t.Fatalf("identical metadata was not corroborated: version=%s/%d cpe=%s/%d", versionStatus, versionSources, cpeStatus, cpeSources)
	}
	if err := SaveFingerprintRunMatches(db, run.ID, []FingerprintRunMatch{{
		FingerprintImportID: first.ID, FingerprintSourceRuleID: firstRule,
		IP: "192.168.122.13", Port: 8080, Protocol: "tcp", Product: "Jenkins",
		Version: "2.452.1", CPE: "cpe:/a:jenkins:jenkins:2.452.1", Tags: []string{"CI", "java"}, Soft: true,
		EvidenceSummary: "tcp matcher=soft", Evidence: fixtureMatchEvidence(firstMatcher),
	}}); err != nil {
		t.Fatalf("save soft match: %v", err)
	}
	var product, version, cpe, tagsJSON string
	var soft, conclusionCount int
	if err := db.QueryRow(`SELECT product_key, version, cpe, tags_json, is_soft FROM asset_fingerprint_matches WHERE ip = '192.168.122.13'`).Scan(&product, &version, &cpe, &tagsJSON, &soft); err != nil {
		t.Fatalf("read soft match: %v", err)
	}
	if product != "jenkins" || version != "2.452.1" || cpe != "cpe:/a:jenkins:jenkins:2.452.1" || tagsJSON != `["ci","java"]` || soft != 1 {
		t.Fatalf("soft match metadata = product=%q version=%q cpe=%q tags=%q soft=%d", product, version, cpe, tagsJSON, soft)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM asset_fingerprint_conclusions WHERE ip = '192.168.122.13'`).Scan(&conclusionCount); err != nil || conclusionCount != 0 {
		t.Fatalf("soft-only conclusion count = %d, err=%v", conclusionCount, err)
	}
	if err := SaveFingerprintRunMatches(db, run.ID, []FingerprintRunMatch{{FingerprintImportID: 99999, FingerprintSourceRuleID: firstRule, IP: "192.168.122.12", Port: 80, Protocol: "http", Product: "fixture", EvidenceSummary: "test"}}); err == nil {
		t.Fatal("unfrozen import must be rejected")
	}
}

func TestStartupAndNewImportDoNotRewriteHistoricalProductRoles(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatal(err)
	}
	firstBatch := fingerprintBatchFixture("role-first", "role-first", "role-first")
	firstBatch.Projections[0].Product.Role = "web_server"
	firstBatch.Projections[0].Product.ExclusiveGroup = "web_server"
	first, err := ImportFingerprintBatch(db, firstBatch)
	if err != nil {
		t.Fatal(err)
	}
	var sourceRuleID, matcherID int64
	if err := db.QueryRow(`SELECT source_rule.id, matcher.id FROM fingerprint_source_rules AS source_rule JOIN fingerprint_rules AS rule ON rule.fingerprint_source_rule_id = source_rule.id JOIN fingerprint_match_groups AS match_group ON match_group.fingerprint_rule_id = rule.id JOIN fingerprint_matchers AS matcher ON matcher.fingerprint_match_group_id = match_group.id WHERE source_rule.fingerprint_import_id = ?`, first.ID).Scan(&sourceRuleID, &matcherID); err != nil {
		t.Fatal(err)
	}
	task := createScheduledTaskForTest(t, db, "192.168.123.0/24")
	run, err := CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-08-07T01:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveFingerprintRunMatches(db, run.ID, []FingerprintRunMatch{{
		FingerprintImportID: first.ID, FingerprintSourceRuleID: sourceRuleID, IP: "192.168.123.10", Port: 80, Protocol: "http",
		Product: "fixture", ProductRole: "web_server", ExclusiveGroup: "web_server", EvidenceSummary: "frozen role", Evidence: fixtureMatchEvidence(matcherID),
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE asset_fingerprint_conclusions SET product_status = 'corroborated', conclusion_status = 'corroborated' WHERE scan_task_run_id = ?`, run.ID); err != nil {
		t.Fatal(err)
	}
	secondBatch := fingerprintBatchFixture("role-second", "role-second", "role-second")
	secondBatch.Projections[0].Product.Role = "application"
	secondBatch.Projections[0].Product.ExclusiveGroup = ""
	if _, err := ImportFingerprintBatch(db, secondBatch); err != nil {
		t.Fatal(err)
	}
	if err := ensureSQLiteMigrations(db); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"asset_fingerprint_matches", "asset_fingerprint_conclusions"} {
		var role, group string
		var status string
		query := `SELECT product_role, exclusive_group, '' FROM ` + table + ` WHERE scan_task_run_id = ?`
		if table == "asset_fingerprint_conclusions" {
			query = `SELECT product_role, exclusive_group, product_status FROM asset_fingerprint_conclusions WHERE scan_task_run_id = ?`
		}
		if err := db.QueryRow(query, run.ID).Scan(&role, &group, &status); err != nil {
			t.Fatal(err)
		}
		if role != "web_server" || group != "web_server" {
			t.Fatalf("%s historical role changed to %q/%q", table, role, group)
		}
		if table == "asset_fingerprint_conclusions" && status != "corroborated" {
			t.Fatalf("historical conclusion status was recomputed: %q", status)
		}
	}
}

func fixtureMatchEvidence(matcherID int64) []model.FingerprintMatchEvidence {
	return []model.FingerprintMatchEvidence{{MatcherID: matcherID, EvidenceType: "http_body", Target: "body", Operator: "contains", ObservedSHA256: strings.Repeat("0", 64), ObservedLength: 7, Summary: "http_body body bytes=7 sha256=" + strings.Repeat("0", 64)}}
}

func containsFingerprintImport(imports []model.FingerprintImport, id int64, commit string) bool {
	for _, fingerprintImport := range imports {
		if fingerprintImport.ID == id && fingerprintImport.Commit == commit {
			return true
		}
	}
	return false
}

func fingerprintBatchFixture(commit, archiveSHA, ruleSHA string) FingerprintImportBatch {
	return FingerprintImportBatch{
		Source: model.FingerprintSource{
			SourceKey:     "fixture-source",
			RepositoryURL: "https://example.invalid/fingerprint",
			Status:        "enabled",
		},
		Import: model.FingerprintImport{
			Commit:          commit,
			ContentSHA256:   archiveSHA,
			ManifestJSON:    `{"source_key":"fixture-source"}`,
			RuleTotal:       1,
			ExecutableTotal: 1,
		},
		Rules: []model.FingerprintSourceRule{{
			SourcePath:    "rules/fixture.json",
			ContentSHA256: ruleSHA,
			RawContent:    `{"name":"fixture"}`,
			ImportStatus:  "executable",
		}},
		Projections: []model.FingerprintRuleProjection{{
			SourcePath: "rules/fixture.json", ContentSHA256: ruleSHA,
			Product: model.FingerprintProduct{CanonicalName: "fixture"}, Protocol: "http",
			Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{EvidenceType: "http_body", Target: "body", Operator: "contains", Value: "fixture"}}},
		}},
	}
}
