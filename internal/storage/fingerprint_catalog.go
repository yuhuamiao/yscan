package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"golandproject/yscan/internal/model"
)

const legacyBannerSourceKey = "legacy-banner"

const legacyBannerAdapterVersion = "legacy-banner-v3"

type legacyBannerRule struct {
	ID            int64  `json:"id"`
	ServiceName   string `json:"service_name"`
	BannerPattern string `json:"banner_pattern"`
	MatchType     string `json:"match_type"`
	Protocol      string `json:"protocol"`
	Port          int    `json:"port,omitempty"`
	Description   string `json:"description,omitempty"`
}

var (
	ErrFingerprintSourceNotFound = errors.New("fingerprint source not found")
	ErrFingerprintImportNotFound = errors.New("fingerprint import not found")
)

func RecordFingerprintBootstrapFailure(db *sql.DB, sourceKey string, failure error) error {
	if db == nil || strings.TrimSpace(sourceKey) == "" || failure == nil {
		return errors.New("fingerprint bootstrap failure requires database, source, and error")
	}
	_, err := db.Exec(`
		INSERT INTO fingerprint_source_bootstrap_diagnostics (source_key, last_error, last_failed_at, resolved_at, updated_at)
		VALUES (?, ?, datetime('now'), NULL, datetime('now'))
		ON CONFLICT(source_key) DO UPDATE SET last_error = excluded.last_error,
			last_failed_at = excluded.last_failed_at, resolved_at = NULL, updated_at = excluded.updated_at`,
		strings.TrimSpace(sourceKey), failure.Error())
	return err
}

func ResolveFingerprintBootstrapDiagnostic(db *sql.DB, sourceKey string) error {
	if db == nil || strings.TrimSpace(sourceKey) == "" {
		return errors.New("fingerprint bootstrap resolution requires database and source")
	}
	_, err := db.Exec(`
		INSERT INTO fingerprint_source_bootstrap_diagnostics (source_key, last_error, resolved_at, updated_at)
		VALUES (?, '', datetime('now'), datetime('now'))
		ON CONFLICT(source_key) DO UPDATE SET resolved_at = datetime('now'), updated_at = datetime('now')`, strings.TrimSpace(sourceKey))
	return err
}

// FingerprintImportBatch is a fully validated source revision. Individual
// unsupported or import_error rules remain part of the batch and its audit
// totals; only structural failures roll back the entire revision.
type FingerprintImportBatch struct {
	Source      model.FingerprintSource
	Import      model.FingerprintImport
	Rules       []model.FingerprintSourceRule
	Projections []model.FingerprintRuleProjection
}

type FingerprintCleanupCandidate struct {
	ImportID              int64
	SourceKey             string
	Commit                string
	AdapterVersion        string
	RuleTotal             int
	EstimatedPayloadBytes int64
	CreatedAt             string
}

type FingerprintCleanupPlan struct {
	Candidates            []FingerprintCleanupCandidate
	EstimatedPayloadBytes int64
	DeletedImports        int
}

const fingerprintCleanupEligibility = `
	fingerprint_import.is_active = 0
	AND NOT EXISTS (
		SELECT 1 FROM scan_task_run_fingerprint_imports AS run_import
		WHERE run_import.fingerprint_import_id = fingerprint_import.id
	)
	AND NOT EXISTS (
		SELECT 1 FROM asset_fingerprint_matches AS asset_match
		WHERE asset_match.fingerprint_import_id = fingerprint_import.id
	)
	AND NOT EXISTS (
		SELECT 1 FROM asset_fingerprint_matches AS asset_match
		JOIN fingerprint_source_rules AS source_rule ON source_rule.id = asset_match.fingerprint_source_rule_id
		WHERE source_rule.fingerprint_import_id = fingerprint_import.id
	)`

type fingerprintCleanupQueryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// PlanFingerprintImportCleanup returns only inactive revisions with no run
// freeze or historical match references. It never mutates the catalog.
func PlanFingerprintImportCleanup(db *sql.DB) (FingerprintCleanupPlan, error) {
	if db == nil {
		return FingerprintCleanupPlan{}, errors.New("fingerprint cleanup database is required")
	}
	return planFingerprintImportCleanup(db)
}

func planFingerprintImportCleanup(queryer fingerprintCleanupQueryer) (FingerprintCleanupPlan, error) {
	rows, err := queryer.Query(`
		SELECT fingerprint_import.id, source.source_key, fingerprint_import.commit_hash,
			fingerprint_import.adapter_version, fingerprint_import.rule_total,
			LENGTH(fingerprint_import.manifest_json) + COALESCE((
				SELECT SUM(LENGTH(source_rule.source_path) + LENGTH(source_rule.content_sha256) +
					LENGTH(source_rule.raw_content) + LENGTH(COALESCE(source_rule.raw_structure, '')) +
					LENGTH(COALESCE(source_rule.import_error, '')))
				FROM fingerprint_source_rules AS source_rule
				WHERE source_rule.fingerprint_import_id = fingerprint_import.id
			), 0), fingerprint_import.created_at
		FROM fingerprint_imports AS fingerprint_import
		JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id
		WHERE ` + fingerprintCleanupEligibility + `
		ORDER BY source.source_key, fingerprint_import.created_at, fingerprint_import.id`)
	if err != nil {
		return FingerprintCleanupPlan{}, err
	}
	defer rows.Close()
	plan := FingerprintCleanupPlan{Candidates: make([]FingerprintCleanupCandidate, 0)}
	for rows.Next() {
		var candidate FingerprintCleanupCandidate
		if err := rows.Scan(&candidate.ImportID, &candidate.SourceKey, &candidate.Commit, &candidate.AdapterVersion, &candidate.RuleTotal, &candidate.EstimatedPayloadBytes, &candidate.CreatedAt); err != nil {
			return FingerprintCleanupPlan{}, err
		}
		plan.Candidates = append(plan.Candidates, candidate)
		plan.EstimatedPayloadBytes += candidate.EstimatedPayloadBytes
	}
	return plan, rows.Err()
}

// ApplyFingerprintImportCleanup recomputes eligibility inside the deletion
// transaction. ON DELETE CASCADE removes that immutable revision's projection.
func ApplyFingerprintImportCleanup(db *sql.DB) (FingerprintCleanupPlan, error) {
	if db == nil {
		return FingerprintCleanupPlan{}, errors.New("fingerprint cleanup database is required")
	}
	tx, err := db.Begin()
	if err != nil {
		return FingerprintCleanupPlan{}, err
	}
	defer func() { _ = tx.Rollback() }()
	plan, err := planFingerprintImportCleanup(tx)
	if err != nil {
		return FingerprintCleanupPlan{}, err
	}
	for _, candidate := range plan.Candidates {
		result, err := tx.Exec(`DELETE FROM fingerprint_imports AS fingerprint_import WHERE fingerprint_import.id = ? AND `+fingerprintCleanupEligibility, candidate.ImportID)
		if err != nil {
			return FingerprintCleanupPlan{}, err
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return FingerprintCleanupPlan{}, err
		}
		if deleted != 1 {
			return FingerprintCleanupPlan{}, fmt.Errorf("fingerprint import %d became referenced during cleanup", candidate.ImportID)
		}
		plan.DeletedImports++
	}
	if err := tx.Commit(); err != nil {
		return FingerprintCleanupPlan{}, err
	}
	return plan, nil
}

// TemplateMappingBatch is a reviewed local template mapping revision. The
// caller must verify each template SHA-256 before this transaction is entered.
type TemplateMappingBatch struct {
	Import   model.TemplateMappingImport
	Mappings []model.FingerprintTemplateMapping
}

// CreateFingerprintSource stores stable upstream identity. Import revisions are
// intentionally separate so upgrades cannot rewrite historical provenance.
func CreateFingerprintSource(db *sql.DB, source model.FingerprintSource) (model.FingerprintSource, error) {
	source.SourceKey = strings.TrimSpace(source.SourceKey)
	source.RepositoryURL = strings.TrimSpace(source.RepositoryURL)
	source.License = strings.TrimSpace(source.License)
	source.Status = strings.TrimSpace(source.Status)
	if source.Status == "" {
		source.Status = "enabled"
	}
	if source.SourceKey == "" || source.RepositoryURL == "" {
		return model.FingerprintSource{}, errors.New("fingerprint source key and repository URL are required")
	}
	result, err := db.Exec(`
		INSERT INTO fingerprint_sources (source_key, repository_url, license, status)
		VALUES (?, ?, ?, ?)`, source.SourceKey, source.RepositoryURL, source.License, source.Status)
	if err != nil {
		return model.FingerprintSource{}, err
	}
	source.ID, err = result.LastInsertId()
	if err != nil {
		return model.FingerprintSource{}, err
	}
	return GetFingerprintSource(db, source.ID)
}

func GetFingerprintSource(db *sql.DB, sourceID int64) (model.FingerprintSource, error) {
	var source model.FingerprintSource
	err := db.QueryRow(`
		SELECT id, source_key, repository_url, COALESCE(license, ''), status, created_at, updated_at
		FROM fingerprint_sources WHERE id = ?`, sourceID).Scan(
		&source.ID, &source.SourceKey, &source.RepositoryURL, &source.License,
		&source.Status, &source.CreatedAt, &source.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.FingerprintSource{}, ErrFingerprintSourceNotFound
	}
	return source, err
}

func ListFingerprintSources(db *sql.DB) ([]model.FingerprintSource, error) {
	rows, err := db.Query(`
		SELECT source.id, source.source_key, source.repository_url, COALESCE(source.license, ''), source.status,
			source.created_at, source.updated_at,
			CASE WHEN diagnostic.resolved_at IS NULL AND COALESCE(diagnostic.last_error, '') <> '' THEN 'failed'
				WHEN EXISTS (SELECT 1 FROM fingerprint_imports AS active_import WHERE active_import.fingerprint_source_id = source.id AND active_import.is_active = 1) THEN 'active'
				ELSE 'missing' END,
			COALESCE(CASE WHEN diagnostic.resolved_at IS NULL THEN diagnostic.last_error ELSE '' END, ''),
			COALESCE(CASE WHEN diagnostic.resolved_at IS NULL THEN diagnostic.last_failed_at ELSE '' END, ''),
			EXISTS (SELECT 1 FROM fingerprint_imports AS active_import WHERE active_import.fingerprint_source_id = source.id AND active_import.is_active = 1)
		FROM fingerprint_sources AS source
		LEFT JOIN fingerprint_source_bootstrap_diagnostics AS diagnostic ON diagnostic.source_key = source.source_key
		ORDER BY source.source_key ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sources := make([]model.FingerprintSource, 0)
	for rows.Next() {
		var source model.FingerprintSource
		if err := rows.Scan(&source.ID, &source.SourceKey, &source.RepositoryURL, &source.License, &source.Status, &source.CreatedAt, &source.UpdatedAt,
			&source.CatalogStatus, &source.LastError, &source.LastFailedAt, &source.HasActiveImport); err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	return sources, rows.Err()
}

// CreateFingerprintImport stores a complete immutable source revision. T255
// will provide manifest validation and active-import switching; this layer only
// persists a validated revision and its accounting fields.
func CreateFingerprintImport(db *sql.DB, fingerprintImport model.FingerprintImport) (model.FingerprintImport, error) {
	if fingerprintImport.FingerprintSourceID <= 0 {
		return model.FingerprintImport{}, errors.New("fingerprint source ID is required")
	}
	fingerprintImport.Commit = strings.TrimSpace(fingerprintImport.Commit)
	fingerprintImport.ContentSHA256 = strings.TrimSpace(fingerprintImport.ContentSHA256)
	fingerprintImport.ManifestJSON = strings.TrimSpace(fingerprintImport.ManifestJSON)
	if fingerprintImport.Commit == "" || fingerprintImport.ContentSHA256 == "" || fingerprintImport.ManifestJSON == "" {
		return model.FingerprintImport{}, errors.New("fingerprint import commit, content SHA-256, and manifest are required")
	}
	if fingerprintImport.RuleTotal < 0 || fingerprintImport.ExecutableTotal < 0 || fingerprintImport.UnsupportedTotal < 0 || fingerprintImport.ImportErrorTotal < 0 {
		return model.FingerprintImport{}, errors.New("fingerprint import totals cannot be negative")
	}
	if fingerprintImport.IsActive {
		return model.FingerprintImport{}, errors.New("active fingerprint imports require an atomic batch import")
	}
	result, err := db.Exec(`
		INSERT INTO fingerprint_imports
			(fingerprint_source_id, commit_hash, content_sha256, manifest_json, rule_total, executable_total, unsupported_total, import_error_total, error_summary, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fingerprintImport.FingerprintSourceID, fingerprintImport.Commit, fingerprintImport.ContentSHA256, fingerprintImport.ManifestJSON,
		fingerprintImport.RuleTotal, fingerprintImport.ExecutableTotal, fingerprintImport.UnsupportedTotal, fingerprintImport.ImportErrorTotal,
		strings.TrimSpace(fingerprintImport.ErrorSummary), boolToInt(fingerprintImport.IsActive),
	)
	if err != nil {
		return model.FingerprintImport{}, err
	}
	fingerprintImport.ID, err = result.LastInsertId()
	if err != nil {
		return model.FingerprintImport{}, err
	}
	return GetFingerprintImport(db, fingerprintImport.ID)
}

// ImportFingerprintBatch writes a complete source revision and switches its
// active import in one transaction. A source can contain unsupported rules;
// only invalid batch accounting or persistence errors prevent activation.
func ImportFingerprintBatch(db *sql.DB, batch FingerprintImportBatch) (model.FingerprintImport, error) {
	prepareFingerprintExecutionRevision(&batch)
	if err := validateFingerprintImportBatch(batch); err != nil {
		return model.FingerprintImport{}, err
	}
	tx, err := db.Begin()
	if err != nil {
		return model.FingerprintImport{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`
		INSERT INTO fingerprint_sources (source_key, repository_url, license, status)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(source_key) DO UPDATE SET
			repository_url = excluded.repository_url,
			license = excluded.license,
			status = excluded.status,
			updated_at = datetime('now')`,
		batch.Source.SourceKey, batch.Source.RepositoryURL, batch.Source.License, batch.Source.Status,
	); err != nil {
		return model.FingerprintImport{}, err
	}
	var sourceID int64
	if err := tx.QueryRow(`SELECT id FROM fingerprint_sources WHERE source_key = ?`, batch.Source.SourceKey).Scan(&sourceID); err != nil {
		return model.FingerprintImport{}, err
	}

	var existingID int64
	err = tx.QueryRow(`
		SELECT id FROM fingerprint_imports
		WHERE fingerprint_source_id = ? AND commit_hash = ?
			AND upstream_content_sha256 = ? AND adapter_version = ? AND projection_sha256 = ?`,
		sourceID, batch.Import.Commit, batch.Import.UpstreamContentSHA256,
		batch.Import.AdapterVersion, batch.Import.ProjectionSHA256,
	).Scan(&existingID)
	if err == nil {
		if err := verifyFingerprintRuleProjections(tx, existingID, len(batch.Projections)); err != nil {
			return model.FingerprintImport{}, err
		}
		if err := activateFingerprintImportTx(tx, sourceID, existingID); err != nil {
			return model.FingerprintImport{}, err
		}
		if err := tx.Commit(); err != nil {
			return model.FingerprintImport{}, err
		}
		return GetFingerprintImport(db, existingID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return model.FingerprintImport{}, err
	}

	result, err := tx.Exec(`
		INSERT INTO fingerprint_imports
			(fingerprint_source_id, commit_hash, content_sha256, upstream_content_sha256, adapter_version, projection_sha256,
			 manifest_json, rule_total, executable_total, unsupported_total, import_error_total, error_summary, is_active)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		sourceID, batch.Import.Commit, batch.Import.ContentSHA256, batch.Import.UpstreamContentSHA256,
		batch.Import.AdapterVersion, batch.Import.ProjectionSHA256, batch.Import.ManifestJSON,
		batch.Import.RuleTotal, batch.Import.ExecutableTotal, batch.Import.UnsupportedTotal, batch.Import.ImportErrorTotal,
		batch.Import.ErrorSummary,
	)
	if err != nil {
		return model.FingerprintImport{}, err
	}
	importID, err := result.LastInsertId()
	if err != nil {
		return model.FingerprintImport{}, err
	}
	for _, rule := range batch.Rules {
		if _, err := tx.Exec(`
			INSERT INTO fingerprint_source_rules
				(fingerprint_import_id, source_rule_id, source_path, content_sha256, raw_content, raw_structure, import_status, import_error)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			importID, rule.SourceRuleID, rule.SourcePath, rule.ContentSHA256, rule.RawContent,
			rule.RawStructure, rule.ImportStatus, rule.ImportError,
		); err != nil {
			return model.FingerprintImport{}, err
		}
	}
	if err := persistFingerprintRuleProjections(tx, importID, batch.Projections); err != nil {
		return model.FingerprintImport{}, err
	}
	if err := activateFingerprintImportTx(tx, sourceID, importID); err != nil {
		return model.FingerprintImport{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.FingerprintImport{}, err
	}
	return GetFingerprintImport(db, importID)
}

func prepareFingerprintExecutionRevision(batch *FingerprintImportBatch) {
	if batch == nil {
		return
	}
	upstream := strings.TrimSpace(batch.Import.UpstreamContentSHA256)
	if upstream == "" {
		upstream = strings.TrimSpace(batch.Import.ContentSHA256)
	}
	adapter := strings.TrimSpace(batch.Import.AdapterVersion)
	if adapter == "" {
		adapter = "legacy-v1"
	}
	projectionSHA := strings.TrimSpace(batch.Import.ProjectionSHA256)
	if projectionSHA == "" {
		encoded, _ := json.Marshal(batch.Projections)
		projectionSHA = sha256String(encoded)
	}
	batch.Import.UpstreamContentSHA256 = upstream
	batch.Import.AdapterVersion = adapter
	batch.Import.ProjectionSHA256 = projectionSHA
	batch.Import.ContentSHA256 = sha256String([]byte(upstream + "\x00" + adapter + "\x00" + projectionSHA))
}

func activateFingerprintImportTx(tx *sql.Tx, sourceID, importID int64) error {
	if _, err := tx.Exec(`UPDATE fingerprint_imports SET is_active = 0 WHERE fingerprint_source_id = ? AND is_active = 1 AND id <> ?`, sourceID, importID); err != nil {
		return err
	}
	_, err := tx.Exec(`UPDATE fingerprint_imports SET is_active = 1 WHERE id = ? AND fingerprint_source_id = ?`, importID, sourceID)
	return err
}

func GetFingerprintImport(db *sql.DB, importID int64) (model.FingerprintImport, error) {
	fingerprintImport, err := scanFingerprintImport(db.QueryRow(fingerprintImportSelect+` WHERE id = ?`, importID))
	if errors.Is(err, sql.ErrNoRows) {
		return model.FingerprintImport{}, ErrFingerprintImportNotFound
	}
	return fingerprintImport, err
}

func ListActiveFingerprintImports(db *sql.DB) ([]model.FingerprintImport, error) {
	rows, err := db.Query(fingerprintImportSelect + ` WHERE is_active = 1 ORDER BY fingerprint_source_id, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	imports := make([]model.FingerprintImport, 0)
	for rows.Next() {
		fingerprintImport, err := scanFingerprintImport(rows)
		if err != nil {
			return nil, err
		}
		imports = append(imports, fingerprintImport)
	}
	return imports, rows.Err()
}

func ListFingerprintImports(db *sql.DB) ([]model.FingerprintImport, error) {
	rows, err := db.Query(fingerprintImportSelect + ` ORDER BY fingerprint_source_id, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	imports := make([]model.FingerprintImport, 0)
	for rows.Next() {
		fingerprintImport, err := scanFingerprintImport(rows)
		if err != nil {
			return nil, err
		}
		imports = append(imports, fingerprintImport)
	}
	return imports, rows.Err()
}

func ListFingerprintImportSummariesPage(db *sql.DB, page, pageSize int) ([]model.FingerprintImportSummary, int, error) {
	page, pageSize = normalizedFingerprintPage(page, pageSize)
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fingerprint_imports`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.Query(fingerprintImportSummarySelect+` ORDER BY fingerprint_source_id, id DESC LIMIT ? OFFSET ?`, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]model.FingerprintImportSummary, 0, pageSize)
	for rows.Next() {
		item, err := scanFingerprintImportSummary(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func ListFingerprintSourceRules(db *sql.DB, sourceKey string, limit int) ([]model.FingerprintSourceRule, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	page, err := ListFingerprintSourceRulesPage(db, FingerprintSourceRuleQuery{SourceKey: sourceKey, Page: 1, PageSize: limit})
	return page.Items, err
}

type FingerprintSourceRuleQuery struct {
	SourceKey string
	ImportID  int64
	RuleID    string
	Product   string
	Status    string
	Page      int
	PageSize  int
}

func ListFingerprintSourceRulesPage(db *sql.DB, query FingerprintSourceRuleQuery) (model.FingerprintSourceRulePage, error) {
	query.SourceKey = strings.TrimSpace(query.SourceKey)
	query.RuleID = strings.TrimSpace(query.RuleID)
	query.Product = strings.TrimSpace(query.Product)
	query.Status = strings.TrimSpace(query.Status)
	if query.SourceKey == "" {
		return model.FingerprintSourceRulePage{}, errors.New("fingerprint source key is required")
	}
	if query.Page <= 0 {
		query.Page = 1
	}
	if query.PageSize <= 0 || query.PageSize > 200 {
		query.PageSize = 50
	}
	where := []string{"s.source_key = ?"}
	args := []interface{}{query.SourceKey}
	if query.ImportID > 0 {
		where = append(where, "i.id = ?")
		args = append(args, query.ImportID)
	} else {
		where = append(where, "i.is_active = 1")
	}
	if query.RuleID != "" {
		where = append(where, "COALESCE(r.source_rule_id, '') LIKE ?")
		args = append(args, "%"+query.RuleID+"%")
	}
	if query.Product != "" {
		where = append(where, "COALESCE(product.canonical_name, '') LIKE ?")
		args = append(args, "%"+strings.ToLower(query.Product)+"%")
	}
	if query.Status != "" {
		where = append(where, "r.import_status = ?")
		args = append(args, query.Status)
	}
	fromWhere := `
		FROM fingerprint_source_rules r
		JOIN fingerprint_imports i ON i.id = r.fingerprint_import_id
		JOIN fingerprint_sources s ON s.id = i.fingerprint_source_id
		LEFT JOIN fingerprint_rules normalized ON normalized.fingerprint_source_rule_id = r.id
		LEFT JOIN fingerprint_products product ON product.id = normalized.fingerprint_product_id
		WHERE ` + strings.Join(where, " AND ")
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) `+fromWhere, args...).Scan(&total); err != nil {
		return model.FingerprintSourceRulePage{}, err
	}
	selectArgs := append(append([]interface{}{}, args...), query.PageSize, (query.Page-1)*query.PageSize)
	rows, err := db.Query(`
		SELECT r.id, r.fingerprint_import_id, COALESCE(r.source_rule_id, ''), r.source_path,
			r.content_sha256, r.raw_content, COALESCE(r.raw_structure, ''), r.import_status,
			COALESCE(r.import_error, ''), r.created_at, COALESCE(product.canonical_name, '')
		`+fromWhere+`
		ORDER BY r.id LIMIT ? OFFSET ?`, selectArgs...)
	if err != nil {
		return model.FingerprintSourceRulePage{}, err
	}
	defer rows.Close()
	rules := make([]model.FingerprintSourceRule, 0)
	for rows.Next() {
		var rule model.FingerprintSourceRule
		if err := rows.Scan(&rule.ID, &rule.FingerprintImportID, &rule.SourceRuleID, &rule.SourcePath, &rule.ContentSHA256, &rule.RawContent, &rule.RawStructure, &rule.ImportStatus, &rule.ImportError, &rule.CreatedAt, &rule.Product); err != nil {
			return model.FingerprintSourceRulePage{}, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return model.FingerprintSourceRulePage{}, err
	}
	return model.FingerprintSourceRulePage{Items: rules, Page: query.Page, PageSize: query.PageSize, Total: total}, nil
}

func ListFingerprintRunMatches(db *sql.DB, runID int64) ([]map[string]interface{}, error) {
	rows, err := db.Query(`
		SELECT m.id, m.ip, m.port, m.protocol, m.product_key, COALESCE(m.product_role, ''), COALESCE(m.exclusive_group, ''), COALESCE(m.source_product_name, ''), COALESCE(m.version, ''), COALESCE(m.cpe, ''), m.tags_json, m.is_soft,
			m.evidence_summary, m.created_at, r.id, r.fingerprint_import_id,
			COALESCE(r.source_rule_id, ''), r.source_path, r.content_sha256, r.import_status, source.source_key
		FROM asset_fingerprint_matches m
		JOIN fingerprint_source_rules r ON r.id = m.fingerprint_source_rule_id
		JOIN fingerprint_imports fingerprint_import ON fingerprint_import.id = r.fingerprint_import_id
		JOIN fingerprint_sources source ON source.id = fingerprint_import.fingerprint_source_id
		WHERE m.scan_task_run_id = ? ORDER BY m.id`, runID)
	if err != nil {
		return nil, err
	}
	matches := make([]map[string]interface{}, 0)
	byID := make(map[int64]map[string]interface{})
	for rows.Next() {
		var ip, protocol, product, productRole, exclusiveGroup, sourceProduct, version, cpe, tagsJSON, summary, created, sourceRuleID, path, sha, status, sourceKey string
		var port, soft int
		var matchID, ruleID, importID int64
		if err := rows.Scan(&matchID, &ip, &port, &protocol, &product, &productRole, &exclusiveGroup, &sourceProduct, &version, &cpe, &tagsJSON, &soft, &summary, &created, &ruleID, &importID, &sourceRuleID, &path, &sha, &status, &sourceKey); err != nil {
			rows.Close()
			return nil, err
		}
		var tags []string
		_ = json.Unmarshal([]byte(tagsJSON), &tags)
		value := map[string]interface{}{"id": matchID, "ip": ip, "port": port, "protocol": protocol, "product_key": product, "product_role": productRole, "exclusive_group": exclusiveGroup, "source_product": sourceProduct, "version": version, "cpe": cpe, "tags": tags, "soft_match": soft != 0, "evidence_summary": summary, "matcher_evidence": []map[string]interface{}{}, "created_at": created, "fingerprint_source_rule_id": ruleID, "fingerprint_import_id": importID, "source_key": sourceKey, "source_rule_id": sourceRuleID, "source_path": path, "content_sha256": sha, "import_status": status}
		matches = append(matches, value)
		byID[matchID] = value
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	evidenceRows, err := db.Query(`
		SELECT evidence.asset_fingerprint_match_id, evidence.fingerprint_matcher_id, evidence.evidence_type,
			COALESCE(evidence.target, ''), evidence.operator, evidence.observed_sha256,
			evidence.observed_length, evidence.truncated, evidence.summary
		FROM asset_fingerprint_match_evidence AS evidence
		JOIN asset_fingerprint_matches AS match ON match.id = evidence.asset_fingerprint_match_id
		WHERE match.scan_task_run_id = ?
		ORDER BY evidence.asset_fingerprint_match_id, evidence.fingerprint_matcher_id`, runID)
	if err != nil {
		return nil, err
	}
	defer evidenceRows.Close()
	for evidenceRows.Next() {
		var matchID, matcherID int64
		var evidenceType, target, operator, observedSHA, summary string
		var observedLength, truncated int
		if err := evidenceRows.Scan(&matchID, &matcherID, &evidenceType, &target, &operator, &observedSHA, &observedLength, &truncated, &summary); err != nil {
			return nil, err
		}
		if match := byID[matchID]; match != nil {
			values := match["matcher_evidence"].([]map[string]interface{})
			match["matcher_evidence"] = append(values, map[string]interface{}{"matcher_id": matcherID, "evidence_type": evidenceType, "target": target, "operator": operator, "observed_sha256": observedSHA, "observed_length": observedLength, "truncated": truncated != 0, "summary": summary})
		}
	}
	return matches, evidenceRows.Err()
}

func ListFingerprintRunConclusions(db *sql.DB, runID int64) ([]map[string]interface{}, error) {
	rows, err := db.Query(`SELECT ip, port, protocol, product_key, COALESCE(product_role, ''), COALESCE(exclusive_group, ''), COALESCE(version, ''), COALESCE(cpe, ''), tags_json, conclusion_status,
		product_status, product_source_count, version_status, version_source_count, cpe_status, cpe_source_count, created_at
		FROM asset_fingerprint_conclusions WHERE scan_task_run_id = ? ORDER BY ip, port, product_key`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		var ip, protocol, product, productRole, exclusiveGroup, version, cpe, tagsJSON, status, productStatus, versionStatus, cpeStatus, created string
		var port, productSources, versionSources, cpeSources int
		if err := rows.Scan(&ip, &port, &protocol, &product, &productRole, &exclusiveGroup, &version, &cpe, &tagsJSON, &status, &productStatus, &productSources, &versionStatus, &versionSources, &cpeStatus, &cpeSources, &created); err != nil {
			return nil, err
		}
		var tags []string
		_ = json.Unmarshal([]byte(tagsJSON), &tags)
		result = append(result, fingerprintConclusionMap(ip, port, protocol, product, productRole, exclusiveGroup, version, cpe, tags, status, productStatus, productSources, versionStatus, versionSources, cpeStatus, cpeSources, created))
	}
	return result, rows.Err()
}

func ListFingerprintRunMatchesPage(db *sql.DB, runID int64, page, pageSize int) ([]map[string]interface{}, int, error) {
	page, pageSize = normalizedFingerprintPage(page, pageSize)
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM asset_fingerprint_matches WHERE scan_task_run_id = ?`, runID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.Query(`
		SELECT m.id, m.ip, m.port, m.protocol, m.product_key, COALESCE(m.product_role, ''), COALESCE(m.exclusive_group, ''), COALESCE(m.source_product_name, ''), COALESCE(m.version, ''), COALESCE(m.cpe, ''), m.tags_json, m.is_soft,
			m.evidence_summary, m.created_at, r.id, r.fingerprint_import_id,
			COALESCE(r.source_rule_id, ''), r.source_path, r.content_sha256, r.import_status, source.source_key
		FROM asset_fingerprint_matches m
		JOIN fingerprint_source_rules r ON r.id = m.fingerprint_source_rule_id
		JOIN fingerprint_imports fingerprint_import ON fingerprint_import.id = r.fingerprint_import_id
		JOIN fingerprint_sources source ON source.id = fingerprint_import.fingerprint_source_id
		WHERE m.scan_task_run_id = ? ORDER BY m.id LIMIT ? OFFSET ?`, runID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	items := make([]map[string]interface{}, 0, pageSize)
	for rows.Next() {
		var ip, protocol, product, productRole, exclusiveGroup, sourceProduct, version, cpe, tagsJSON, summary, created, sourceRuleID, path, sha, status, sourceKey string
		var port, soft int
		var matchID, ruleID, importID int64
		if err := rows.Scan(&matchID, &ip, &port, &protocol, &product, &productRole, &exclusiveGroup, &sourceProduct, &version, &cpe, &tagsJSON, &soft, &summary, &created, &ruleID, &importID, &sourceRuleID, &path, &sha, &status, &sourceKey); err != nil {
			rows.Close()
			return nil, 0, err
		}
		var tags []string
		_ = json.Unmarshal([]byte(tagsJSON), &tags)
		items = append(items, map[string]interface{}{"id": matchID, "ip": ip, "port": port, "protocol": protocol, "product_key": product, "product_role": productRole, "exclusive_group": exclusiveGroup, "source_product": sourceProduct, "version": version, "cpe": cpe, "tags": tags, "soft_match": soft != 0, "evidence_summary": summary, "created_at": created, "fingerprint_source_rule_id": ruleID, "fingerprint_import_id": importID, "source_key": sourceKey, "source_rule_id": sourceRuleID, "source_path": path, "content_sha256": sha, "import_status": status})
	}
	return items, total, rows.Err()
}

func ListFingerprintRunEvidencePage(db *sql.DB, runID int64, page, pageSize int) ([]map[string]interface{}, int, error) {
	page, pageSize = normalizedFingerprintPage(page, pageSize)
	var total int
	if err := db.QueryRow(`
		SELECT COUNT(*)
		FROM asset_fingerprint_match_evidence AS evidence
		JOIN asset_fingerprint_matches AS match ON match.id = evidence.asset_fingerprint_match_id
		WHERE match.scan_task_run_id = ?`, runID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.Query(`
		SELECT evidence.asset_fingerprint_match_id, evidence.fingerprint_matcher_id, evidence.evidence_type,
			COALESCE(evidence.target, ''), evidence.operator, evidence.observed_sha256,
			evidence.observed_length, evidence.truncated, evidence.summary
		FROM asset_fingerprint_match_evidence AS evidence
		JOIN asset_fingerprint_matches AS match ON match.id = evidence.asset_fingerprint_match_id
		WHERE match.scan_task_run_id = ?
		ORDER BY evidence.asset_fingerprint_match_id, evidence.fingerprint_matcher_id
		LIMIT ? OFFSET ?`, runID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]map[string]interface{}, 0, pageSize)
	for rows.Next() {
		var matchID, matcherID int64
		var evidenceType, target, operator, sha, summary string
		var length, truncated int
		if err := rows.Scan(&matchID, &matcherID, &evidenceType, &target, &operator, &sha, &length, &truncated, &summary); err != nil {
			return nil, 0, err
		}
		items = append(items, map[string]interface{}{"match_id": matchID, "matcher_id": matcherID, "evidence_type": evidenceType, "target": target, "operator": operator, "observed_sha256": sha, "observed_length": length, "truncated": truncated != 0, "summary": summary})
	}
	return items, total, rows.Err()
}

func ListFingerprintRunConclusionsPage(db *sql.DB, runID int64, page, pageSize int) ([]map[string]interface{}, int, error) {
	page, pageSize = normalizedFingerprintPage(page, pageSize)
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM asset_fingerprint_conclusions WHERE scan_task_run_id = ?`, runID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.Query(`SELECT ip, port, protocol, product_key, COALESCE(product_role, ''), COALESCE(exclusive_group, ''), COALESCE(version, ''), COALESCE(cpe, ''), tags_json, conclusion_status,
		product_status, product_source_count, version_status, version_source_count, cpe_status, cpe_source_count, created_at
		FROM asset_fingerprint_conclusions WHERE scan_task_run_id = ? ORDER BY ip, port, protocol, product_key LIMIT ? OFFSET ?`, runID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]map[string]interface{}, 0, pageSize)
	for rows.Next() {
		var ip, protocol, product, productRole, exclusiveGroup, version, cpe, tagsJSON, status, productStatus, versionStatus, cpeStatus, created string
		var port, productSources, versionSources, cpeSources int
		if err := rows.Scan(&ip, &port, &protocol, &product, &productRole, &exclusiveGroup, &version, &cpe, &tagsJSON, &status, &productStatus, &productSources, &versionStatus, &versionSources, &cpeStatus, &cpeSources, &created); err != nil {
			return nil, 0, err
		}
		var tags []string
		_ = json.Unmarshal([]byte(tagsJSON), &tags)
		items = append(items, fingerprintConclusionMap(ip, port, protocol, product, productRole, exclusiveGroup, version, cpe, tags, status, productStatus, productSources, versionStatus, versionSources, cpeStatus, cpeSources, created))
	}
	return items, total, rows.Err()
}

func fingerprintConclusionMap(ip string, port int, protocol, product, productRole, exclusiveGroup, version, cpe string, tags []string, status, productStatus string, productSources int, versionStatus string, versionSources int, cpeStatus string, cpeSources int, created string) map[string]interface{} {
	return map[string]interface{}{
		"ip": ip, "port": port, "protocol": protocol, "product_key": product, "product_role": productRole, "exclusive_group": exclusiveGroup, "version": version, "cpe": cpe, "tags": tags,
		"conclusion_status": status, "product_status": productStatus, "product_source_count": productSources,
		"version_status": versionStatus, "version_source_count": versionSources,
		"cpe_status": cpeStatus, "cpe_source_count": cpeSources, "created_at": created,
	}
}

func ListFingerprintImportsForRunPage(db *sql.DB, runID int64, page, pageSize int) ([]model.FingerprintImportSummary, int, error) {
	page, pageSize = normalizedFingerprintPage(page, pageSize)
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM scan_task_run_fingerprint_imports WHERE scan_task_run_id = ?`, runID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.Query(fingerprintImportSummarySelect+`
		JOIN scan_task_run_fingerprint_imports run_import ON run_import.fingerprint_import_id = fingerprint_imports.id
		WHERE run_import.scan_task_run_id = ? ORDER BY fingerprint_imports.fingerprint_source_id, fingerprint_imports.id LIMIT ? OFFSET ?`, runID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]model.FingerprintImportSummary, 0, pageSize)
	for rows.Next() {
		item, err := scanFingerprintImportSummary(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func normalizedFingerprintPage(page, pageSize int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	return page, pageSize
}

func ImportTemplateMappingBatch(db *sql.DB, batch TemplateMappingBatch) (model.TemplateMappingImport, error) {
	batch.Import.Revision = strings.TrimSpace(batch.Import.Revision)
	batch.Import.ContentSHA256 = strings.TrimSpace(batch.Import.ContentSHA256)
	batch.Import.ManifestJSON = strings.TrimSpace(batch.Import.ManifestJSON)
	if batch.Import.Revision == "" || batch.Import.ContentSHA256 == "" || batch.Import.ManifestJSON == "" || len(batch.Mappings) == 0 {
		return model.TemplateMappingImport{}, errors.New("template mapping revision, SHA-256, manifest, and mappings are required")
	}
	tx, err := db.Begin()
	if err != nil {
		return model.TemplateMappingImport{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var id int64
	err = tx.QueryRow(`SELECT id FROM template_mapping_imports WHERE content_sha256 = ?`, batch.Import.ContentSHA256).Scan(&id)
	if err == nil {
		if err := tx.Commit(); err != nil {
			return model.TemplateMappingImport{}, err
		}
		return GetTemplateMappingImport(db, id)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return model.TemplateMappingImport{}, err
	}
	result, err := tx.Exec(`INSERT INTO template_mapping_imports (revision, content_sha256, manifest_json, is_active) VALUES (?, ?, ?, 0)`, batch.Import.Revision, batch.Import.ContentSHA256, batch.Import.ManifestJSON)
	if err != nil {
		return model.TemplateMappingImport{}, err
	}
	id, err = result.LastInsertId()
	if err != nil {
		return model.TemplateMappingImport{}, err
	}
	for _, mapping := range batch.Mappings {
		if strings.TrimSpace(mapping.ProductKey) == "" || strings.TrimSpace(mapping.TemplateID) == "" || strings.TrimSpace(mapping.TemplatePath) == "" || strings.TrimSpace(mapping.TemplateSHA256) == "" || strings.TrimSpace(mapping.TemplateSetRevision) == "" || mapping.SideEffect != "read_only" || mapping.ReviewStatus != "approved" {
			return model.TemplateMappingImport{}, errors.New("template mappings require product, pinned template, read_only effect, and approved review")
		}
		if strings.TrimSpace(mapping.SourceRuleID) != "" && strings.TrimSpace(mapping.SourceKey) == "" {
			return model.TemplateMappingImport{}, errors.New("rule-specific template mapping requires source_key")
		}
		if _, err := tx.Exec(`INSERT INTO fingerprint_template_mappings (template_mapping_import_id, product_key, source_key, source_rule_id, template_id, template_path, template_sha256, template_set_revision, side_effect, review_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, mapping.ProductKey, nullIfEmpty(mapping.SourceKey), nullIfEmpty(mapping.SourceRuleID), mapping.TemplateID, mapping.TemplatePath, mapping.TemplateSHA256, mapping.TemplateSetRevision, mapping.SideEffect, mapping.ReviewStatus); err != nil {
			return model.TemplateMappingImport{}, err
		}
	}
	if _, err := tx.Exec(`UPDATE template_mapping_imports SET is_active = 0 WHERE is_active = 1`); err != nil {
		return model.TemplateMappingImport{}, err
	}
	if _, err := tx.Exec(`UPDATE template_mapping_imports SET is_active = 1 WHERE id = ?`, id); err != nil {
		return model.TemplateMappingImport{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.TemplateMappingImport{}, err
	}
	return GetTemplateMappingImport(db, id)
}

func GetTemplateMappingImport(db *sql.DB, id int64) (model.TemplateMappingImport, error) {
	var value model.TemplateMappingImport
	var active int
	err := db.QueryRow(`SELECT id, revision, content_sha256, manifest_json, is_active, created_at FROM template_mapping_imports WHERE id = ?`, id).Scan(&value.ID, &value.Revision, &value.ContentSHA256, &value.ManifestJSON, &active, &value.CreatedAt)
	value.IsActive = active != 0
	return value, err
}

func ListFingerprintTemplateMappings(db *sql.DB) ([]model.FingerprintTemplateMapping, error) {
	rows, err := db.Query(`SELECT id, template_mapping_import_id, product_key, COALESCE(source_key, ''), COALESCE(source_rule_id, ''), template_id, template_path, template_sha256, template_set_revision, side_effect, review_status, enabled, created_at, COALESCE(disabled_at, '') FROM fingerprint_template_mappings ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]model.FingerprintTemplateMapping, 0)
	for rows.Next() {
		var m model.FingerprintTemplateMapping
		var enabled int
		if err := rows.Scan(&m.ID, &m.TemplateMappingImportID, &m.ProductKey, &m.SourceKey, &m.SourceRuleID, &m.TemplateID, &m.TemplatePath, &m.TemplateSHA256, &m.TemplateSetRevision, &m.SideEffect, &m.ReviewStatus, &enabled, &m.CreatedAt, &m.DisabledAt); err != nil {
			return nil, err
		}
		m.Enabled = enabled != 0
		result = append(result, m)
	}
	return result, rows.Err()
}

func DisableFingerprintTemplateMapping(db *sql.DB, id int64) error {
	result, err := db.Exec(`UPDATE fingerprint_template_mappings SET enabled = 0, disabled_at = datetime('now') WHERE id = ? AND enabled = 1`, id)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListApprovedTemplateMappingsForRun returns only active reviewed mappings
// justified by conclusions from this immutable run and endpoint.
func ListApprovedTemplateMappingsForRun(db *sql.DB, runID int64, ip string, port int, protocol string) ([]model.FingerprintTemplateMapping, error) {
	rows, err := db.Query(`
		SELECT DISTINCT m.id, m.template_mapping_import_id, m.product_key, COALESCE(m.source_key, ''), COALESCE(m.source_rule_id, ''),
			m.template_id, m.template_path, m.template_sha256, m.template_set_revision, m.side_effect,
			m.review_status, m.enabled, m.created_at, COALESCE(m.disabled_at, '')
		FROM fingerprint_template_mappings m
		JOIN template_mapping_imports mi ON mi.id = m.template_mapping_import_id AND mi.is_active = 1
		JOIN asset_fingerprint_conclusions c ON c.scan_task_run_id = ? AND c.ip = ? AND c.port = ? AND c.protocol = ? AND c.product_key = m.product_key
		WHERE m.enabled = 1 AND m.review_status = 'approved' AND m.side_effect = 'read_only'
		  AND (m.source_rule_id IS NULL OR m.source_rule_id = '' OR EXISTS (
			SELECT 1 FROM asset_fingerprint_matches am JOIN fingerprint_source_rules sr ON sr.id = am.fingerprint_source_rule_id JOIN fingerprint_imports fi ON fi.id = sr.fingerprint_import_id JOIN fingerprint_sources fs ON fs.id = fi.fingerprint_source_id
			WHERE am.scan_task_run_id = c.scan_task_run_id AND am.ip = c.ip AND am.port = c.port AND am.protocol = c.protocol AND sr.source_rule_id = m.source_rule_id AND fs.source_key = m.source_key))
		ORDER BY m.id`, runID, ip, port, protocol)
	if isMissingTemplateMappingTable(err) {
		return []model.FingerprintTemplateMapping{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]model.FingerprintTemplateMapping, 0)
	for rows.Next() {
		var m model.FingerprintTemplateMapping
		var enabled int
		if err := rows.Scan(&m.ID, &m.TemplateMappingImportID, &m.ProductKey, &m.SourceKey, &m.SourceRuleID, &m.TemplateID, &m.TemplatePath, &m.TemplateSHA256, &m.TemplateSetRevision, &m.SideEffect, &m.ReviewStatus, &enabled, &m.CreatedAt, &m.DisabledAt); err != nil {
			return nil, err
		}
		m.Enabled = enabled != 0
		result = append(result, m)
	}
	return result, rows.Err()
}

// ListApprovedTemplateMappingsForMatches selects reviewed mappings from the
// current run's in-memory hard matches, before the atomic snapshot commit.
func ListApprovedTemplateMappingsForMatches(db *sql.DB, runID int64, ip string, port int, protocol string, matches []model.FingerprintRunMatch) ([]model.FingerprintTemplateMapping, error) {
	if runID <= 0 || net.ParseIP(strings.TrimSpace(ip)) == nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid fingerprint mapping endpoint")
	}
	candidates := make([]model.FingerprintRunMatch, 0)
	for _, match := range matches {
		if !match.Soft && match.IP == ip && match.Port == port && match.Protocol == protocol {
			candidates = append(candidates, match)
		}
	}
	if len(candidates) == 0 {
		return []model.FingerprintTemplateMapping{}, nil
	}
	frozen := make(map[int64]struct{})
	rows, err := db.Query(`SELECT fingerprint_import_id FROM scan_task_run_fingerprint_imports WHERE scan_task_run_id = ?`, runID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var importID int64
		if err := rows.Scan(&importID); err != nil {
			rows.Close()
			return nil, err
		}
		frozen[importID] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	eligible := make([]model.FingerprintRunMatch, 0)
	for _, match := range candidates {
		if _, ok := frozen[match.FingerprintImportID]; !ok {
			continue
		}
		eligible = append(eligible, match)
	}
	if len(eligible) == 0 {
		return []model.FingerprintTemplateMapping{}, nil
	}

	rows, err = db.Query(`
		SELECT m.id, m.template_mapping_import_id, m.product_key, COALESCE(m.source_key, ''), COALESCE(m.source_rule_id, ''),
			m.template_id, m.template_path, m.template_sha256, m.template_set_revision, m.side_effect,
			m.review_status, m.enabled, m.created_at, COALESCE(m.disabled_at, '')
		FROM fingerprint_template_mappings AS m
		JOIN template_mapping_imports AS mapping_import ON mapping_import.id = m.template_mapping_import_id AND mapping_import.is_active = 1
		WHERE m.enabled = 1 AND m.review_status = 'approved' AND m.side_effect = 'read_only'
		ORDER BY m.id`)
	if isMissingTemplateMappingTable(err) {
		return []model.FingerprintTemplateMapping{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]model.FingerprintTemplateMapping, 0)
	for rows.Next() {
		var mapping model.FingerprintTemplateMapping
		var enabled int
		if err := rows.Scan(&mapping.ID, &mapping.TemplateMappingImportID, &mapping.ProductKey, &mapping.SourceKey, &mapping.SourceRuleID, &mapping.TemplateID, &mapping.TemplatePath, &mapping.TemplateSHA256, &mapping.TemplateSetRevision, &mapping.SideEffect, &mapping.ReviewStatus, &enabled, &mapping.CreatedAt, &mapping.DisabledAt); err != nil {
			return nil, err
		}
		mapping.Enabled = enabled != 0
		for _, match := range eligible {
			if !strings.EqualFold(mapping.ProductKey, match.Product) {
				continue
			}
			if mapping.SourceRuleID != "" && (mapping.SourceKey != match.SourceKey || mapping.SourceRuleID != match.SourceRuleID) {
				continue
			}
			result = append(result, mapping)
			break
		}
	}
	return result, rows.Err()
}

func isMissingTemplateMappingTable(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table") &&
		(strings.Contains(strings.ToLower(err.Error()), "fingerprint_template_mappings") || strings.Contains(strings.ToLower(err.Error()), "template_mapping_imports"))
}

func CreateFingerprintSourceRule(db *sql.DB, rule model.FingerprintSourceRule) (model.FingerprintSourceRule, error) {
	if rule.FingerprintImportID <= 0 {
		return model.FingerprintSourceRule{}, errors.New("fingerprint import ID is required")
	}
	rule.SourcePath = strings.TrimSpace(rule.SourcePath)
	rule.ContentSHA256 = strings.TrimSpace(rule.ContentSHA256)
	rule.ImportStatus = strings.TrimSpace(rule.ImportStatus)
	if rule.SourcePath == "" || rule.ContentSHA256 == "" || rule.RawContent == "" {
		return model.FingerprintSourceRule{}, errors.New("fingerprint source rule path, content SHA-256, and raw content are required")
	}
	switch rule.ImportStatus {
	case "executable", "unsupported", "import_error":
	default:
		return model.FingerprintSourceRule{}, fmt.Errorf("invalid fingerprint source rule import status: %s", rule.ImportStatus)
	}
	result, err := db.Exec(`
		INSERT INTO fingerprint_source_rules
			(fingerprint_import_id, source_rule_id, source_path, content_sha256, raw_content, raw_structure, import_status, import_error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.FingerprintImportID, strings.TrimSpace(rule.SourceRuleID), rule.SourcePath, rule.ContentSHA256,
		rule.RawContent, rule.RawStructure, rule.ImportStatus, strings.TrimSpace(rule.ImportError),
	)
	if err != nil {
		return model.FingerprintSourceRule{}, err
	}
	rule.ID, err = result.LastInsertId()
	if err != nil {
		return model.FingerprintSourceRule{}, err
	}
	return GetFingerprintSourceRule(db, rule.ID)
}

func GetFingerprintSourceRule(db *sql.DB, ruleID int64) (model.FingerprintSourceRule, error) {
	var rule model.FingerprintSourceRule
	err := db.QueryRow(`
		SELECT id, fingerprint_import_id, COALESCE(source_rule_id, ''), source_path, content_sha256,
			raw_content, COALESCE(raw_structure, ''), import_status, COALESCE(import_error, ''), created_at
		FROM fingerprint_source_rules WHERE id = ?`, ruleID).Scan(
		&rule.ID, &rule.FingerprintImportID, &rule.SourceRuleID, &rule.SourcePath, &rule.ContentSHA256,
		&rule.RawContent, &rule.RawStructure, &rule.ImportStatus, &rule.ImportError, &rule.CreatedAt,
	)
	return rule, err
}

// AssociateFingerprintImportWithRun persists the exact import revision used by
// a run. It is idempotent to allow T255's atomic freeze operation to retry.
func AssociateFingerprintImportWithRun(db *sql.DB, runID, importID int64) error {
	if runID <= 0 || importID <= 0 {
		return errors.New("scan task run ID and fingerprint import ID are required")
	}
	_, err := db.Exec(`
		INSERT INTO scan_task_run_fingerprint_imports (scan_task_run_id, fingerprint_import_id)
		VALUES (?, ?) ON CONFLICT(scan_task_run_id, fingerprint_import_id) DO NOTHING`, runID, importID)
	return err
}

func ListFingerprintImportsForRun(db *sql.DB, runID int64) ([]model.FingerprintImport, error) {
	rows, err := db.Query(fingerprintImportSelect+`
		JOIN scan_task_run_fingerprint_imports AS run_import ON run_import.fingerprint_import_id = fingerprint_imports.id
		WHERE run_import.scan_task_run_id = ?
		ORDER BY fingerprint_imports.fingerprint_source_id, fingerprint_imports.id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	imports := make([]model.FingerprintImport, 0)
	for rows.Next() {
		fingerprintImport, err := scanFingerprintImport(rows)
		if err != nil {
			return nil, err
		}
		imports = append(imports, fingerprintImport)
	}
	return imports, rows.Err()
}

// FingerprintRunMatch is a single rule match generated from evidence gathered
// during one immutable ScanTaskRun. EvidenceSummary must already be redacted.
type FingerprintRunMatch = model.FingerprintRunMatch

// SaveFingerprintRunMatches persists every raw source-rule match, then derives
// product conclusions without collapsing conflicting candidates.
func SaveFingerprintRunMatches(db *sql.DB, runID int64, matches []FingerprintRunMatch) error {
	if runID <= 0 {
		return errors.New("scan task run ID is required")
	}
	if len(matches) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := saveFingerprintRunMatchesTx(tx, runID, matches); err != nil {
		return err
	}
	return tx.Commit()
}

type fingerprintProductConclusion struct {
	role           string
	exclusiveGroup string
	sourceImports  map[int64]struct{}
	versions       map[string]map[int64]struct{}
	cpes           map[string]map[int64]struct{}
	tags           map[string]struct{}
}

func saveFingerprintRunMatchesTx(tx *sql.Tx, runID int64, matches []model.FingerprintRunMatch) error {
	if runID <= 0 {
		return errors.New("scan task run ID is required")
	}
	conclusions := make(map[string]map[string]*fingerprintProductConclusion)
	for _, match := range matches {
		match.IP = strings.TrimSpace(match.IP)
		match.Protocol = strings.TrimSpace(match.Protocol)
		match.Product = strings.ToLower(strings.TrimSpace(match.Product))
		match.ProductRole = strings.TrimSpace(match.ProductRole)
		match.ExclusiveGroup = strings.TrimSpace(match.ExclusiveGroup)
		match.Version = strings.TrimSpace(match.Version)
		match.CPE = strings.TrimSpace(match.CPE)
		match.Tags = normalizedStringSet(match.Tags)
		if match.ProductRole == "" {
			match.ProductRole, match.ExclusiveGroup = model.FingerprintProductClassification(match.Product, match.Tags)
		}
		match.EvidenceSummary = strings.TrimSpace(match.EvidenceSummary)
		if match.FingerprintImportID <= 0 || match.FingerprintSourceRuleID <= 0 || net.ParseIP(match.IP) == nil || match.Port < 1 || match.Port > 65535 || match.Protocol == "" || match.Product == "" || match.EvidenceSummary == "" || len(match.Evidence) == 0 {
			return errors.New("invalid fingerprint run match")
		}
		var frozen int
		if err := tx.QueryRow(`SELECT 1 FROM scan_task_run_fingerprint_imports WHERE scan_task_run_id = ? AND fingerprint_import_id = ?`, runID, match.FingerprintImportID).Scan(&frozen); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("fingerprint import %d is not frozen for run %d", match.FingerprintImportID, runID)
			}
			return err
		}
		var ruleImportID int64
		if err := tx.QueryRow(`SELECT fingerprint_import_id FROM fingerprint_source_rules WHERE id = ?`, match.FingerprintSourceRuleID).Scan(&ruleImportID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("fingerprint source rule %d not found", match.FingerprintSourceRuleID)
			}
			return err
		}
		if ruleImportID != match.FingerprintImportID {
			return fmt.Errorf("fingerprint source rule %d does not belong to import %d", match.FingerprintSourceRuleID, match.FingerprintImportID)
		}
		tagsJSON, err := json.Marshal(match.Tags)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`
			INSERT INTO asset_fingerprint_matches
				(scan_task_run_id, fingerprint_import_id, fingerprint_source_rule_id, ip, port, protocol, product_key, product_role, exclusive_group, source_product_name, version, cpe, tags_json, is_soft, evidence_summary)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(scan_task_run_id, ip, port, fingerprint_source_rule_id, evidence_summary) DO NOTHING`,
			runID, match.FingerprintImportID, match.FingerprintSourceRuleID, match.IP, match.Port, match.Protocol,
			match.Product, match.ProductRole, match.ExclusiveGroup, strings.TrimSpace(match.SourceProduct), nullIfEmpty(match.Version), nullIfEmpty(match.CPE), string(tagsJSON), boolToInt(match.Soft), match.EvidenceSummary,
		); err != nil {
			return err
		}
		var assetMatchID int64
		if err := tx.QueryRow(`
			SELECT id FROM asset_fingerprint_matches
			WHERE scan_task_run_id = ? AND ip = ? AND port = ? AND fingerprint_source_rule_id = ? AND evidence_summary = ?`,
			runID, match.IP, match.Port, match.FingerprintSourceRuleID, match.EvidenceSummary).Scan(&assetMatchID); err != nil {
			return err
		}
		for _, evidence := range match.Evidence {
			evidence.EvidenceType = strings.TrimSpace(evidence.EvidenceType)
			evidence.Target = strings.TrimSpace(evidence.Target)
			evidence.Operator = strings.TrimSpace(evidence.Operator)
			evidence.ObservedSHA256 = strings.ToLower(strings.TrimSpace(evidence.ObservedSHA256))
			evidence.Summary = strings.TrimSpace(evidence.Summary)
			if evidence.MatcherID <= 0 || evidence.EvidenceType == "" || evidence.Operator == "" || len(evidence.ObservedSHA256) != sha256.Size*2 || evidence.ObservedLength < 0 || evidence.Summary == "" {
				return errors.New("invalid fingerprint matcher evidence")
			}
			if _, err := hex.DecodeString(evidence.ObservedSHA256); err != nil {
				return errors.New("invalid fingerprint matcher evidence SHA-256")
			}
			var matcherRuleID int64
			if err := tx.QueryRow(`
				SELECT rule.fingerprint_source_rule_id
				FROM fingerprint_matchers AS matcher
				JOIN fingerprint_match_groups AS match_group ON match_group.id = matcher.fingerprint_match_group_id
				JOIN fingerprint_rules AS rule ON rule.id = match_group.fingerprint_rule_id
				WHERE matcher.id = ?`, evidence.MatcherID).Scan(&matcherRuleID); err != nil {
				return err
			}
			if matcherRuleID != match.FingerprintSourceRuleID {
				return fmt.Errorf("fingerprint matcher %d does not belong to source rule %d", evidence.MatcherID, match.FingerprintSourceRuleID)
			}
			if _, err := tx.Exec(`
				INSERT INTO asset_fingerprint_match_evidence
					(asset_fingerprint_match_id, fingerprint_matcher_id, evidence_type, target, operator, observed_sha256, observed_length, truncated, summary)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(asset_fingerprint_match_id, fingerprint_matcher_id) DO UPDATE SET
					evidence_type = excluded.evidence_type, target = excluded.target, operator = excluded.operator,
					observed_sha256 = excluded.observed_sha256, observed_length = excluded.observed_length,
					truncated = excluded.truncated, summary = excluded.summary`,
				assetMatchID, evidence.MatcherID, evidence.EvidenceType, nullIfEmpty(evidence.Target), evidence.Operator,
				evidence.ObservedSHA256, evidence.ObservedLength, boolToInt(evidence.Truncated), evidence.Summary); err != nil {
				return err
			}
		}
		if match.Soft {
			continue
		}
		endpointKey := fmt.Sprintf("%s\x00%d\x00%s", match.IP, match.Port, match.Protocol)
		if conclusions[endpointKey] == nil {
			conclusions[endpointKey] = map[string]*fingerprintProductConclusion{}
		}
		if conclusions[endpointKey][match.Product] == nil {
			conclusions[endpointKey][match.Product] = &fingerprintProductConclusion{
				role: match.ProductRole, exclusiveGroup: match.ExclusiveGroup,
				sourceImports: map[int64]struct{}{}, versions: map[string]map[int64]struct{}{}, cpes: map[string]map[int64]struct{}{}, tags: map[string]struct{}{},
			}
		}
		conclusion := conclusions[endpointKey][match.Product]
		conclusion.sourceImports[match.FingerprintImportID] = struct{}{}
		if match.Version != "" {
			if conclusion.versions[match.Version] == nil {
				conclusion.versions[match.Version] = map[int64]struct{}{}
			}
			conclusion.versions[match.Version][match.FingerprintImportID] = struct{}{}
		}
		if match.CPE != "" {
			if conclusion.cpes[match.CPE] == nil {
				conclusion.cpes[match.CPE] = map[int64]struct{}{}
			}
			conclusion.cpes[match.CPE][match.FingerprintImportID] = struct{}{}
		}
		for _, tag := range match.Tags {
			conclusion.tags[tag] = struct{}{}
		}
	}
	for endpointKey, products := range conclusions {
		parts := strings.Split(endpointKey, "\x00")
		port, _ := strconv.Atoi(parts[1])
		for product, conclusion := range products {
			productStatus := "matched"
			if fingerprintProductConflicted(product, conclusion, products) {
				productStatus = "conflicted"
			} else if len(conclusion.sourceImports) > 1 {
				productStatus = "corroborated"
			}
			version, versionStatus, versionSources := metadataConclusion(conclusion.versions)
			cpe, cpeStatus, cpeSources := metadataConclusion(conclusion.cpes)
			tags := make([]string, 0, len(conclusion.tags))
			for tag := range conclusion.tags {
				tags = append(tags, tag)
			}
			sort.Strings(tags)
			tagsJSON, err := json.Marshal(tags)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(`
				INSERT INTO asset_fingerprint_conclusions
					(scan_task_run_id, ip, port, protocol, product_key, product_role, exclusive_group, version, cpe, tags_json, conclusion_status,
					 product_status, product_source_count, version_status, version_source_count, cpe_status, cpe_source_count)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(scan_task_run_id, ip, port, protocol, product_key) DO UPDATE SET
					product_role = excluded.product_role, exclusive_group = excluded.exclusive_group,
					version = excluded.version, cpe = excluded.cpe, tags_json = excluded.tags_json, conclusion_status = excluded.conclusion_status,
					product_status = excluded.product_status, product_source_count = excluded.product_source_count,
					version_status = excluded.version_status, version_source_count = excluded.version_source_count,
					cpe_status = excluded.cpe_status, cpe_source_count = excluded.cpe_source_count`,
				runID, parts[0], port, parts[2], product, conclusion.role, conclusion.exclusiveGroup, nullIfEmpty(version), nullIfEmpty(cpe), string(tagsJSON), productStatus,
				productStatus, len(conclusion.sourceImports), versionStatus, versionSources, cpeStatus, cpeSources,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

func fingerprintProductConflicted(product string, conclusion *fingerprintProductConclusion, products map[string]*fingerprintProductConclusion) bool {
	if conclusion == nil || conclusion.exclusiveGroup == "" {
		return false
	}
	for otherProduct, other := range products {
		if otherProduct != product && other != nil && other.exclusiveGroup == conclusion.exclusiveGroup {
			return true
		}
	}
	return false
}

func metadataConclusion(values map[string]map[int64]struct{}) (string, string, int) {
	if len(values) == 0 {
		return "", "unobserved", 0
	}
	if len(values) > 1 {
		sources := make(map[int64]struct{})
		for _, valueSources := range values {
			for importID := range valueSources {
				sources[importID] = struct{}{}
			}
		}
		return "", "conflicted", len(sources)
	}
	for value, sources := range values {
		if len(sources) > 1 {
			return value, "corroborated", len(sources)
		}
		return value, "matched", len(sources)
	}
	return "", "unobserved", 0
}

func normalizedStringSet(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// FreezeActiveFingerprintImportsTx records the complete active import set as
// part of the same transaction that creates or claims a run.
func FreezeActiveFingerprintImportsTx(tx *sql.Tx, runID int64) error {
	if runID <= 0 {
		return errors.New("scan task run ID is required")
	}
	_, err := tx.Exec(`
		INSERT INTO scan_task_run_fingerprint_imports (scan_task_run_id, fingerprint_import_id)
		SELECT ?, id FROM fingerprint_imports WHERE is_active = 1
		ON CONFLICT(scan_task_run_id, fingerprint_import_id) DO NOTHING`, runID)
	if isMissingFingerprintCatalogTable(err) {
		return nil
	}
	return err
}

func isMissingFingerprintCatalogTable(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no such table") &&
		(strings.Contains(strings.ToLower(err.Error()), "fingerprint_import") || strings.Contains(strings.ToLower(err.Error()), "scan_task_run_fingerprint_imports"))
}

func validateFingerprintImportBatch(batch FingerprintImportBatch) error {
	batch.Source.SourceKey = strings.TrimSpace(batch.Source.SourceKey)
	batch.Source.RepositoryURL = strings.TrimSpace(batch.Source.RepositoryURL)
	batch.Source.Status = strings.TrimSpace(batch.Source.Status)
	batch.Import.Commit = strings.TrimSpace(batch.Import.Commit)
	batch.Import.ContentSHA256 = strings.TrimSpace(batch.Import.ContentSHA256)
	batch.Import.ManifestJSON = strings.TrimSpace(batch.Import.ManifestJSON)
	if batch.Source.SourceKey == "" || batch.Source.RepositoryURL == "" || batch.Import.Commit == "" || batch.Import.ContentSHA256 == "" || batch.Import.ManifestJSON == "" {
		return errors.New("fingerprint batch source identity, commit, content SHA-256, and manifest are required")
	}
	if batch.Source.Status == "" {
		batch.Source.Status = "enabled"
	}
	if batch.Import.RuleTotal != len(batch.Rules) || batch.Import.RuleTotal < 0 {
		return errors.New("fingerprint batch rule total does not match raw rules")
	}
	executable, unsupported, importErrors := 0, 0, 0
	for index, rule := range batch.Rules {
		if strings.TrimSpace(rule.SourcePath) == "" || strings.TrimSpace(rule.ContentSHA256) == "" || rule.RawContent == "" {
			return fmt.Errorf("fingerprint batch rule %d is incomplete", index)
		}
		switch rule.ImportStatus {
		case "executable":
			executable++
		case "unsupported":
			unsupported++
		case "import_error":
			importErrors++
		default:
			return fmt.Errorf("fingerprint batch rule %d has invalid status %q", index, rule.ImportStatus)
		}
	}
	if executable != batch.Import.ExecutableTotal || unsupported != batch.Import.UnsupportedTotal || importErrors != batch.Import.ImportErrorTotal {
		return fmt.Errorf("fingerprint batch status totals do not match raw rules: got executable=%d unsupported=%d import_error=%d", executable, unsupported, importErrors)
	}
	if len(batch.Projections) != executable {
		return fmt.Errorf("fingerprint executable projection total mismatch: got %d want %d", len(batch.Projections), executable)
	}
	seenProjections := make(map[string]struct{}, len(batch.Projections))
	for index, projection := range batch.Projections {
		key := strings.TrimSpace(projection.SourcePath) + "\x00" + strings.TrimSpace(projection.ContentSHA256)
		if strings.TrimSpace(projection.SourcePath) == "" || strings.TrimSpace(projection.ContentSHA256) == "" || strings.TrimSpace(projection.Product.CanonicalName) == "" || strings.TrimSpace(projection.Protocol) == "" {
			return fmt.Errorf("fingerprint projection %d is incomplete", index)
		}
		if _, exists := seenProjections[key]; exists {
			return fmt.Errorf("duplicate fingerprint projection for %s", projection.SourcePath)
		}
		seenProjections[key] = struct{}{}
	}
	return nil
}

func verifyFingerprintRuleProjections(tx *sql.Tx, importID int64, expected int) error {
	var existing int
	if err := tx.QueryRow(`
		SELECT COUNT(*) FROM fingerprint_rules AS rule
		JOIN fingerprint_source_rules AS source_rule ON source_rule.id = rule.fingerprint_source_rule_id
		WHERE source_rule.fingerprint_import_id = ?`, importID).Scan(&existing); err != nil {
		return err
	}
	if existing == expected {
		return nil
	}
	return fmt.Errorf("immutable fingerprint projection revision %d has %d rules, want %d", importID, existing, expected)
}

func persistFingerprintRuleProjections(tx *sql.Tx, importID int64, projections []model.FingerprintRuleProjection) error {
	if err := verifyFingerprintRuleProjections(tx, importID, 0); err != nil {
		return err
	}
	for _, projection := range projections {
		var sourceRuleID int64
		if err := tx.QueryRow(`
			SELECT id FROM fingerprint_source_rules
			WHERE fingerprint_import_id = ? AND source_path = ? AND content_sha256 = ?`,
			importID, projection.SourcePath, projection.ContentSHA256).Scan(&sourceRuleID); err != nil {
			return fmt.Errorf("resolve projected source rule %s: %w", projection.SourcePath, err)
		}
		canonicalName := strings.ToLower(strings.TrimSpace(projection.Product.CanonicalName))
		productRole := strings.TrimSpace(projection.Product.Role)
		exclusiveGroup := strings.TrimSpace(projection.Product.ExclusiveGroup)
		if productRole == "" {
			productRole, exclusiveGroup = model.FingerprintProductClassification(canonicalName, projection.Tags)
		}
		aliasesJSON := strings.TrimSpace(projection.Product.AliasesJSON)
		if aliasesJSON == "" {
			aliasesJSON = "[]"
		}
		if _, err := tx.Exec(`
			INSERT INTO fingerprint_products (canonical_name, vendor, aliases_json, cpe, product_role, exclusive_group)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(canonical_name) DO UPDATE SET
				vendor = CASE WHEN COALESCE(fingerprint_products.vendor, '') = '' THEN excluded.vendor ELSE fingerprint_products.vendor END,
				aliases_json = CASE WHEN COALESCE(fingerprint_products.aliases_json, '') IN ('', '[]') THEN excluded.aliases_json ELSE fingerprint_products.aliases_json END,
				cpe = CASE WHEN COALESCE(fingerprint_products.cpe, '') = '' THEN excluded.cpe ELSE fingerprint_products.cpe END,
				product_role = excluded.product_role, exclusive_group = excluded.exclusive_group`,
			canonicalName, nullIfEmpty(projection.Product.Vendor), aliasesJSON, nullIfEmpty(projection.Product.CPE), productRole, exclusiveGroup); err != nil {
			return err
		}
		var productID int64
		if err := tx.QueryRow(`SELECT id FROM fingerprint_products WHERE canonical_name = ?`, canonicalName).Scan(&productID); err != nil {
			return err
		}
		tagsJSON, err := json.Marshal(projection.Tags)
		if err != nil {
			return err
		}
		result, err := tx.Exec(`
			INSERT INTO fingerprint_rules
				(fingerprint_source_rule_id, fingerprint_product_id, source_product_name, protocol, soft_match, version_template, cpe, tags_json, product_role, exclusive_group, status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'executable')`,
			sourceRuleID, productID, strings.TrimSpace(projection.SourceProduct), strings.ToLower(strings.TrimSpace(projection.Protocol)), boolToInt(projection.SoftMatch),
			nullIfEmpty(projection.VersionTemplate), nullIfEmpty(projection.CPE), string(tagsJSON), productRole, exclusiveGroup)
		if err != nil {
			return err
		}
		ruleID, err := result.LastInsertId()
		if err != nil {
			return err
		}
		if err := persistFingerprintMatchGroup(tx, ruleID, nil, 0, projection.Root); err != nil {
			return err
		}
	}
	return nil
}

func persistFingerprintMatchGroup(tx *sql.Tx, ruleID int64, parentID *int64, position int, group model.FingerprintMatchGroupProjection) error {
	result, err := tx.Exec(`
		INSERT INTO fingerprint_match_groups (fingerprint_rule_id, parent_id, operator, position)
		VALUES (?, ?, ?, ?)`, ruleID, parentID, group.Operator, position)
	if err != nil {
		return err
	}
	groupID, err := result.LastInsertId()
	if err != nil {
		return err
	}
	for position, matcher := range group.Matchers {
		if _, err := tx.Exec(`
			INSERT INTO fingerprint_matchers
				(fingerprint_match_group_id, evidence_type, target, operator, value, version_capture, position)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			groupID, matcher.EvidenceType, nullIfEmpty(matcher.Target), matcher.Operator, matcher.Value, nullIfEmpty(matcher.VersionCapture), position); err != nil {
			return err
		}
	}
	for position, child := range group.Children {
		if err := persistFingerprintMatchGroup(tx, ruleID, &groupID, position, child); err != nil {
			return err
		}
	}
	return nil
}

// MigrateLegacyBannerFingerprintRules preserves every v1 banner row while
// activating an immutable execution revision that excludes state/fallback
// rows. Older imports remain available to runs that already froze them.
func MigrateLegacyBannerFingerprintRules(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT id, service_name, banner_pattern, COALESCE(match_type, 'contains'),
			COALESCE(protocol, ''), COALESCE(port, 0), COALESCE(description, '')
		FROM banner ORDER BY id ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	legacyRules := make([]legacyBannerRule, 0)
	for rows.Next() {
		var rule legacyBannerRule
		if err := rows.Scan(&rule.ID, &rule.ServiceName, &rule.BannerPattern, &rule.MatchType, &rule.Protocol, &rule.Port, &rule.Description); err != nil {
			return err
		}
		legacyRules = append(legacyRules, rule)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(legacyRules) == 0 {
		return nil
	}

	encodedRules, err := json.Marshal(legacyRules)
	if err != nil {
		return fmt.Errorf("encode legacy banner revision: %w", err)
	}
	contentSHA := sha256String(encodedRules)
	rules := make([]model.FingerprintSourceRule, 0, len(legacyRules))
	projections := make([]model.FingerprintRuleProjection, 0, len(legacyRules))
	unsupported := 0
	for _, legacy := range legacyRules {
		raw, err := json.Marshal(legacy)
		if err != nil {
			return err
		}
		path := fmt.Sprintf("banner/%d.json", legacy.ID)
		ruleSHA := sha256String(raw)
		status, reason := legacyBannerExecutionStatus(legacy)
		rules = append(rules, model.FingerprintSourceRule{
			SourceRuleID: fmt.Sprintf("banner:%d", legacy.ID), SourcePath: path,
			ContentSHA256: ruleSHA, RawContent: string(raw), RawStructure: `{"legacy":"banner"}`,
			ImportStatus: status, ImportError: reason,
		})
		if status != "executable" {
			unsupported++
			continue
		}
		operator, pattern := legacyBannerMatcher(legacy)
		projections = append(projections, model.FingerprintRuleProjection{
			SourcePath: path, ContentSHA256: ruleSHA, SourceProduct: strings.TrimSpace(legacy.ServiceName),
			Product:  model.FingerprintProduct{CanonicalName: strings.ToLower(strings.TrimSpace(legacy.ServiceName))},
			Protocol: firstNonEmptyFingerprintProtocol(legacy.Protocol),
			Root: model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{{
				EvidenceType: "tcp_banner", Target: "banner", Operator: operator, Value: pattern,
			}}},
		})
	}
	manifestJSON, err := json.Marshal(map[string]interface{}{
		"source_key":  legacyBannerSourceKey,
		"migration":   "v1-banner-migration",
		"adapter":     legacyBannerAdapterVersion,
		"rule_total":  len(legacyRules),
		"executable":  len(projections),
		"unsupported": unsupported,
	})
	if err != nil {
		return err
	}
	_, err = ImportFingerprintBatch(db, FingerprintImportBatch{
		Source: model.FingerprintSource{SourceKey: legacyBannerSourceKey, RepositoryURL: "local://banner", License: "project-internal", Status: "enabled"},
		Import: model.FingerprintImport{
			Commit: "v1-banner-migration", ContentSHA256: contentSHA, UpstreamContentSHA256: contentSHA,
			AdapterVersion: legacyBannerAdapterVersion, ManifestJSON: string(manifestJSON),
			RuleTotal: len(rules), ExecutableTotal: len(projections), UnsupportedTotal: unsupported,
		},
		Rules: rules, Projections: projections,
	})
	return err
}

func legacyBannerExecutionStatus(rule legacyBannerRule) (string, string) {
	service := strings.ToLower(strings.TrimSpace(rule.ServiceName))
	if service == "" || service == "unknown" || service == "none_unknown" {
		return "unsupported", "legacy fallback/state row is not a product fingerprint"
	}
	if strings.TrimSpace(rule.BannerPattern) == "" {
		return "unsupported", "empty banner pattern matches every endpoint"
	}
	switch strings.ToLower(strings.TrimSpace(rule.MatchType)) {
	case "contains", "contains_ci", "equals", "regex", "regex_ci":
		return "executable", ""
	default:
		return "unsupported", "unsupported legacy match operator"
	}
}

func legacyBannerMatcher(rule legacyBannerRule) (string, string) {
	if strings.EqualFold(strings.TrimSpace(rule.ServiceName), "openssh") &&
		strings.EqualFold(strings.TrimSpace(rule.BannerPattern), "openssh") {
		return "regex_ci", `^SSH-[0-9.]+-OpenSSH(?:[_/-]|$)`
	}
	return strings.ToLower(strings.TrimSpace(rule.MatchType)), rule.BannerPattern
}

func firstNonEmptyFingerprintProtocol(protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		return "tcp"
	}
	return protocol
}

func sha256String(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

const fingerprintImportSelect = `
	SELECT id, fingerprint_source_id, commit_hash, content_sha256, upstream_content_sha256,
		adapter_version, projection_sha256, manifest_json, rule_total,
		executable_total, unsupported_total, import_error_total, COALESCE(error_summary, ''), is_active, created_at
	FROM fingerprint_imports`

const fingerprintImportSummarySelect = `
	SELECT fingerprint_imports.id, fingerprint_imports.fingerprint_source_id, fingerprint_imports.commit_hash,
		fingerprint_imports.content_sha256, fingerprint_imports.upstream_content_sha256,
		fingerprint_imports.adapter_version, fingerprint_imports.projection_sha256,
		fingerprint_imports.rule_total, fingerprint_imports.executable_total, fingerprint_imports.unsupported_total,
		fingerprint_imports.import_error_total, COALESCE(fingerprint_imports.error_summary, ''),
		fingerprint_imports.is_active, fingerprint_imports.created_at
	FROM fingerprint_imports`

type fingerprintImportScanner interface {
	Scan(dest ...interface{}) error
}

func scanFingerprintImport(scanner fingerprintImportScanner) (model.FingerprintImport, error) {
	var fingerprintImport model.FingerprintImport
	var isActive int
	err := scanner.Scan(
		&fingerprintImport.ID, &fingerprintImport.FingerprintSourceID, &fingerprintImport.Commit,
		&fingerprintImport.ContentSHA256, &fingerprintImport.UpstreamContentSHA256,
		&fingerprintImport.AdapterVersion, &fingerprintImport.ProjectionSHA256,
		&fingerprintImport.ManifestJSON, &fingerprintImport.RuleTotal,
		&fingerprintImport.ExecutableTotal, &fingerprintImport.UnsupportedTotal, &fingerprintImport.ImportErrorTotal,
		&fingerprintImport.ErrorSummary, &isActive, &fingerprintImport.CreatedAt,
	)
	fingerprintImport.IsActive = isActive != 0
	return fingerprintImport, err
}

func scanFingerprintImportSummary(scanner fingerprintImportScanner) (model.FingerprintImportSummary, error) {
	var value model.FingerprintImportSummary
	var active int
	err := scanner.Scan(&value.ID, &value.FingerprintSourceID, &value.Commit, &value.ContentSHA256,
		&value.UpstreamContentSHA256, &value.AdapterVersion, &value.ProjectionSHA256,
		&value.RuleTotal, &value.ExecutableTotal, &value.UnsupportedTotal, &value.ImportErrorTotal,
		&value.ErrorSummary, &active, &value.CreatedAt)
	value.IsActive = active != 0
	return value, err
}
