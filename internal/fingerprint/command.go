package fingerprint

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

type SourceAdapter interface {
	SourceKey() string
	Adapt(VerifiedSnapshot) ([]model.FingerprintSourceRule, error)
	Project(model.FingerprintSourceRule) (model.FingerprintRuleProjection, error)
}

type versionedSourceAdapter interface {
	AdapterVersion() string
}

const normalizedProjectionAdapterVersion = "m11-projection-v2"

func adapterVersion(adapter SourceAdapter) string {
	base := normalizedProjectionAdapterVersion
	if versioned, ok := adapter.(versionedSourceAdapter); ok {
		if version := strings.TrimSpace(versioned.AdapterVersion()); version != "" {
			base = version
		}
	}
	return base + "+" + ProductNormalizationRevision
}

type Registry struct {
	DB               *sql.DB
	Manifest         Manifest
	EmbeddedArchives map[string][]byte
	Adapters         map[string]SourceAdapter
}

func NewRegistry(db *sql.DB, manifest Manifest, embeddedArchives map[string][]byte, adapters []SourceAdapter) *Registry {
	registry := &Registry{DB: db, Manifest: manifest, EmbeddedArchives: embeddedArchives, Adapters: make(map[string]SourceAdapter)}
	for _, adapter := range adapters {
		if adapter != nil {
			registry.Adapters[adapter.SourceKey()] = adapter
		}
	}
	return registry
}

func (registry *Registry) Import(ctx context.Context, sourceKey, recoveryArchive string) (model.FingerprintImport, error) {
	if err := ctx.Err(); err != nil {
		return model.FingerprintImport{}, err
	}
	source, ok := registry.source(strings.TrimSpace(sourceKey))
	if !ok {
		return model.FingerprintImport{}, fmt.Errorf("no embedded fingerprint source revision for %q", sourceKey)
	}
	archive := registry.EmbeddedArchives[source.SourceKey]
	if strings.TrimSpace(recoveryArchive) != "" {
		var err error
		archive, err = os.ReadFile(recoveryArchive)
		if err != nil {
			return model.FingerprintImport{}, fmt.Errorf("read recovery archive: %w", err)
		}
	}
	verified, err := VerifyArchive(source, archive)
	if err != nil {
		return model.FingerprintImport{}, err
	}
	adapter := registry.Adapters[source.SourceKey]
	if adapter == nil {
		return model.FingerprintImport{}, fmt.Errorf("no fingerprint adapter registered for %q", source.SourceKey)
	}
	rules, err := adapter.Adapt(verified)
	if err != nil {
		return model.FingerprintImport{}, fmt.Errorf("adapt fingerprint source %s: %w", source.SourceKey, err)
	}
	projections, err := projectExecutableRules(adapter, rules)
	if err != nil {
		return model.FingerprintImport{}, fmt.Errorf("normalize fingerprint source %s: %w", source.SourceKey, err)
	}
	manifestJSON, err := CanonicalManifestJSON(source)
	if err != nil {
		return model.FingerprintImport{}, err
	}
	return storage.ImportFingerprintBatch(registry.DB, storage.FingerprintImportBatch{
		Source: model.FingerprintSource{SourceKey: source.SourceKey, RepositoryURL: source.RepositoryURL, License: source.License, Status: "enabled"},
		Import: model.FingerprintImport{
			Commit:                source.Commit,
			ContentSHA256:         source.ArchiveSHA256,
			UpstreamContentSHA256: source.ArchiveSHA256,
			AdapterVersion:        adapterVersion(adapter),
			ManifestJSON:          manifestJSON,
			RuleTotal:             source.ExpectedStats.RuleTotal,
			ExecutableTotal:       source.ExpectedStats.ExecutableTotal,
			UnsupportedTotal:      source.ExpectedStats.UnsupportedTotal,
			ImportErrorTotal:      source.ExpectedStats.ImportErrorTotal,
		},
		Rules:       rules,
		Projections: projections,
	})
}

func (registry *Registry) source(sourceKey string) (SourceManifest, bool) {
	for _, source := range registry.Manifest.Sources {
		if source.SourceKey == sourceKey {
			return source, true
		}
	}
	return SourceManifest{}, false
}

// RunCLI is separate from schedule commands because rule lifecycle is not a
// ScanTask lifecycle. `upgrade` is intentionally the same verified operation
// as `import`; idempotency and active switching live in storage.
func RunCLI(ctx context.Context, registry *Registry, args []string, output io.Writer) error {
	if registry == nil || registry.DB == nil || output == nil {
		return errors.New("fingerprint CLI registry and output are required")
	}
	if len(args) == 0 {
		writeUsage(output)
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "list":
		return writeSources(output, registry.DB)
	case "import":
		sourceKey, recovery, err := parseImportArgs(args[1:])
		if err != nil {
			return err
		}
		fingerprintImport, err := registry.Import(ctx, sourceKey, recovery)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "Fingerprint source %s revision %s active (import %d)\n", sourceKey, fingerprintImport.Commit, fingerprintImport.ID)
		return err
	case "upgrade":
		if len(args) > 1 {
			sourceKey, recovery, err := parseImportArgs(args[1:])
			if err != nil {
				return err
			}
			fingerprintImport, err := registry.Import(ctx, sourceKey, recovery)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(output, "Fingerprint source %s revision %s active (import %d)\n", sourceKey, fingerprintImport.Commit, fingerprintImport.ID)
			return err
		}
		var failures []error
		for _, source := range registry.Manifest.Sources {
			fingerprintImport, err := registry.Import(ctx, source.SourceKey, "")
			if err != nil {
				_, _ = fmt.Fprintf(output, "Fingerprint source %s upgrade failed: %v\n", source.SourceKey, err)
				failures = append(failures, fmt.Errorf("%s: %w", source.SourceKey, err))
				continue
			}
			_, _ = fmt.Fprintf(output, "Fingerprint source %s revision %s active (import %d)\n", source.SourceKey, fingerprintImport.Commit, fingerprintImport.ID)
		}
		return errors.Join(failures...)
	case "mapping":
		return runMappingCLI(registry.DB, args[1:], output)
	case "cleanup":
		return runCleanupCLI(registry.DB, args[1:], output)
	default:
		writeUsage(output)
		return nil
	}
}

func runCleanupCLI(db *sql.DB, args []string, output io.Writer) error {
	apply := false
	if len(args) > 0 {
		if len(args) != 1 || args[0] != "--apply" {
			return errors.New("usage: yscan fingerprint cleanup [--apply]")
		}
		apply = true
	}
	plan, err := storage.PlanFingerprintImportCleanup(db)
	if err != nil {
		return err
	}
	mode := "DRY-RUN"
	if apply {
		plan, err = storage.ApplyFingerprintImportCleanup(db)
		if err != nil {
			return err
		}
		mode = "APPLIED"
	}
	for _, candidate := range plan.Candidates {
		if _, err := fmt.Fprintf(output, "%s import=%d source=%s revision=%s adapter=%s rules=%d estimated_bytes=%d\n", mode, candidate.ImportID, candidate.SourceKey, candidate.Commit, candidate.AdapterVersion, candidate.RuleTotal, candidate.EstimatedPayloadBytes); err != nil {
			return err
		}
	}
	type sourceCleanupSummary struct {
		count int
		bytes int64
	}
	bySource := make(map[string]sourceCleanupSummary)
	for _, candidate := range plan.Candidates {
		summary := bySource[candidate.SourceKey]
		summary.count++
		summary.bytes += candidate.EstimatedPayloadBytes
		bySource[candidate.SourceKey] = summary
	}
	sourceKeys := make([]string, 0, len(bySource))
	for sourceKey := range bySource {
		sourceKeys = append(sourceKeys, sourceKey)
	}
	sort.Strings(sourceKeys)
	for _, sourceKey := range sourceKeys {
		summary := bySource[sourceKey]
		if _, err := fmt.Fprintf(output, "%s source=%s candidates=%d estimated_bytes=%d\n", mode, sourceKey, summary.count, summary.bytes); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(output, "%s candidates=%d deleted=%d estimated_bytes=%d\n", mode, len(plan.Candidates), plan.DeletedImports, plan.EstimatedPayloadBytes)
	return err
}

type mappingManifest struct {
	Revision            string                             `json:"revision"`
	TemplateSetRevision string                             `json:"template_set_revision"`
	Mappings            []model.FingerprintTemplateMapping `json:"mappings"`
}

func runMappingCLI(db *sql.DB, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: yscan fingerprint mapping list|import|disable")
	}
	switch args[0] {
	case "list":
		mappings, err := storage.ListFingerprintTemplateMappings(db)
		if err != nil {
			return err
		}
		for _, mapping := range mappings {
			if _, err := fmt.Fprintf(output, "%d %s %s %s %t\n", mapping.ID, mapping.ProductKey, mapping.TemplateID, mapping.TemplateSHA256, mapping.Enabled); err != nil {
				return err
			}
		}
		return nil
	case "disable":
		if len(args) != 3 || args[1] != "--id" {
			return errors.New("usage: yscan fingerprint mapping disable --id <id>")
		}
		id, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil || id <= 0 {
			return errors.New("mapping id must be a positive integer")
		}
		return storage.DisableFingerprintTemplateMapping(db, id)
	case "import":
		if len(args) != 5 || args[1] != "--manifest" || args[3] != "--templates" {
			return errors.New("usage: yscan fingerprint mapping import --manifest <path> --templates <root>")
		}
		return importMappingManifest(db, args[2], args[4], output)
	default:
		return errors.New("usage: yscan fingerprint mapping list|import|disable")
	}
}

func importMappingManifest(db *sql.DB, manifestPath, templatesRoot string, output io.Writer) error {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read mapping manifest: %w", err)
	}
	var manifest mappingManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("parse mapping manifest: %w", err)
	}
	if strings.TrimSpace(manifest.Revision) == "" || strings.TrimSpace(manifest.TemplateSetRevision) == "" {
		return errors.New("mapping manifest revision and template_set_revision are required")
	}
	root, err := filepath.Abs(templatesRoot)
	if err != nil {
		return err
	}
	for index := range manifest.Mappings {
		mapping := &manifest.Mappings[index]
		mapping.TemplateSetRevision = manifest.TemplateSetRevision
		path := filepath.Join(root, filepath.Clean(mapping.TemplatePath))
		if !strings.HasPrefix(path, root+string(os.PathSeparator)) {
			return fmt.Errorf("mapping %d template path escapes root", index)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read template %s: %w", mapping.TemplatePath, err)
		}
		sum := sha256.Sum256(content)
		actual := hex.EncodeToString(sum[:])
		if !strings.EqualFold(actual, strings.TrimSpace(mapping.TemplateSHA256)) {
			return fmt.Errorf("template SHA-256 mismatch for %s", mapping.TemplatePath)
		}
	}
	sum := sha256.Sum256(raw)
	value, err := storage.ImportTemplateMappingBatch(db, storage.TemplateMappingBatch{Import: model.TemplateMappingImport{Revision: manifest.Revision, ContentSHA256: hex.EncodeToString(sum[:]), ManifestJSON: string(raw)}, Mappings: manifest.Mappings})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Template mapping revision %s active (import %d)\n", value.Revision, value.ID)
	return err
}

func parseImportArgs(args []string) (string, string, error) {
	var sourceKey, recovery string
	for index := 0; index < len(args); index++ {
		if index+1 >= len(args) {
			return "", "", fmt.Errorf("%s requires a value", args[index])
		}
		value := strings.TrimSpace(args[index+1])
		switch strings.TrimSpace(args[index]) {
		case "--source":
			sourceKey = value
		case "--recovery-archive":
			recovery = value
		default:
			return "", "", fmt.Errorf("unsupported flag: %s", args[index])
		}
		index++
	}
	if sourceKey == "" {
		return "", "", errors.New("usage: yscan fingerprint import --source <source_key> [--recovery-archive <path>]")
	}
	return sourceKey, recovery, nil
}

func writeSources(output io.Writer, db *sql.DB) error {
	sources, err := storage.ListFingerprintSources(db)
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		_, err := fmt.Fprintln(output, "No fingerprint sources imported.")
		return err
	}
	imports, err := storage.ListActiveFingerprintImports(db)
	if err != nil {
		return err
	}
	activeBySource := make(map[int64]model.FingerprintImport, len(imports))
	for _, fingerprintImport := range imports {
		activeBySource[fingerprintImport.FingerprintSourceID] = fingerprintImport
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].SourceKey < sources[j].SourceKey })
	if _, err := fmt.Fprintln(output, "SOURCE                         STATUS     REVISION                 RULES  EXEC  UNSUPPORTED  IMPORT_ERROR  ERROR"); err != nil {
		return err
	}
	for _, source := range sources {
		fingerprintImport := activeBySource[source.ID]
		errorSummary := firstNonEmptyString(source.LastError, fingerprintImport.ErrorSummary)
		if _, err := fmt.Fprintf(output, "%-30s %-10s %-24s %-6d %-5d %-12d %-13d %s\n", source.SourceKey, source.CatalogStatus, fingerprintImport.Commit, fingerprintImport.RuleTotal, fingerprintImport.ExecutableTotal, fingerprintImport.UnsupportedTotal, fingerprintImport.ImportErrorTotal, errorSummary); err != nil {
			return err
		}
	}
	return nil
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func writeUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: yscan fingerprint list")
	fmt.Fprintln(output, "       yscan fingerprint import --source <source_key> [--recovery-archive <path>]")
	fmt.Fprintln(output, "       yscan fingerprint upgrade --source <source_key> [--recovery-archive <path>]")
	fmt.Fprintln(output, "       yscan fingerprint mapping list")
	fmt.Fprintln(output, "       yscan fingerprint mapping import --manifest <path> --templates <root>")
	fmt.Fprintln(output, "       yscan fingerprint mapping disable --id <id>")
	fmt.Fprintln(output, "       yscan fingerprint cleanup [--apply]")
}
