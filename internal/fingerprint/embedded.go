package fingerprint

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

//go:embed snapshots/manifest.json snapshots/*.tar.gz
var embeddedSnapshots embed.FS

func NewEmbeddedRegistry(db *sql.DB) (*Registry, error) {
	rawManifest, err := embeddedSnapshots.ReadFile("snapshots/manifest.json")
	if err != nil {
		return nil, err
	}
	manifest, err := ParseManifest(rawManifest)
	if err != nil {
		return nil, err
	}
	archives := make(map[string][]byte, len(manifest.Sources))
	for _, source := range manifest.Sources {
		archive, err := embeddedSnapshots.ReadFile(source.ArchivePath)
		if err != nil {
			return nil, fmt.Errorf("read embedded fingerprint archive %s: %w", source.SourceKey, err)
		}
		archives[source.SourceKey] = archive
	}
	return NewRegistry(db, manifest, archives, []SourceAdapter{
		fingerprintHubV3Adapter{}, fingerprintHubV4Adapter{}, eHoleAdapter{}, fscanAdapter{}, nmapAdapter{},
		fingerprintHubWebYAMLAdapter(), fingerprintHubServiceYAMLAdapter(), whatWebAdapter(), wappalyzerAdapter{},
	}), nil
}

func BootstrapEmbeddedSources(ctx context.Context, db *sql.DB) error {
	registry, err := NewEmbeddedRegistry(db)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(registry.Manifest.Sources))
	for _, source := range registry.Manifest.Sources {
		keys = append(keys, source.SourceKey)
	}
	return bootstrapSourceImports(ctx, db, keys, func(ctx context.Context, sourceKey string) error {
		_, err := registry.Import(ctx, sourceKey, "")
		return err
	})
}

// InitializeEmbeddedSourcesIfEmpty is the only implicit catalog mutation. It
// fills manifest sources that have never had an import, while existing source
// revisions change only through the explicit upgrade CLI.
func InitializeEmbeddedSourcesIfEmpty(ctx context.Context, db *sql.DB) (bool, error) {
	registry, err := NewEmbeddedRegistry(db)
	if err != nil {
		return false, err
	}
	return initializeMissingManifestSources(ctx, registry)
}

func initializeMissingManifestSources(ctx context.Context, registry *Registry) (bool, error) {
	if registry == nil || registry.DB == nil {
		return false, errors.New("fingerprint registry database is required")
	}
	changed := false
	for _, source := range registry.Manifest.Sources {
		var existing int
		if err := registry.DB.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM fingerprint_imports AS fingerprint_import
			JOIN fingerprint_sources AS fingerprint_source ON fingerprint_source.id = fingerprint_import.fingerprint_source_id
			WHERE fingerprint_source.source_key = ?`, source.SourceKey).Scan(&existing); err != nil {
			return changed, err
		}
		if existing > 0 {
			continue
		}
		if _, err := registry.DB.ExecContext(ctx, `
			INSERT INTO fingerprint_sources (source_key, repository_url, license, status)
			VALUES (?, ?, ?, 'enabled')
			ON CONFLICT(source_key) DO UPDATE SET repository_url = excluded.repository_url, license = excluded.license`,
			source.SourceKey, source.RepositoryURL, source.License); err != nil {
			return changed, err
		}
		if err := bootstrapSourceImports(ctx, registry.DB, []string{source.SourceKey}, func(ctx context.Context, sourceKey string) error {
			_, err := registry.Import(ctx, sourceKey, "")
			return err
		}); err != nil {
			return changed, err
		}
		var imported int
		if err := registry.DB.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM fingerprint_imports AS fingerprint_import
			JOIN fingerprint_sources AS fingerprint_source ON fingerprint_source.id = fingerprint_import.fingerprint_source_id
			WHERE fingerprint_source.source_key = ?`, source.SourceKey).Scan(&imported); err != nil {
			return changed, err
		}
		changed = changed || imported > 0
	}
	return changed, nil
}

func bootstrapSourceImports(ctx context.Context, db *sql.DB, sourceKeys []string, importSource func(context.Context, string) error) error {
	for _, sourceKey := range sourceKeys {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := importSource(ctx, sourceKey); err != nil {
			if pingErr := db.PingContext(ctx); pingErr != nil {
				return fmt.Errorf("fingerprint source %s failed and database is unavailable: %w", sourceKey, pingErr)
			}
			if diagnosticErr := storage.RecordFingerprintBootstrapFailure(db, sourceKey, err); diagnosticErr != nil {
				return fmt.Errorf("record fingerprint source %s bootstrap failure: %w", sourceKey, diagnosticErr)
			}
			log.Printf("fingerprint source %s bootstrap failed; retaining previous active revision: %v", sourceKey, err)
			continue
		}
		if err := storage.ResolveFingerprintBootstrapDiagnostic(db, sourceKey); err != nil {
			return fmt.Errorf("resolve fingerprint source %s bootstrap diagnostic: %w", sourceKey, err)
		}
	}
	return nil
}

type fingerprintHubV4Adapter struct{}

func (fingerprintHubV4Adapter) SourceKey() string      { return "fingerprinthub-web-v4" }
func (fingerprintHubV4Adapter) AdapterVersion() string { return "m11-fh-web-v4-stable-id-v1" }

func (fingerprintHubV4Adapter) Adapt(snapshot VerifiedSnapshot) ([]model.FingerprintSourceRule, error) {
	return adaptFingerprintHubWebJSON(snapshot, "web_fingerprint_v4.json")
}

type fingerprintHubV3Adapter struct{}

func (fingerprintHubV3Adapter) SourceKey() string      { return "fingerprinthub-web-v3" }
func (fingerprintHubV3Adapter) AdapterVersion() string { return "m11-fh-web-v3-stable-id-v1" }

func (fingerprintHubV3Adapter) Adapt(snapshot VerifiedSnapshot) ([]model.FingerprintSourceRule, error) {
	return adaptFingerprintHubWebJSON(snapshot, "web_fingerprint_v3.json")
}

func adaptFingerprintHubWebJSON(snapshot VerifiedSnapshot, fileName string) ([]model.FingerprintSourceRule, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(snapshot.Files[fileName], &entries); err != nil {
		return nil, err
	}
	rules := make([]model.FingerprintSourceRule, 0, len(entries))
	for index, raw := range entries {
		var identity struct {
			ID             string            `json:"id"`
			Path           string            `json:"path"`
			RequestMethod  string            `json:"request_method"`
			RequestHeaders map[string]string `json:"request_headers"`
			RequestData    string            `json:"request_data"`
			HTTP           []struct {
				Method string   `json:"method"`
				Path   []string `json:"path"`
			} `json:"http"`
		}
		if err := json.Unmarshal(raw, &identity); err != nil {
			return nil, fmt.Errorf("decode FingerprintHub rule %d: %w", index, err)
		}
		sourceRuleID := strings.TrimSpace(identity.ID)
		if sourceRuleID == "" {
			sourceRuleID = fmt.Sprintf("index:%d", index)
		}
		status, importError := "executable", ""
		if fileName == "web_fingerprint_v4.json" && !isRootGETOnly(identity.HTTP) {
			status, importError = "unsupported", "request_method_or_path_not_supported"
		}
		if fileName == "web_fingerprint_v3.json" && (!strings.EqualFold(identity.RequestMethod, "get") || identity.Path != "/" || len(identity.RequestHeaders) > 0 || identity.RequestData != "") {
			status, importError = "unsupported", "request_method_or_path_not_supported"
		}
		rules = append(rules, model.FingerprintSourceRule{
			SourceRuleID:  sourceRuleID,
			SourcePath:    fmt.Sprintf("%s#/%d", fileName, index),
			ContentSHA256: sha256Hex(raw),
			RawContent:    string(raw),
			RawStructure:  string(raw),
			ImportStatus:  status,
			ImportError:   importError,
		})
	}
	return rules, nil
}

func isRootGETOnly(requests []struct {
	Method string   `json:"method"`
	Path   []string `json:"path"`
}) bool {
	for _, request := range requests {
		if request.Method != "" && !strings.EqualFold(request.Method, "GET") {
			return false
		}
		for _, path := range request.Path {
			if path != "/" && path != "{{BaseURL}}/" {
				return false
			}
		}
	}
	return true
}

type eHoleAdapter struct{}

func (eHoleAdapter) SourceKey() string { return "ehole" }

func (eHoleAdapter) Adapt(snapshot VerifiedSnapshot) ([]model.FingerprintSourceRule, error) {
	var document struct {
		Fingerprint []json.RawMessage `json:"fingerprint"`
	}
	if err := json.Unmarshal(snapshot.Files["finger.json"], &document); err != nil {
		return nil, err
	}
	rules := make([]model.FingerprintSourceRule, 0, len(document.Fingerprint))
	for index, raw := range document.Fingerprint {
		var identity struct {
			CMS string `json:"cms"`
		}
		if err := json.Unmarshal(raw, &identity); err != nil {
			return nil, fmt.Errorf("decode EHole rule %d: %w", index, err)
		}
		rules = append(rules, model.FingerprintSourceRule{
			SourceRuleID:  fmt.Sprintf("%s:%d", identity.CMS, index),
			SourcePath:    fmt.Sprintf("finger.json#/fingerprint/%d", index),
			ContentSHA256: sha256Hex(raw),
			RawContent:    string(raw),
			RawStructure:  string(raw),
			ImportStatus:  "executable",
		})
	}
	return rules, nil
}
