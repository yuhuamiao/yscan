// Package fingerprint defines the auditable local-rule pipeline used by M11.
package fingerprint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"
)

const SourceManifestFormatVersion = 1

var sourceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// SourceManifest is the checked-in provenance record for local fingerprint
// snapshots. It is metadata only: runtime code must consume the local snapshot
// named here and must not fetch the repository URL.
type SourceManifest struct {
	FormatVersion int                 `json:"format_version"`
	Sources       []FingerprintSource `json:"sources"`
}

// FingerprintSource pins one rule snapshot to an upstream repository, version,
// licence and content hash. Snapshot is a slash-separated package-relative
// path, normally below data/fingerprints/.
type FingerprintSource struct {
	ID         string `json:"id"`
	Repository string `json:"repository"`
	Version    string `json:"version"`
	License    string `json:"license"`
	SHA256     string `json:"sha256"`
	Snapshot   string `json:"snapshot"`
}

// ParseSourceManifest decodes and validates one complete manifest. Unknown
// JSON fields and trailing values are rejected so new metadata cannot be
// silently ignored by an older binary.
func ParseSourceManifest(data []byte) (SourceManifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var manifest SourceManifest
	if err := decoder.Decode(&manifest); err != nil {
		return SourceManifest{}, fmt.Errorf("decode fingerprint source manifest: %w", err)
	}
	if err := ensureManifestEOF(decoder); err != nil {
		return SourceManifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return SourceManifest{}, err
	}
	return manifest, nil
}

func ensureManifestEOF(decoder *json.Decoder) error {
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("fingerprint source manifest contains trailing JSON values")
		}
		return fmt.Errorf("decode fingerprint source manifest tail: %w", err)
	}
	return nil
}

// Validate canonicalizes whitespace and verifies every provenance field needed
// to reproduce a local snapshot. The method mutates the receiver only to store
// canonical lower-case SHA-256 values and trimmed text.
func (manifest *SourceManifest) Validate() error {
	if manifest.FormatVersion != SourceManifestFormatVersion {
		return fmt.Errorf("unsupported fingerprint source manifest format_version: %d", manifest.FormatVersion)
	}
	if len(manifest.Sources) == 0 {
		return errors.New("fingerprint source manifest requires at least one source")
	}

	seenIDs := make(map[string]struct{}, len(manifest.Sources))
	seenSnapshots := make(map[string]struct{}, len(manifest.Sources))
	for index := range manifest.Sources {
		source := &manifest.Sources[index]
		if err := source.Validate(); err != nil {
			return fmt.Errorf("fingerprint source %d: %w", index, err)
		}
		if _, exists := seenIDs[source.ID]; exists {
			return fmt.Errorf("duplicate fingerprint source id: %s", source.ID)
		}
		if _, exists := seenSnapshots[source.Snapshot]; exists {
			return fmt.Errorf("duplicate fingerprint source snapshot: %s", source.Snapshot)
		}
		seenIDs[source.ID] = struct{}{}
		seenSnapshots[source.Snapshot] = struct{}{}
	}
	return nil
}

// Validate verifies and normalizes one provenance entry.
func (source *FingerprintSource) Validate() error {
	source.ID = strings.TrimSpace(strings.ToLower(source.ID))
	source.Repository = strings.TrimSpace(source.Repository)
	source.Version = strings.TrimSpace(source.Version)
	source.License = strings.TrimSpace(source.License)
	source.SHA256 = strings.ToLower(strings.TrimSpace(source.SHA256))
	source.Snapshot = strings.TrimSpace(source.Snapshot)

	if !sourceIDPattern.MatchString(source.ID) {
		return errors.New("id must contain 1-64 lowercase letters, numbers, dots, underscores or hyphens")
	}
	if err := validateRepository(source.Repository); err != nil {
		return err
	}
	if source.Version == "" || isFloatingVersion(source.Version) {
		return errors.New("version must pin a release or immutable revision")
	}
	if source.License == "" {
		return errors.New("license is required")
	}
	if len(source.SHA256) != 64 || strings.Trim(source.SHA256, "0123456789abcdef") != "" {
		return errors.New("sha256 must be a 64-character hexadecimal digest")
	}
	if err := validateSnapshotPath(source.Snapshot); err != nil {
		return err
	}
	return nil
}

func validateRepository(value string) error {
	if value == "" {
		return errors.New("repository is required")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("repository must be an HTTPS URL without credentials, query or fragment")
	}
	return nil
}

func isFloatingVersion(value string) bool {
	switch strings.ToLower(value) {
	case "latest", "head", "main", "master":
		return true
	default:
		return false
	}
}

func validateSnapshotPath(value string) error {
	if value == "" {
		return errors.New("snapshot is required")
	}
	if strings.Contains(value, `\`) || strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "." || strings.HasPrefix(value, "../") {
		return errors.New("snapshot must be a clean relative slash-separated path")
	}
	return nil
}
