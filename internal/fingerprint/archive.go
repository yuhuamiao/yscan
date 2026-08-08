// Package fingerprint owns source-snapshot validation and, in later tasks,
// source-specific adapters. It never treats a loose rule file as runtime data.
package fingerprint

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

type Manifest struct {
	Sources []SourceManifest `json:"sources"`
}

type SourceManifest struct {
	SourceKey     string         `json:"source_key"`
	RepositoryURL string         `json:"repository_url"`
	License       string         `json:"license"`
	Commit        string         `json:"commit"`
	ArchivePath   string         `json:"archive_path"`
	ArchiveSHA256 string         `json:"archive_sha256"`
	Files         []ManifestFile `json:"files"`
	ExpectedStats RuleStats      `json:"expected_stats"`
}

type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type RuleStats struct {
	RuleTotal        int `json:"rule_total"`
	ExecutableTotal  int `json:"executable_total"`
	UnsupportedTotal int `json:"unsupported_total"`
	ImportErrorTotal int `json:"import_error_total"`
}

type VerifiedSnapshot struct {
	Manifest SourceManifest
	Files    map[string][]byte
}

func ParseManifest(raw []byte) (Manifest, error) {
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode fingerprint manifest: %w", err)
	}
	if len(manifest.Sources) == 0 {
		return Manifest{}, errors.New("fingerprint manifest contains no sources")
	}
	seenSources := make(map[string]struct{}, len(manifest.Sources))
	for _, source := range manifest.Sources {
		if err := validateSourceManifest(source); err != nil {
			return Manifest{}, err
		}
		if _, exists := seenSources[source.SourceKey]; exists {
			return Manifest{}, fmt.Errorf("duplicate fingerprint manifest source: %s", source.SourceKey)
		}
		seenSources[source.SourceKey] = struct{}{}
	}
	return manifest, nil
}

func VerifyArchive(source SourceManifest, archive []byte) (VerifiedSnapshot, error) {
	if err := validateSourceManifest(source); err != nil {
		return VerifiedSnapshot{}, err
	}
	if sha256Hex(archive) != strings.ToLower(source.ArchiveSHA256) {
		return VerifiedSnapshot{}, fmt.Errorf("fingerprint archive SHA-256 mismatch for %s", source.SourceKey)
	}

	reader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return VerifiedSnapshot{}, fmt.Errorf("open fingerprint archive: %w", err)
	}
	defer reader.Close()
	tarReader := tar.NewReader(reader)
	files := make(map[string][]byte, len(source.Files))
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return VerifiedSnapshot{}, fmt.Errorf("read fingerprint archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			return VerifiedSnapshot{}, fmt.Errorf("fingerprint archive contains non-regular entry: %s", header.Name)
		}
		name, err := cleanArchivePath(header.Name)
		if err != nil {
			return VerifiedSnapshot{}, err
		}
		if _, exists := files[name]; exists {
			return VerifiedSnapshot{}, fmt.Errorf("fingerprint archive contains duplicate file: %s", name)
		}
		content, err := io.ReadAll(tarReader)
		if err != nil {
			return VerifiedSnapshot{}, fmt.Errorf("read fingerprint archive file %s: %w", name, err)
		}
		files[name] = content
	}

	expected := make(map[string]string, len(source.Files))
	for _, file := range source.Files {
		expected[file.Path] = strings.ToLower(file.SHA256)
	}
	if len(files) != len(expected) {
		return VerifiedSnapshot{}, fmt.Errorf("fingerprint archive file count mismatch for %s", source.SourceKey)
	}
	for name, content := range files {
		sha, exists := expected[name]
		if !exists {
			return VerifiedSnapshot{}, fmt.Errorf("fingerprint archive contains unlisted file: %s", name)
		}
		if sha256Hex(content) != sha {
			return VerifiedSnapshot{}, fmt.Errorf("fingerprint archive file SHA-256 mismatch: %s", name)
		}
	}
	return VerifiedSnapshot{Manifest: source, Files: files}, nil
}

func CanonicalManifestJSON(source SourceManifest) (string, error) {
	copy := source
	sort.Slice(copy.Files, func(i, j int) bool { return copy.Files[i].Path < copy.Files[j].Path })
	encoded, err := json.Marshal(copy)
	if err != nil {
		return "", fmt.Errorf("encode source manifest: %w", err)
	}
	return string(encoded), nil
}

func validateSourceManifest(source SourceManifest) error {
	if strings.TrimSpace(source.SourceKey) == "" || strings.TrimSpace(source.RepositoryURL) == "" || strings.TrimSpace(source.Commit) == "" || strings.TrimSpace(source.ArchivePath) == "" {
		return errors.New("fingerprint manifest source key, repository URL, commit, and archive path are required")
	}
	if _, err := cleanArchivePath(source.ArchivePath); err != nil {
		return fmt.Errorf("invalid fingerprint manifest archive path %q", source.ArchivePath)
	}
	if !isSHA256(source.ArchiveSHA256) {
		return fmt.Errorf("invalid fingerprint archive SHA-256 for %s", source.SourceKey)
	}
	if source.ExpectedStats.RuleTotal < 0 || source.ExpectedStats.ExecutableTotal < 0 || source.ExpectedStats.UnsupportedTotal < 0 || source.ExpectedStats.ImportErrorTotal < 0 {
		return fmt.Errorf("negative fingerprint statistics for %s", source.SourceKey)
	}
	seenFiles := make(map[string]struct{}, len(source.Files))
	for _, file := range source.Files {
		cleanPath, err := cleanArchivePath(file.Path)
		if err != nil || cleanPath != file.Path {
			return fmt.Errorf("invalid fingerprint manifest path %q", file.Path)
		}
		if !isSHA256(file.SHA256) {
			return fmt.Errorf("invalid fingerprint manifest file SHA-256: %s", file.Path)
		}
		if _, exists := seenFiles[file.Path]; exists {
			return fmt.Errorf("duplicate fingerprint manifest file: %s", file.Path)
		}
		seenFiles[file.Path] = struct{}{}
	}
	if len(source.Files) == 0 {
		return fmt.Errorf("fingerprint manifest has no files for %s", source.SourceKey)
	}
	return nil
}

func cleanArchivePath(value string) (string, error) {
	cleaned := path.Clean(strings.TrimSpace(value))
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("unsafe fingerprint archive path: %q", value)
	}
	return cleaned, nil
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
