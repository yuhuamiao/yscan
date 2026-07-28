package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSourceManifestValidatesAndCanonicalizesSources(t *testing.T) {
	manifest, err := ParseSourceManifest([]byte(`{
		"format_version": 1,
		"sources": [{
			"id": "FingerprintHub",
			"repository": "https://github.com/0x727/FingerprintHub",
			"version": "4c29d2a",
			"license": "MIT",
			"sha256": "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD",
			"snapshot": "data/fingerprints/fingerprinthub/rules.yaml"
		}]
	}`))
	if err != nil {
		t.Fatalf("parse valid manifest: %v", err)
	}
	if manifest.FormatVersion != SourceManifestFormatVersion || len(manifest.Sources) != 1 {
		t.Fatalf("manifest = %#v", manifest)
	}
	source := manifest.Sources[0]
	if source.ID != "fingerprinthub" || source.SHA256 != strings.ToLower("ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD") {
		t.Fatalf("canonical source = %#v", source)
	}
}

func TestCheckedInSourceManifestMatchesLocalSnapshots(t *testing.T) {
	repositoryRoot := filepath.Join("..", "..")
	manifestData, err := os.ReadFile(filepath.Join(repositoryRoot, "data", "fingerprints", "manifest.json"))
	if err != nil {
		t.Fatalf("read checked-in manifest: %v", err)
	}
	manifest, err := ParseSourceManifest(manifestData)
	if err != nil {
		t.Fatalf("parse checked-in manifest: %v", err)
	}
	for _, source := range manifest.Sources {
		snapshot, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(source.Snapshot)))
		if err != nil {
			t.Fatalf("read %s snapshot: %v", source.ID, err)
		}
		digest := sha256.Sum256(snapshot)
		if got := hex.EncodeToString(digest[:]); got != source.SHA256 {
			t.Fatalf("%s snapshot sha256 = %s, want %s", source.ID, got, source.SHA256)
		}
	}
}

func TestParseSourceManifestRejectsMissingProvenance(t *testing.T) {
	fields := []string{"id", "repository", "version", "license", "sha256", "snapshot"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			manifest := validManifestJSON()
			manifest = strings.Replace(manifest, `"`+field+`":"`+validFieldValue(field)+`"`, `"`+field+`":""`, 1)
			if _, err := ParseSourceManifest([]byte(manifest)); err == nil {
				t.Fatalf("missing %s must be rejected", field)
			}
		})
	}
}

func TestParseSourceManifestRejectsUnsafeOrAmbiguousEntries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(string) string
	}{
		{
			name: "unknown field",
			mutate: func(manifest string) string {
				return strings.Replace(manifest, `"id":"fingerprinthub",`, `"id":"fingerprinthub","unchecked":true,`, 1)
			},
		},
		{
			name: "floating version",
			mutate: func(manifest string) string {
				return strings.Replace(manifest, `"version":"4c29d2a"`, `"version":"main"`, 1)
			},
		},
		{
			name: "unsafe snapshot",
			mutate: func(manifest string) string {
				return strings.Replace(manifest, `data/fingerprints/fingerprinthub/rules.yaml`, `../rules.yaml`, 1)
			},
		},
		{
			name: "duplicate source id",
			mutate: func(manifest string) string {
				return strings.Replace(manifest, `]}`, `,{"id":"fingerprinthub","repository":"https://github.com/example/other","version":"v1.0.0","license":"MIT","sha256":"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd","snapshot":"data/fingerprints/other/rules.yaml"}]}`, 1)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseSourceManifest([]byte(test.mutate(validManifestJSON()))); err == nil {
				t.Fatal("invalid manifest must be rejected")
			}
		})
	}
}

func validManifestJSON() string {
	return `{"format_version":1,"sources":[{"id":"fingerprinthub","repository":"https://github.com/0x727/FingerprintHub","version":"4c29d2a","license":"Apache-2.0","sha256":"abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd","snapshot":"data/fingerprints/fingerprinthub/rules.yaml"}]}`
}

func validFieldValue(field string) string {
	values := map[string]string{
		"id":         "fingerprinthub",
		"repository": "https://github.com/0x727/FingerprintHub",
		"version":    "4c29d2a",
		"license":    "Apache-2.0",
		"sha256":     "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
		"snapshot":   "data/fingerprints/fingerprinthub/rules.yaml",
	}
	return values[field]
}
