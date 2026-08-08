package fingerprint

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

func TestParseManifestAndVerifyArchive(t *testing.T) {
	archive := fixtureArchive(t, map[string]string{
		"LICENSE":      "fixture license\n",
		"rules/a.json": `{"name":"fixture"}`,
	})
	source := SourceManifest{
		SourceKey:     "fixture-source",
		RepositoryURL: "https://example.invalid/fingerprint",
		License:       "fixture",
		Commit:        "fixture-commit",
		ArchivePath:   "snapshots/fixture.tar.gz",
		ArchiveSHA256: sha256Hex(archive),
		Files: []ManifestFile{
			{Path: "LICENSE", SHA256: sha256Hex([]byte("fixture license\n"))},
			{Path: "rules/a.json", SHA256: sha256Hex([]byte(`{"name":"fixture"}`))},
		},
		ExpectedStats: RuleStats{RuleTotal: 1, ExecutableTotal: 1},
	}
	manifestJSON, err := CanonicalManifestJSON(source)
	if err != nil {
		t.Fatalf("canonical manifest: %v", err)
	}
	manifest, err := ParseManifest([]byte(`{"sources":[` + manifestJSON + `]}`))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	verified, err := VerifyArchive(manifest.Sources[0], archive)
	if err != nil {
		t.Fatalf("verify archive: %v", err)
	}
	if string(verified.Files["rules/a.json"]) != `{"name":"fixture"}` {
		t.Fatalf("verified rule = %q", verified.Files["rules/a.json"])
	}

	tampered := append([]byte(nil), archive...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := VerifyArchive(manifest.Sources[0], tampered); err == nil {
		t.Fatal("tampered archive must be rejected")
	}
}

func TestVerifyArchiveRejectsUnlistedAndUnsafeFiles(t *testing.T) {
	archive := fixtureArchive(t, map[string]string{"rules/a.json": "fixture", "extra.txt": "unexpected"})
	source := SourceManifest{
		SourceKey:     "fixture-source",
		RepositoryURL: "https://example.invalid/fingerprint",
		Commit:        "fixture-commit",
		ArchivePath:   "snapshots/fixture.tar.gz",
		ArchiveSHA256: sha256Hex(archive),
		Files:         []ManifestFile{{Path: "rules/a.json", SHA256: sha256Hex([]byte("fixture"))}},
	}
	if _, err := VerifyArchive(source, archive); err == nil {
		t.Fatal("archive with an unlisted file must be rejected")
	}
	source.Files[0].Path = "../rules/a.json"
	if _, err := ParseManifest([]byte(`{"sources":[{"source_key":"fixture-source","repository_url":"https://example.invalid/fingerprint","commit":"fixture-commit","archive_path":"snapshots/fixture.tar.gz","archive_sha256":"` + source.ArchiveSHA256 + `","files":[{"path":"../rules/a.json","sha256":"` + source.Files[0].SHA256 + `"}]}]}`)); err == nil {
		t.Fatal("unsafe manifest path must be rejected")
	}
}

func fixtureArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, content := range files {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatalf("write archive header: %v", err)
		}
		if _, err := tarWriter.Write([]byte(content)); err != nil {
			t.Fatalf("write archive content: %v", err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buffer.Bytes()
}
