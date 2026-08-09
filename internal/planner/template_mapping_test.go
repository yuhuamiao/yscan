package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"golandproject/yscan/internal/model"
)

func TestResolveReviewedTemplateCandidatesPinsContent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "http", "fixture.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	content := []byte("id: fixture\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	mapping := model.FingerprintTemplateMapping{ID: 1, ProductKey: "fixture", TemplateID: "fixture", TemplatePath: "http/fixture.yaml", TemplateSHA256: hex.EncodeToString(sum[:]), TemplateSetRevision: "r1", SideEffect: "read_only", ReviewStatus: "approved", Enabled: true}
	resolved, err := ResolveReviewedTemplateCandidates(root, []model.FingerprintTemplateMapping{mapping})
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolve = %#v, %v", resolved, err)
	}
	if err := os.WriteFile(path, []byte("id: changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := MaterializePinnedNucleiTemplates([]PinnedNucleiTemplate{resolved[0].Pinned})
	if err != nil {
		t.Fatal(err)
	}
	pinnedContent, err := os.ReadFile(snapshot.Paths[0])
	if err != nil || string(pinnedContent) != string(content) {
		t.Fatalf("pinned content changed with source: %q, %v", pinnedContent, err)
	}
	_ = snapshot.Close()
	if _, err := ResolveReviewedTemplateCandidates(root, []model.FingerprintTemplateMapping{mapping}); err == nil {
		t.Fatal("changed reviewed template must be rejected")
	}
}

func TestResolveReviewedTemplateCandidatesPinsSymlinkTargetBytes(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first.yaml")
	second := filepath.Join(root, "second.yaml")
	link := filepath.Join(root, "selected.yaml")
	content := []byte("id: first\n")
	if err := os.WriteFile(first, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("id: second\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(first, link); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	mapping := model.FingerprintTemplateMapping{ID: 2, ProductKey: "fixture", TemplateID: "first", TemplatePath: "selected.yaml", TemplateSHA256: hex.EncodeToString(digest[:]), TemplateSetRevision: "r1", SideEffect: "read_only", ReviewStatus: "approved", Enabled: true}
	resolved, err := ResolveReviewedTemplateCandidates(root, []model.FingerprintTemplateMapping{mapping})
	if err != nil || len(resolved) != 1 {
		t.Fatalf("resolve symlink=%#v err=%v", resolved, err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, link); err != nil {
		t.Fatal(err)
	}
	snapshot, err := MaterializePinnedNucleiTemplates([]PinnedNucleiTemplate{resolved[0].Pinned})
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	got, err := os.ReadFile(snapshot.Paths[0])
	if err != nil || string(got) != string(content) {
		t.Fatalf("symlink switch changed pinned content: %q, %v", got, err)
	}
}
