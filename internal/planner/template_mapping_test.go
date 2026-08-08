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
	if _, err := ResolveReviewedTemplateCandidates(root, []model.FingerprintTemplateMapping{mapping}); err == nil {
		t.Fatal("changed reviewed template must be rejected")
	}
}
