package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

func TestMaterializePinnedNucleiTemplatesUsesAuditedBytes(t *testing.T) {
	content := []byte("id: audited\n")
	digest := sha256.Sum256(content)
	snapshot, err := MaterializePinnedNucleiTemplates([]PinnedNucleiTemplate{{TemplateID: "audited", Path: "source.yaml", SHA256: hex.EncodeToString(digest[:]), Content: content}})
	if err != nil {
		t.Fatal(err)
	}
	path := snapshot.Paths[0]
	read, err := os.ReadFile(path)
	if err != nil || string(read) != string(content) {
		t.Fatalf("snapshot content=%q err=%v", read, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0400 {
		t.Fatalf("snapshot mode=%v", info.Mode().Perm())
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("snapshot path still exists: %v", err)
	}
}

func TestMaterializePinnedNucleiTemplatesRejectsHashMismatch(t *testing.T) {
	if _, err := MaterializePinnedNucleiTemplates([]PinnedNucleiTemplate{{TemplateID: "changed", Path: "changed.yaml", SHA256: "00", Content: []byte("changed")}}); err == nil {
		t.Fatal("hash mismatch must be rejected")
	}
}
