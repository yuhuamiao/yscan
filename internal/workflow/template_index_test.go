package workflow

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golandproject/yscan/internal/planner"
	"golandproject/yscan/internal/storage"
)

type workflowTemplateSpec struct {
	id, product, protocol string
}

func openFullWorkflowDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := storage.InitDBAt(filepath.Join(t.TempDir(), "workflow.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func workflowTemplateIndexFixture(t *testing.T, specs ...workflowTemplateSpec) (string, *planner.NucleiTemplateIndex) {
	t.Helper()
	root := t.TempDir()
	for _, spec := range specs {
		request := "http:\n  - method: GET\n    path: [\"{{BaseURL}}\"]"
		if spec.protocol == "tcp" {
			request = "tcp:\n  - inputs:\n      - data: \"info\\r\\nquit\\r\\n\""
		}
		content := fmt.Sprintf("id: %s\ninfo:\n  name: %s\n  severity: high\n  metadata: {product: %s}\n  tags: %s,config,vuln\n%s\n", spec.id, spec.id, spec.product, spec.product, request)
		path := filepath.Join(root, spec.id+".yaml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	index, err := planner.BuildNucleiTemplateIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Templates) != len(specs) {
		t.Fatalf("strict template fixture projected %d/%d entries", len(index.Templates), len(specs))
	}
	return root, index
}
