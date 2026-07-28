package planner

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBuildNucleiTemplateIndexParsesStableMetadata(t *testing.T) {
	root := t.TempDir()
	writeTemplateFile(t, root, "http/apache.yaml", `
id: apache-detect
info:
  name: Apache Detection
  severity: High
  tags: Apache, http, apache
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`)
	writeTemplateFile(t, root, "network/redis.yml", `
id: redis-detect
info:
  name: Redis Detection
  severity: medium
  tags:
    - redis
    - database, network
network:
  - inputs:
      - data: "PING\r\n"
`)

	index, err := BuildNucleiTemplateIndex(root)
	if err != nil {
		t.Fatalf("build template index: %v", err)
	}
	if len(index.Diagnostics) != 0 {
		t.Fatalf("diagnostics = %#v", index.Diagnostics)
	}
	want := []TemplateMetadata{
		{
			ID:        "apache-detect",
			Path:      "http/apache.yaml",
			Protocols: []string{"http"},
			Tags:      []string{"apache", "http"},
			Severity:  "high",
		},
		{
			ID:        "redis-detect",
			Path:      "network/redis.yml",
			Protocols: []string{"network"},
			Tags:      []string{"database", "network", "redis"},
			Severity:  "medium",
		},
	}
	if !reflect.DeepEqual(index.Templates, want) {
		t.Fatalf("templates = %#v, want %#v", index.Templates, want)
	}
}

func TestBuildNucleiTemplateIndexDiagnosesBadTemplatesWithoutDroppingValidTemplates(t *testing.T) {
	root := t.TempDir()
	writeTemplateFile(t, root, "valid.yaml", `
id: valid-template
info:
  name: Valid Template
  severity: info
dns:
  - name: "{{FQDN}}"
    type: A
`)
	writeTemplateFile(t, root, "broken.yaml", "id: [")
	writeTemplateFile(t, root, "bad-severity.yaml", `
id: bad-severity
info:
  severity: urgent
http:
  - method: GET
`)
	writeTemplateFile(t, root, "workflow.yaml", `
id: workflow-template
info:
  severity: info
workflows:
  - template: http/example.yaml
`)
	writeTemplateFile(t, root, "empty-protocol.yaml", `
id: empty-protocol
info:
  severity: low
http: []
`)

	index, err := BuildNucleiTemplateIndex(root)
	if err != nil {
		t.Fatalf("build template index: %v", err)
	}
	if !reflect.DeepEqual(index.Templates, []TemplateMetadata{{
		ID: "valid-template", Path: "valid.yaml", Protocols: []string{"dns"}, Severity: "info",
	}}) {
		t.Fatalf("valid templates = %#v", index.Templates)
	}
	for _, code := range []string{"invalid_yaml", "invalid_severity", "workflow_not_indexed", "empty_protocol"} {
		assertTemplateIndexDiagnostic(t, index.Diagnostics, code)
	}
}

func TestBuildNucleiTemplateIndexExcludesDuplicateIDs(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"first.yaml", "nested/second.yaml"} {
		writeTemplateFile(t, root, path, `
id: duplicate-template
info:
  severity: low
  tags: exposure
http:
  - method: GET
`)
	}

	index, err := BuildNucleiTemplateIndex(root)
	if err != nil {
		t.Fatalf("build template index: %v", err)
	}
	if len(index.Templates) != 0 {
		t.Fatalf("duplicate templates must be excluded: %#v", index.Templates)
	}
	count := 0
	for _, diagnostic := range index.Diagnostics {
		if diagnostic.Code == "duplicate_template_id" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("duplicate diagnostics = %d, want 2: %#v", count, index.Diagnostics)
	}
}

func TestBuildNucleiTemplateIndexRejectsInvalidRoot(t *testing.T) {
	if _, err := BuildNucleiTemplateIndex(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing template root must fail")
	}
}

func writeTemplateFile(t *testing.T, root, relativePath, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create template directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write template fixture: %v", err)
	}
}

func assertTemplateIndexDiagnostic(t *testing.T, diagnostics []TemplateIndexDiagnostic, code string) {
	t.Helper()
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == code && diagnostic.Path != "" && diagnostic.Reason != "" {
			return
		}
	}
	t.Fatalf("diagnostic %q not found in %#v", code, diagnostics)
}
