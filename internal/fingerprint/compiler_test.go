package fingerprint

import (
	"reflect"
	"testing"
)

func TestCompileRulesIsDeterministicAndDeduplicatesExactRules(t *testing.T) {
	nginx := validRule()
	apache := validRule()
	apache.ID = "fingerprinthub/apache"
	apache.Product = ProductIdentity{Vendor: "apache", Name: "httpd"}
	apache.Matchers[0].Pattern = "apache"

	first, err := CompileRules([]Rule{nginx, apache, nginx})
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	second, err := CompileRules([]Rule{nginx, apache, nginx})
	if err != nil {
		t.Fatalf("compile same rules: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("same input compiled differently:\nfirst: %#v\nsecond: %#v", first, second)
	}
	if len(first.Rules) != 2 || len(first.Conflicts) != 0 {
		t.Fatalf("compilation = %#v", first)
	}
	if first.Rules[0].ID != "fingerprinthub/apache" || first.Rules[1].ID != "fingerprinthub/nginx" {
		t.Fatalf("compiled rule order = %#v", first.Rules)
	}
}

func TestCompileRulesKeepsConflictingSourcesForReview(t *testing.T) {
	left := validRule()
	left.ID = "shared/web-server"
	left.SourceID = "source-a"
	right := validRule()
	right.ID = left.ID
	right.SourceID = "source-b"
	right.Product.Name = "other-server"

	result, err := CompileRules([]Rule{right, left})
	if err != nil {
		t.Fatalf("compile conflicting rules: %v", err)
	}
	if len(result.Rules) != 0 || len(result.Conflicts) != 1 {
		t.Fatalf("compilation = %#v", result)
	}
	conflict := result.Conflicts[0]
	if conflict.ID != "shared/web-server" || len(conflict.Candidates) != 2 {
		t.Fatalf("conflict = %#v", conflict)
	}
	if conflict.Candidates[0].SourceID != "source-a" || conflict.Candidates[1].SourceID != "source-b" {
		t.Fatalf("conflict sources were not preserved: %#v", conflict.Candidates)
	}
}

func TestCompileRulesRejectsInvalidRules(t *testing.T) {
	rule := validRule()
	rule.Matchers[1].Pattern = "(invalid"
	if _, err := CompileRules([]Rule{rule}); err == nil {
		t.Fatal("invalid rule must prevent compilation")
	}
}
