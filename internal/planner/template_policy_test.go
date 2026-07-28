package planner

import (
	"reflect"
	"testing"
)

func TestDefaultTemplateSafetyPolicyIsConservativeAndIndependent(t *testing.T) {
	policy := DefaultTemplateSafetyPolicy()
	if !reflect.DeepEqual(policy.ExcludedTags, []string{"intrusive", "dos", "auth"}) {
		t.Fatalf("excluded tags = %v", policy.ExcludedTags)
	}
	if !reflect.DeepEqual(policy.ExcludedProtocols, []string{"code", "file"}) {
		t.Fatalf("excluded protocols = %v", policy.ExcludedProtocols)
	}
	policy.ExcludedTags[0] = "mutated"
	policy.ExcludedProtocols[0] = "mutated"
	second := DefaultTemplateSafetyPolicy()
	if second.ExcludedTags[0] == "mutated" || second.ExcludedProtocols[0] == "mutated" {
		t.Fatal("default policy must not expose mutable state")
	}
}

func TestTemplateSafetyPolicyEvaluatesTagsAndProtocolsDeterministically(t *testing.T) {
	policy := DefaultTemplateSafetyPolicy()
	decision := policy.Evaluate(TemplateMetadata{
		ID:        "unsafe",
		Tags:      []string{"AUTH", "dos", "safe"},
		Protocols: []string{"http", "CODE", "file"},
	})
	if decision.Allowed {
		t.Fatal("unsafe template was allowed")
	}
	want := []string{"excluded_protocol:code", "excluded_protocol:file", "excluded_tag:auth", "excluded_tag:dos"}
	if !reflect.DeepEqual(decision.Reasons, want) {
		t.Fatalf("reasons = %v, want %v", decision.Reasons, want)
	}
}

func TestTemplateSafetyPolicyFilterPreservesOnlyAllowedTemplatesInStableOrder(t *testing.T) {
	policy := DefaultTemplateSafetyPolicy()
	allowed, rejected := policy.Filter([]TemplateMetadata{
		{ID: "z-allowed", Path: "z.yaml", Protocols: []string{"http"}},
		{ID: "a-rejected", Path: "a.yaml", Tags: []string{"intrusive"}, Protocols: []string{"http"}},
		{ID: "m-allowed", Path: "m.yaml", Protocols: []string{"tcp"}},
	})
	if got := []string{allowed[0].ID, allowed[1].ID}; !reflect.DeepEqual(got, []string{"m-allowed", "z-allowed"}) {
		t.Fatalf("allowed IDs = %v", got)
	}
	if len(rejected) != 1 || rejected[0].Template.ID != "a-rejected" || !reflect.DeepEqual(rejected[0].Reasons, []string{"excluded_tag:intrusive"}) {
		t.Fatalf("rejected = %#v", rejected)
	}
}
