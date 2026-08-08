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
	policy.ExcludedTags[0] = "mutated"
	second := DefaultTemplateSafetyPolicy()
	if second.ExcludedTags[0] == "mutated" {
		t.Fatal("default policy must not expose mutable state")
	}
}
