package planner

import (
	"reflect"
	"testing"

	"golandproject/yscan/internal/model"
)

func TestPlanFingerprintCandidatesUsesHighConfidenceProductAndSafeProtocol(t *testing.T) {
	index := TemplateIndex{Templates: []TemplateMetadata{
		{ID: "redis-safe", Path: "redis.yaml", Tags: []string{"redis"}, Protocols: []string{"network"}},
		{ID: "redis-code", Path: "code.yaml", Tags: []string{"redis"}, Protocols: []string{"code"}},
		{ID: "nginx", Path: "nginx.yaml", Tags: []string{"nginx"}, Protocols: []string{"http"}},
	}}
	fingerprints := []model.AssetFingerprint{
		{Protocol: "tcp", Product: "redis", RuleID: "redis-banner", SourceID: "fingerprinthub", Confidence: 90},
		{Protocol: "https", Product: "nginx", RuleID: "nginx-header", SourceID: "fingerprinthub", Confidence: 60},
	}
	got := PlanFingerprintCandidates(fingerprints, index, DefaultTemplateSafetyPolicy(), 70)
	want := []TemplateCandidate{{TemplateID: "redis-safe", Path: "redis.yaml", Source: "fingerprint", FingerprintRule: "redis-banner", FingerprintSource: "fingerprinthub", Product: "redis", Confidence: 90}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %#v, want %#v", got, want)
	}
}

func TestPlanFingerprintCandidatesNeverCreatesUnknownOrCatchAllPlan(t *testing.T) {
	index := TemplateIndex{Templates: []TemplateMetadata{{ID: "generic-http", Path: "http.yaml", Tags: []string{"http", "misconfiguration"}, Protocols: []string{"http"}}}}
	got := PlanFingerprintCandidates([]model.AssetFingerprint{{Protocol: "http", Product: "unknown", RuleID: "unknown", SourceID: "source", Confidence: 95}}, index, DefaultTemplateSafetyPolicy(), 70)
	if len(got) != 0 {
		t.Fatalf("unknown product candidates = %#v", got)
	}
}
