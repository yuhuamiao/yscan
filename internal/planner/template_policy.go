package planner

import (
	"sort"
	"strings"
)

// TemplateSafetyPolicy is the deterministic local admission policy used
// before a Nuclei template can become a validation candidate. It deliberately
// relies only on indexed metadata so selection is reproducible offline.
type TemplateSafetyPolicy struct {
	ExcludedTags      []string
	ExcludedProtocols []string
}

// TemplatePolicyDecision records whether a template is eligible and why a
// rejected template was excluded. Reasons use stable machine-readable codes.
type TemplatePolicyDecision struct {
	Template TemplateMetadata `json:"template"`
	Allowed  bool             `json:"allowed"`
	Reasons  []string         `json:"reasons"`
}

var defaultExcludedTemplateTags = []string{"intrusive", "dos", "auth"}

var defaultExcludedTemplateProtocols = []string{"code", "file"}

// DefaultTemplateSafetyPolicy returns a copy of the product's conservative
// default. Code and file templates can execute locally or read local files,
// so they are never candidates for remote asset validation.
func DefaultTemplateSafetyPolicy() TemplateSafetyPolicy {
	return TemplateSafetyPolicy{
		ExcludedTags:      append([]string(nil), defaultExcludedTemplateTags...),
		ExcludedProtocols: append([]string(nil), defaultExcludedTemplateProtocols...),
	}
}

// Evaluate applies the policy to one indexed template. It returns all matching
// exclusion reasons in sorted order so callers can persist or render them
// without depending on source order.
func (policy TemplateSafetyPolicy) Evaluate(template TemplateMetadata) TemplatePolicyDecision {
	excludedTags := normalizedPolicyValues(policy.ExcludedTags)
	excludedProtocols := normalizedPolicyValues(policy.ExcludedProtocols)
	reasons := make([]string, 0)

	for tag := range normalizedPolicyValues(template.Tags) {
		if _, excluded := excludedTags[tag]; excluded {
			reasons = append(reasons, "excluded_tag:"+tag)
		}
	}
	for protocol := range normalizedPolicyValues(template.Protocols) {
		if _, excluded := excludedProtocols[protocol]; excluded {
			reasons = append(reasons, "excluded_protocol:"+protocol)
		}
	}
	sort.Strings(reasons)

	return TemplatePolicyDecision{
		Template: template,
		Allowed:  len(reasons) == 0,
		Reasons:  reasons,
	}
}

// Filter returns allowed templates and rejected decisions in stable metadata
// order. T232 can use the same result to explain both chosen and skipped
// candidates without reimplementing safety filtering.
func (policy TemplateSafetyPolicy) Filter(templates []TemplateMetadata) ([]TemplateMetadata, []TemplatePolicyDecision) {
	ordered := append([]TemplateMetadata(nil), templates...)
	sort.SliceStable(ordered, func(left, right int) bool {
		if ordered[left].ID != ordered[right].ID {
			return ordered[left].ID < ordered[right].ID
		}
		return ordered[left].Path < ordered[right].Path
	})

	allowed := make([]TemplateMetadata, 0, len(ordered))
	rejected := make([]TemplatePolicyDecision, 0)
	for _, template := range ordered {
		decision := policy.Evaluate(template)
		if decision.Allowed {
			allowed = append(allowed, template)
			continue
		}
		rejected = append(rejected, decision)
	}
	return allowed, rejected
}

func normalizedPolicyValues(values []string) map[string]struct{} {
	normalized := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			normalized[value] = struct{}{}
		}
	}
	return normalized
}
