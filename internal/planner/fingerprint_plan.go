package planner

import (
	"sort"
	"strings"

	"golandproject/yscan/internal/model"
)

const DefaultFingerprintConfidenceThreshold = 70

// TemplateCandidate records why a concrete reviewed template was selected.
// It contains no raw fingerprint evidence and is safe to retain in a run
// snapshot or report.
type TemplateCandidate struct {
	TemplateID        string `json:"template_id"`
	Path              string `json:"path"`
	Source            string `json:"source"`
	FingerprintRule   string `json:"fingerprint_rule_id"`
	FingerprintSource string `json:"fingerprint_source_id"`
	Product           string `json:"product"`
	Confidence        int    `json:"confidence"`
}

// PlanFingerprintCandidates selects templates only for high-confidence,
// protocol-compatible product fingerprints. It never returns a catch-all
// candidate: a template must explicitly carry a product identity tag.
func PlanFingerprintCandidates(fingerprints []model.AssetFingerprint, index TemplateIndex, policy TemplateSafetyPolicy, minimumConfidence int) []TemplateCandidate {
	if minimumConfidence <= 0 {
		minimumConfidence = DefaultFingerprintConfidenceThreshold
	}
	allowed, _ := policy.Filter(index.Templates)
	candidates := make(map[string]TemplateCandidate)
	for _, fingerprint := range fingerprints {
		if fingerprint.Confidence < minimumConfidence {
			continue
		}
		terms := fingerprintTerms(fingerprint)
		if len(terms) == 0 {
			continue
		}
		for _, template := range allowed {
			if !templateSupportsFingerprintProtocol(template, fingerprint.Protocol) || !templateMatchesTerms(template, terms) {
				continue
			}
			candidate := TemplateCandidate{
				TemplateID: template.ID, Path: template.Path, Source: "fingerprint",
				FingerprintRule: fingerprint.RuleID, FingerprintSource: fingerprint.SourceID,
				Product: fingerprint.Product, Confidence: fingerprint.Confidence,
			}
			key := template.ID + "\x00" + template.Path
			if current, exists := candidates[key]; !exists || candidate.confidenceOrderBefore(current) {
				candidates[key] = candidate
			}
		}
	}
	result := make([]TemplateCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		result = append(result, candidate)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].TemplateID != result[j].TemplateID {
			return result[i].TemplateID < result[j].TemplateID
		}
		return result[i].Path < result[j].Path
	})
	return result
}

func (candidate TemplateCandidate) confidenceOrderBefore(other TemplateCandidate) bool {
	if candidate.Confidence != other.Confidence {
		return candidate.Confidence > other.Confidence
	}
	if candidate.FingerprintRule != other.FingerprintRule {
		return candidate.FingerprintRule < other.FingerprintRule
	}
	return candidate.FingerprintSource < other.FingerprintSource
}

func fingerprintTerms(fingerprint model.AssetFingerprint) map[string]struct{} {
	terms := make(map[string]struct{})
	for _, value := range []string{fingerprint.Vendor, fingerprint.Product} {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			terms[value] = struct{}{}
		}
	}
	parts := strings.Split(strings.ToLower(strings.TrimSpace(fingerprint.CPE)), ":")
	if len(parts) >= 5 && parts[4] != "" && parts[4] != "*" {
		terms[parts[4]] = struct{}{}
	}
	return terms
}

func templateMatchesTerms(template TemplateMetadata, terms map[string]struct{}) bool {
	for _, tag := range template.Tags {
		if _, ok := terms[strings.ToLower(strings.TrimSpace(tag))]; ok {
			return true
		}
	}
	return false
}

func templateSupportsFingerprintProtocol(template TemplateMetadata, protocol string) bool {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	for _, value := range template.Protocols {
		value = strings.ToLower(strings.TrimSpace(value))
		if (protocol == "http" || protocol == "https") && value == "http" {
			return true
		}
		if (protocol == "tcp" || protocol == "tls") && (value == "network" || value == "tcp" || value == "ssl") {
			return true
		}
	}
	return false
}
