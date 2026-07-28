package fingerprint

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"golandproject/yscan/internal/model"
)

// ServiceEvidence is the bounded observation set for one network service.
// HeaderText and Body must be obtained through the bounded HTTP collector;
// Banner is supplied by the existing TCP service identification stage.
type ServiceEvidence struct {
	Protocol   Protocol        `json:"protocol"`
	Headers    http.Header     `json:"headers,omitempty"`
	HeaderText string          `json:"header_text,omitempty"`
	Body       string          `json:"body,omitempty"`
	Banner     string          `json:"banner,omitempty"`
	Favicon    FaviconEvidence `json:"favicon,omitempty"`
}

// MatchEvidence records a rule condition that matched without retaining a raw
// response fragment. Summary is suitable for persistence and reports.
type MatchEvidence struct {
	Target     EvidenceTarget `json:"target"`
	HeaderName string         `json:"header_name,omitempty"`
	Operator   MatchOperator  `json:"operator"`
	Pattern    string         `json:"pattern"`
	Summary    string         `json:"summary"`
}

// FingerprintMatch is one explainable product conclusion. Confidence is an
// integer in [0, 100] derived only from independently matched evidence types.
type FingerprintMatch struct {
	RuleID     string          `json:"rule_id"`
	SourceID   string          `json:"source_id"`
	Product    ProductIdentity `json:"product"`
	Protocol   Protocol        `json:"protocol"`
	Confidence int             `json:"confidence"`
	Evidence   []MatchEvidence `json:"evidence"`
}

// ToAssetFingerprint converts an explainable match into the persistence model
// used by T213. The caller supplies the concrete service address and port so
// this package remains independent of storage concerns.
func (match FingerprintMatch) ToAssetFingerprint(ip string, port int) (model.AssetFingerprint, error) {
	evidence := make([]model.FingerprintEvidence, 0, len(match.Evidence))
	for _, hit := range match.Evidence {
		evidence = append(evidence, model.FingerprintEvidence{
			Target:     string(hit.Target),
			HeaderName: hit.HeaderName,
			Operator:   string(hit.Operator),
			Pattern:    hit.Pattern,
			Summary:    hit.Summary,
		})
	}
	fingerprint := model.AssetFingerprint{
		IP:         ip,
		Port:       port,
		Protocol:   string(match.Protocol),
		RuleID:     match.RuleID,
		SourceID:   match.SourceID,
		Vendor:     match.Product.Vendor,
		Product:    match.Product.Name,
		Version:    match.Product.Version,
		CPE:        match.Product.CPE,
		Confidence: match.Confidence,
		Evidence:   evidence,
	}
	if !fingerprint.Valid() {
		return model.AssetFingerprint{}, errors.New("invalid fingerprint match persistence record")
	}
	return fingerprint, nil
}

// MatchRules evaluates validated, compiled rules against one service evidence
// set. Rules with an incompatible protocol are ignored. The result order is
// deterministic: higher confidence first, then rule ID and source ID.
func MatchRules(rules []Rule, evidence ServiceEvidence) ([]FingerprintMatch, error) {
	if !validEvidenceProtocol(evidence.Protocol) {
		return nil, fmt.Errorf("unsupported evidence protocol: %s", evidence.Protocol)
	}

	matchedRules := make([]FingerprintMatch, 0, len(rules))
	for index, candidate := range rules {
		rule := cloneRule(candidate)
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("validate rule %d: %w", index, err)
		}
		if !ruleSupportsProtocol(rule, evidence.Protocol) {
			continue
		}
		match, ok, err := matchRule(rule, evidence)
		if err != nil {
			return nil, fmt.Errorf("match rule %s: %w", rule.ID, err)
		}
		if ok {
			matchedRules = append(matchedRules, match)
		}
	}

	sort.Slice(matchedRules, func(left, right int) bool {
		if matchedRules[left].Confidence != matchedRules[right].Confidence {
			return matchedRules[left].Confidence > matchedRules[right].Confidence
		}
		if matchedRules[left].RuleID != matchedRules[right].RuleID {
			return matchedRules[left].RuleID < matchedRules[right].RuleID
		}
		return matchedRules[left].SourceID < matchedRules[right].SourceID
	})
	return matchedRules, nil
}

func validEvidenceProtocol(protocol Protocol) bool {
	return protocol == ProtocolHTTP || protocol == ProtocolHTTPS || protocol == ProtocolTCP || protocol == ProtocolTLS
}

func ruleSupportsProtocol(rule Rule, protocol Protocol) bool {
	for _, supported := range rule.Protocols {
		if supported == protocol {
			return true
		}
	}
	return false
}

func matchRule(rule Rule, evidence ServiceEvidence) (FingerprintMatch, bool, error) {
	hits := make([]MatchEvidence, 0, len(rule.Matchers))
	for _, matcher := range rule.Matchers {
		hit, err := matcherMatches(matcher, evidence)
		if err != nil {
			return FingerprintMatch{}, false, err
		}
		if hit {
			hits = append(hits, MatchEvidence{
				Target:     matcher.Target,
				HeaderName: matcher.HeaderName,
				Operator:   matcher.Operator,
				Pattern:    matcher.Pattern,
				Summary:    matchSummary(matcher),
			})
		}
	}

	if (rule.MatchMode == MatchAll && len(hits) != len(rule.Matchers)) || (rule.MatchMode == MatchAny && len(hits) == 0) {
		return FingerprintMatch{}, false, nil
	}
	return FingerprintMatch{
		RuleID:     rule.ID,
		SourceID:   rule.SourceID,
		Product:    rule.Product,
		Protocol:   evidence.Protocol,
		Confidence: confidenceFor(rule.MatchMode, hits),
		Evidence:   hits,
	}, true, nil
}

func matcherMatches(matcher Matcher, evidence ServiceEvidence) (bool, error) {
	switch matcher.Target {
	case EvidenceHeader:
		if matcher.HeaderName == "" {
			return textMatches(matcher, evidence.HeaderText)
		}
		for _, value := range evidence.Headers.Values(matcher.HeaderName) {
			matched, err := textMatches(matcher, value)
			if err != nil || matched {
				return matched, err
			}
		}
		return false, nil
	case EvidenceBody:
		return textMatches(matcher, evidence.Body)
	case EvidenceBanner:
		return textMatches(matcher, evidence.Banner)
	case EvidenceFaviconHash:
		if evidence.Favicon.Status != FaviconAvailable {
			return false, nil
		}
		return textMatches(matcher, faviconHash(evidence.Favicon, matcher.HashAlgorithm))
	default:
		return false, errors.New("unsupported matcher target")
	}
}

func faviconHash(evidence FaviconEvidence, algorithm FaviconHashAlgorithm) string {
	switch algorithm {
	case FaviconHashMD5:
		return evidence.MD5
	case FaviconHashMMH3:
		return evidence.MMH3
	case FaviconHashSHA256:
		return evidence.SHA256
	default:
		return ""
	}
}

func textMatches(matcher Matcher, observed string) (bool, error) {
	switch matcher.Operator {
	case MatchContains:
		if matcher.CaseInsensitive {
			return strings.Contains(strings.ToLower(observed), strings.ToLower(matcher.Pattern)), nil
		}
		return strings.Contains(observed, matcher.Pattern), nil
	case MatchEquals:
		if matcher.CaseInsensitive {
			return strings.EqualFold(observed, matcher.Pattern), nil
		}
		return observed == matcher.Pattern, nil
	case MatchRegex:
		pattern := matcher.Pattern
		if matcher.CaseInsensitive {
			pattern = "(?i)" + pattern
		}
		expression, err := regexp.Compile(pattern)
		if err != nil {
			return false, err
		}
		return expression.MatchString(observed), nil
	default:
		return false, errors.New("unsupported matcher operator")
	}
}

func matchSummary(matcher Matcher) string {
	target := string(matcher.Target)
	if matcher.Target == EvidenceHeader && matcher.HeaderName != "" {
		target += " " + matcher.HeaderName
	}
	return fmt.Sprintf("%s %s %q", target, matcher.Operator, matcher.Pattern)
}

func confidenceFor(mode MatchMode, evidence []MatchEvidence) int {
	weights := map[EvidenceTarget]int{
		EvidenceHeader:      20,
		EvidenceBody:        20,
		EvidenceBanner:      35,
		EvidenceFaviconHash: 35,
	}
	uniqueTargets := make(map[EvidenceTarget]struct{}, len(evidence))
	confidence := 35
	for _, hit := range evidence {
		if _, exists := uniqueTargets[hit.Target]; exists {
			continue
		}
		uniqueTargets[hit.Target] = struct{}{}
		confidence += weights[hit.Target]
	}
	if mode == MatchAll && len(uniqueTargets) > 1 {
		confidence += 5
	}
	if confidence > 95 {
		return 95
	}
	return confidence
}
