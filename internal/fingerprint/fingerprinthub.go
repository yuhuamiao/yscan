package fingerprint

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseDiagnostic explains a source construct that was intentionally skipped
// because the normalized rule model cannot represent it without weakening its
// meaning. Diagnostics are sorted before return for reproducible imports.
type ParseDiagnostic struct {
	DocumentID string `json:"document_id"`
	Path       string `json:"path"`
	Code       string `json:"code"`
	Reason     string `json:"reason"`
}

// ParseResult contains the valid normalized rules and all non-fatal import
// diagnostics. A malformed YAML document is returned as an error because its
// contents cannot be audited safely.
type ParseResult struct {
	Rules       []Rule            `json:"rules"`
	Diagnostics []ParseDiagnostic `json:"diagnostics"`
}

// ParseFingerprintHubSnapshot converts a checked-in FingerprintHub YAML
// snapshot into source-independent rules. It intentionally supports only
// response evidence: HTTP word/regex/favicon matchers and TCP regex
// extractors. Unsupported active probes, negative matching and protocol
// semantics are reported instead of being silently approximated.
func ParseFingerprintHubSnapshot(sourceID string, data []byte) (ParseResult, error) {
	sourceID = strings.ToLower(strings.TrimSpace(sourceID))
	if !sourceIDPattern.MatchString(sourceID) {
		return ParseResult{}, fmt.Errorf("invalid FingerprintHub source id: %q", sourceID)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	result := ParseResult{}
	for documentIndex := 0; ; documentIndex++ {
		var document fingerprintHubDocument
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			return ParseResult{}, fmt.Errorf("decode FingerprintHub YAML document %d: %w", documentIndex, err)
		}
		if document.empty() {
			continue
		}
		parseFingerprintHubDocument(&result, sourceID, document)
	}

	sort.Slice(result.Rules, func(left, right int) bool {
		return result.Rules[left].ID < result.Rules[right].ID
	})
	sort.Slice(result.Diagnostics, func(left, right int) bool {
		leftDiagnostic := result.Diagnostics[left]
		rightDiagnostic := result.Diagnostics[right]
		if leftDiagnostic.DocumentID != rightDiagnostic.DocumentID {
			return leftDiagnostic.DocumentID < rightDiagnostic.DocumentID
		}
		if leftDiagnostic.Path != rightDiagnostic.Path {
			return leftDiagnostic.Path < rightDiagnostic.Path
		}
		if leftDiagnostic.Code != rightDiagnostic.Code {
			return leftDiagnostic.Code < rightDiagnostic.Code
		}
		return leftDiagnostic.Reason < rightDiagnostic.Reason
	})
	return result, nil
}

func parseFingerprintHubDocument(result *ParseResult, sourceID string, document fingerprintHubDocument) {
	documentID := strings.ToLower(strings.TrimSpace(document.ID))
	if !ruleIDPattern.MatchString(documentID) {
		result.addDiagnostic(document.ID, "id", "invalid_rule_id", "FingerprintHub rule IDs must be valid normalized rule IDs")
		return
	}
	product, ok := fingerprintHubProduct(result, documentID, document)
	if !ok {
		return
	}
	parsedRule := false
	for requestIndex, request := range document.HTTP {
		if !fingerprintHubHTTPSupported(result, documentID, requestIndex, request) {
			continue
		}
		for matcherIndex, matcher := range request.Matchers {
			rule, ok := fingerprintHubHTTPRule(result, sourceID, documentID, product, requestIndex, matcherIndex, matcher)
			if ok {
				result.addRule(documentID, rule)
				parsedRule = true
			}
		}
	}
	for probeIndex, probe := range document.TCP {
		if len(probe.Inputs) > 0 {
			result.addDiagnostic(documentID, fmt.Sprintf("tcp[%d].inputs", probeIndex), "unsupported_tcp_probe", "active TCP probe payloads are not represented by the local response-evidence rule model")
		}
		if strings.TrimSpace(probe.Port) != "" {
			result.addDiagnostic(documentID, fmt.Sprintf("tcp[%d].port", probeIndex), "unsupported_tcp_port_filter", "TCP port filters are not represented by the normalized rule model")
		}
		for extractorIndex, extractor := range probe.Extractors {
			rule, ok := fingerprintHubTCPRule(result, sourceID, documentID, product, probeIndex, extractorIndex, extractor)
			if ok {
				result.addRule(documentID, rule)
				parsedRule = true
			}
		}
	}
	if !parsedRule {
		result.addDiagnostic(documentID, "", "no_supported_evidence", "rule has no safely representable HTTP matcher or TCP regex extractor")
	}
}

func fingerprintHubProduct(result *ParseResult, documentID string, document fingerprintHubDocument) (ProductIdentity, bool) {
	product := ProductIdentity{
		Name: documentID,
	}
	if name, present := metadataString(result, documentID, "info.metadata.product", document.Info.Metadata["product"]); present {
		product.Name = name
	} else if strings.TrimSpace(document.Info.Name) != "" {
		product.Name = document.Info.Name
	}
	if vendor, present := metadataString(result, documentID, "info.metadata.vendor", document.Info.Metadata["vendor"]); present {
		product.Vendor = vendor
	}
	if version, present := metadataString(result, documentID, "info.metadata.version", document.Info.Metadata["version"]); present {
		if strings.Contains(version, "{{") || strings.Contains(version, "$P(") {
			result.addDiagnostic(documentID, "info.metadata.version", "unsupported_dynamic_version", "dynamic version extraction is not represented by the normalized rule model")
		} else {
			product.Version = version
		}
	}
	if cpe, present := metadataString(result, documentID, "info.metadata.cpe", document.Info.Metadata["cpe"]); present {
		product.CPE = cpe
		if err := product.Validate(); err != nil {
			product.CPE = ""
			result.addDiagnostic(documentID, "info.metadata.cpe", "unsupported_cpe", "only complete CPE 2.3 values are accepted by the normalized rule model")
		}
	}
	if err := product.Validate(); err != nil {
		result.addDiagnostic(documentID, "info", "invalid_product", err.Error())
		return ProductIdentity{}, false
	}
	return product, true
}

func metadataString(result *ParseResult, documentID, path string, value interface{}) (string, bool) {
	if value == nil {
		return "", false
	}
	text, ok := value.(string)
	if !ok {
		result.addDiagnostic(documentID, path, "unsupported_metadata_value", "metadata value must be a string")
		return "", false
	}
	return strings.TrimSpace(text), true
}

func fingerprintHubHTTPSupported(result *ParseResult, documentID string, requestIndex int, request fingerprintHubHTTP) bool {
	pathPrefix := fmt.Sprintf("http[%d]", requestIndex)
	method := strings.ToUpper(strings.TrimSpace(request.Method))
	if method != "" && method != "GET" {
		result.addDiagnostic(documentID, pathPrefix+".method", "unsupported_http_method", "only GET response evidence is represented by the normalized rule model")
		return false
	}
	if request.MatchersCondition != "" {
		result.addDiagnostic(documentID, pathPrefix+".matchers-condition", "unsupported_matchers_condition", "cross-matcher conditions are not represented by the normalized rule model")
		return false
	}
	for _, requestPath := range request.Path {
		requestPath = strings.TrimSpace(requestPath)
		if requestPath != "" && requestPath != "{{BaseURL}}/" && requestPath != "/" {
			result.addDiagnostic(documentID, pathPrefix+".path", "unsupported_http_path", "only base URL response evidence is represented by the normalized rule model")
			return false
		}
	}
	return true
}

func fingerprintHubHTTPRule(result *ParseResult, sourceID, documentID string, product ProductIdentity, requestIndex, matcherIndex int, matcher fingerprintHubMatcher) (Rule, bool) {
	path := fmt.Sprintf("http[%d].matchers[%d]", requestIndex, matcherIndex)
	if matcher.Negative {
		result.addDiagnostic(documentID, path+".negative", "unsupported_negative_matcher", "negative matchers are not represented by the normalized rule model")
		return Rule{}, false
	}

	matchMode, ok := fingerprintHubMatchMode(result, documentID, path+".condition", matcher.Condition)
	if !ok {
		return Rule{}, false
	}
	rule := Rule{
		ID:       fmt.Sprintf("%s/%s/http-%d/matcher-%d", sourceID, documentID, requestIndex, matcherIndex),
		SourceID: sourceID,
		Product:  product,
		Protocols: []Protocol{
			ProtocolHTTP,
			ProtocolHTTPS,
		},
		MatchMode: matchMode,
	}

	switch strings.ToLower(strings.TrimSpace(matcher.Type)) {
	case "word", "regex":
		target, ok := fingerprintHubTarget(result, documentID, path+".part", matcher.Part)
		if !ok {
			return Rule{}, false
		}
		operator := MatchContains
		patterns := matcher.Words
		if strings.EqualFold(strings.TrimSpace(matcher.Type), "regex") {
			operator = MatchRegex
			patterns = matcher.Regex
		}
		for _, pattern := range patterns {
			if strings.TrimSpace(pattern) == "" {
				result.addDiagnostic(documentID, path, "empty_match_pattern", "empty source patterns are ignored")
				continue
			}
			rule.Matchers = append(rule.Matchers, Matcher{
				Target:          target,
				Operator:        operator,
				Pattern:         pattern,
				CaseInsensitive: matcher.CaseInsensitive,
			})
		}
	case "favicon":
		for _, hash := range matcher.Hash {
			algorithm, ok := fingerprintHubFaviconAlgorithm(hash)
			if !ok {
				result.addDiagnostic(documentID, path+".hash", "unsupported_favicon_hash", "only MD5, MMH3 and SHA-256 favicon hashes are supported")
				continue
			}
			rule.Matchers = append(rule.Matchers, Matcher{
				Target:        EvidenceFaviconHash,
				Operator:      MatchEquals,
				Pattern:       hash,
				HashAlgorithm: algorithm,
			})
		}
	default:
		result.addDiagnostic(documentID, path+".type", "unsupported_http_matcher", "only word, regex and favicon HTTP matchers are supported")
		return Rule{}, false
	}
	if len(rule.Matchers) == 0 {
		result.addDiagnostic(documentID, path, "empty_matcher", "matcher has no supported patterns")
		return Rule{}, false
	}
	return rule, true
}

func fingerprintHubTCPRule(result *ParseResult, sourceID, documentID string, product ProductIdentity, probeIndex, extractorIndex int, extractor fingerprintHubExtractor) (Rule, bool) {
	path := fmt.Sprintf("tcp[%d].extractors[%d]", probeIndex, extractorIndex)
	if !strings.EqualFold(strings.TrimSpace(extractor.Type), "regex") {
		result.addDiagnostic(documentID, path+".type", "unsupported_tcp_extractor", "only regex TCP extractors are supported")
		return Rule{}, false
	}
	rule := Rule{
		ID:        fmt.Sprintf("%s/%s/tcp-%d/extractor-%d", sourceID, documentID, probeIndex, extractorIndex),
		SourceID:  sourceID,
		Product:   product,
		Protocols: []Protocol{ProtocolTCP},
		MatchMode: MatchAny,
	}
	for _, pattern := range extractor.Regex {
		if strings.TrimSpace(pattern) == "" {
			result.addDiagnostic(documentID, path+".regex", "empty_match_pattern", "empty source patterns are ignored")
			continue
		}
		rule.Matchers = append(rule.Matchers, Matcher{Target: EvidenceBanner, Operator: MatchRegex, Pattern: pattern})
	}
	if len(rule.Matchers) == 0 {
		result.addDiagnostic(documentID, path, "empty_extractor", "regex extractor has no supported patterns")
		return Rule{}, false
	}
	return rule, true
}

func fingerprintHubMatchMode(result *ParseResult, documentID, path, condition string) (MatchMode, bool) {
	switch strings.ToLower(strings.TrimSpace(condition)) {
	case "", "or":
		return MatchAny, true
	case "and":
		return MatchAll, true
	default:
		result.addDiagnostic(documentID, path, "unsupported_matcher_condition", "matcher condition must be and or or")
		return "", false
	}
}

func fingerprintHubTarget(result *ParseResult, documentID, path, part string) (EvidenceTarget, bool) {
	switch strings.ToLower(strings.TrimSpace(part)) {
	case "", "body":
		return EvidenceBody, true
	case "header":
		return EvidenceHeader, true
	default:
		result.addDiagnostic(documentID, path, "unsupported_http_part", "only response body and header matchers are supported")
		return "", false
	}
}

func fingerprintHubFaviconAlgorithm(hash string) (FaviconHashAlgorithm, bool) {
	if validFaviconHash(FaviconHashMD5, hash) {
		return FaviconHashMD5, true
	}
	if validFaviconHash(FaviconHashMMH3, hash) {
		return FaviconHashMMH3, true
	}
	if validFaviconHash(FaviconHashSHA256, hash) {
		return FaviconHashSHA256, true
	}
	return "", false
}

func (result *ParseResult) addRule(documentID string, rule Rule) {
	if err := rule.Validate(); err != nil {
		result.addDiagnostic(documentID, "", "invalid_normalized_rule", err.Error())
		return
	}
	result.Rules = append(result.Rules, rule)
}

func (result *ParseResult) addDiagnostic(documentID, path, code, reason string) {
	result.Diagnostics = append(result.Diagnostics, ParseDiagnostic{
		DocumentID: strings.ToLower(strings.TrimSpace(documentID)),
		Path:       path,
		Code:       code,
		Reason:     reason,
	})
}

type fingerprintHubDocument struct {
	ID   string               `yaml:"id"`
	Info fingerprintHubInfo   `yaml:"info"`
	HTTP []fingerprintHubHTTP `yaml:"http"`
	TCP  []fingerprintHubTCP  `yaml:"tcp"`
}

func (document fingerprintHubDocument) empty() bool {
	return document.ID == "" && len(document.HTTP) == 0 && len(document.TCP) == 0
}

type fingerprintHubInfo struct {
	Name     string                 `yaml:"name"`
	Metadata map[string]interface{} `yaml:"metadata"`
}

type fingerprintHubHTTP struct {
	Method            string                  `yaml:"method"`
	Path              []string                `yaml:"path"`
	Matchers          []fingerprintHubMatcher `yaml:"matchers"`
	MatchersCondition string                  `yaml:"matchers-condition"`
}

type fingerprintHubTCP struct {
	Inputs     []fingerprintHubInput     `yaml:"inputs"`
	Port       string                    `yaml:"port"`
	Extractors []fingerprintHubExtractor `yaml:"extractors"`
}

type fingerprintHubInput struct {
	Data string `yaml:"data"`
}

type fingerprintHubMatcher struct {
	Type            string   `yaml:"type"`
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Hash            []string `yaml:"hash"`
	Part            string   `yaml:"part"`
	Condition       string   `yaml:"condition"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
	Negative        bool     `yaml:"negative"`
}

type fingerprintHubExtractor struct {
	Type  string   `yaml:"type"`
	Regex []string `yaml:"regex"`
}
