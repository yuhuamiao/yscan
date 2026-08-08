package fingerprint

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golandproject/yscan/internal/model"
)

const ProductNormalizationRevision = "product-normalization-v1"

var productAliasesV1 = map[string]string{
	"apache":             "apache http server",
	"apache http server": "apache http server",
	"apache httpd":       "apache http server",
	"httpd":              "apache http server",
}

func projectExecutableRules(adapter SourceAdapter, rules []model.FingerprintSourceRule) ([]model.FingerprintRuleProjection, error) {
	projections := make([]model.FingerprintRuleProjection, 0)
	for index, rule := range rules {
		if rule.ImportStatus != "executable" {
			continue
		}
		projection, err := adapter.Project(rule)
		if err != nil {
			return nil, fmt.Errorf("project executable rule %s at %d: %w", rule.SourcePath, index, err)
		}
		projection.SourcePath = rule.SourcePath
		projection.ContentSHA256 = rule.ContentSHA256
		projection.SourceProduct = strings.TrimSpace(projection.Product.CanonicalName)
		projection.Product = normalizedProduct(projection.Product)
		projection.Protocol = strings.ToLower(strings.TrimSpace(projection.Protocol))
		projection.Tags = normalizedTags(projection.Tags)
		if projection.Product.Role == "" {
			projection.Product.Role, projection.Product.ExclusiveGroup = model.FingerprintProductClassification(projection.Product.CanonicalName, projection.Tags)
		}
		if projection.Product.CanonicalName == "" || projection.Protocol == "" || !validProjectedGroup(projection.Root) {
			return nil, fmt.Errorf("projected rule %s is incomplete", rule.SourcePath)
		}
		projections = append(projections, projection)
	}
	return projections, nil
}

func normalizedProduct(product model.FingerprintProduct) model.FingerprintProduct {
	original := strings.TrimSpace(product.CanonicalName)
	normalized := strings.ToLower(original)
	if canonical := productAliasesV1[normalized]; canonical != "" {
		normalized = canonical
	}
	product.CanonicalName = normalized
	product.Vendor = strings.ToLower(strings.TrimSpace(product.Vendor))
	product.CPE = strings.TrimSpace(product.CPE)
	aliases := normalizedProductAliases(product.AliasesJSON, original, product.CanonicalName)
	encoded, _ := json.Marshal(aliases)
	product.AliasesJSON = string(encoded)
	return product
}

func normalizedProductAliases(encoded, original, canonical string) []string {
	values := make([]string, 0)
	_ = json.Unmarshal([]byte(encoded), &values)
	if original != "" && !strings.EqualFold(original, canonical) {
		values = append(values, original)
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		key := strings.ToLower(value)
		if value == "" || key == canonical {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return strings.ToLower(result[i]) < strings.ToLower(result[j]) })
	return result
}

func normalizedTags(tags []string) []string {
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "" {
			continue
		}
		if _, exists := seen[tag]; exists {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func validProjectedGroup(group model.FingerprintMatchGroupProjection) bool {
	if group.Operator != "all" && group.Operator != "any" {
		return false
	}
	if len(group.Matchers) == 0 && len(group.Children) == 0 {
		return false
	}
	for _, matcher := range group.Matchers {
		if strings.TrimSpace(matcher.EvidenceType) == "" || strings.TrimSpace(matcher.Operator) == "" || matcher.Value == "" {
			return false
		}
	}
	for _, child := range group.Children {
		if !validProjectedGroup(child) {
			return false
		}
	}
	return true
}

func matcher(evidenceType, target, operator, value string) model.FingerprintMatcher {
	return model.FingerprintMatcher{EvidenceType: evidenceType, Target: target, Operator: operator, Value: value}
}

func (fingerprintHubV3Adapter) Project(source model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	var rule struct {
		Name        string            `json:"name"`
		StatusCode  int               `json:"status_code"`
		Headers     map[string]string `json:"headers"`
		Keyword     []string          `json:"keyword"`
		FaviconHash []string          `json:"favicon_hash"`
	}
	if err := json.Unmarshal([]byte(source.RawContent), &rule); err != nil {
		return model.FingerprintRuleProjection{}, err
	}
	root := model.FingerprintMatchGroupProjection{Operator: "all"}
	if rule.StatusCode != 0 {
		root.Matchers = append(root.Matchers, matcher("status_code", "status", "equals", strconv.Itoa(rule.StatusCode)))
	}
	keys := make([]string, 0, len(rule.Headers))
	for key := range rule.Headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		root.Matchers = append(root.Matchers, matcher("http_header", strings.ToLower(key), "contains_ci", rule.Headers[key]))
	}
	for _, value := range rule.Keyword {
		root.Matchers = append(root.Matchers, matcher("http_body", "body", "contains_ci", value))
	}
	if len(rule.FaviconHash) > 0 {
		child := model.FingerprintMatchGroupProjection{Operator: "any"}
		for _, value := range rule.FaviconHash {
			algorithm, normalized, err := normalizeFaviconHash(value)
			if err != nil {
				return model.FingerprintRuleProjection{}, err
			}
			child.Matchers = append(child.Matchers, matcher("favicon_hash", algorithm, "equals", normalized))
		}
		root.Children = append(root.Children, child)
	}
	return model.FingerprintRuleProjection{Product: model.FingerprintProduct{CanonicalName: firstNonEmpty(rule.Name, source.SourceRuleID)}, Protocol: "http", Root: root}, nil
}

func (fingerprintHubV4Adapter) Project(source model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	var rule struct {
		ID   string `json:"id"`
		Info struct {
			Name     string `json:"name"`
			Tags     string `json:"tags"`
			Metadata struct {
				Product string `json:"product"`
				Vendor  string `json:"vendor"`
				CPE     string `json:"cpe"`
			} `json:"metadata"`
		} `json:"info"`
		HTTP []struct {
			MatchersCondition string `json:"matchers-condition"`
			Matchers          []struct {
				Type            string   `json:"type"`
				Part            string   `json:"part"`
				Condition       string   `json:"condition"`
				Words           []string `json:"words"`
				Regex           []string `json:"regex"`
				Hash            []string `json:"hash"`
				CaseInsensitive bool     `json:"case-insensitive"`
			} `json:"matchers"`
		} `json:"http"`
	}
	if err := json.Unmarshal([]byte(source.RawContent), &rule); err != nil {
		return model.FingerprintRuleProjection{}, err
	}
	root := model.FingerprintMatchGroupProjection{Operator: "any"}
	for _, request := range rule.HTTP {
		requestGroup := model.FingerprintMatchGroupProjection{Operator: normalizedGroupOperator(request.MatchersCondition)}
		for _, upstream := range request.Matchers {
			condition := model.FingerprintMatchGroupProjection{Operator: normalizedGroupOperator(upstream.Condition)}
			values := upstream.Words
			operator := "contains"
			evidenceType, target := webMatcherTarget(upstream.Part)
			switch strings.ToLower(upstream.Type) {
			case "word":
				if upstream.CaseInsensitive {
					operator = "contains_ci"
				}
			case "regex":
				values, operator = upstream.Regex, "regex"
				if upstream.CaseInsensitive {
					operator = "regex_ci"
				}
			case "favicon":
				values, operator, evidenceType = upstream.Hash, "equals", "favicon_hash"
			default:
				return model.FingerprintRuleProjection{}, fmt.Errorf("unsupported FingerprintHub matcher type %q", upstream.Type)
			}
			for _, value := range values {
				matcherTarget := target
				if evidenceType == "favicon_hash" {
					var err error
					var normalized string
					matcherTarget, normalized, err = normalizeFaviconHash(value)
					if err != nil {
						return model.FingerprintRuleProjection{}, err
					}
					value = normalized
				}
				condition.Matchers = append(condition.Matchers, matcher(evidenceType, matcherTarget, operator, value))
			}
			requestGroup.Children = append(requestGroup.Children, condition)
		}
		root.Children = append(root.Children, requestGroup)
	}
	product := firstNonEmpty(rule.Info.Metadata.Product, rule.Info.Name, rule.ID, source.SourceRuleID)
	return model.FingerprintRuleProjection{
		Product:  model.FingerprintProduct{CanonicalName: product, Vendor: rule.Info.Metadata.Vendor, CPE: rule.Info.Metadata.CPE},
		Protocol: "http",
		CPE:      rule.Info.Metadata.CPE,
		Tags:     strings.Split(rule.Info.Tags, ","),
		Root:     root,
	}, nil
}

func (eHoleAdapter) Project(source model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	var rule struct {
		CMS, Method, Location string
		Keyword               []string `json:"keyword"`
	}
	if err := json.Unmarshal([]byte(source.RawContent), &rule); err != nil {
		return model.FingerprintRuleProjection{}, err
	}
	root := model.FingerprintMatchGroupProjection{Operator: "all"}
	for _, value := range rule.Keyword {
		if strings.EqualFold(rule.Method, "faviconhash") {
			algorithm, normalized, err := normalizeFaviconHash(value)
			if err != nil {
				return model.FingerprintRuleProjection{}, err
			}
			root.Matchers = append(root.Matchers, matcher("favicon_hash", algorithm, "equals", normalized))
			continue
		}
		evidenceType, target := webMatcherTarget(rule.Location)
		root.Matchers = append(root.Matchers, matcher(evidenceType, target, "contains_ci", value))
	}
	return model.FingerprintRuleProjection{Product: model.FingerprintProduct{CanonicalName: rule.CMS}, Protocol: "http", Root: root}, nil
}

func (fscanAdapter) Project(source model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	values, err := parseFscanLiteral(source.RawContent)
	if err != nil || len(values) < 2 {
		return model.FingerprintRuleProjection{}, fmt.Errorf("parse fscan rule: %w", err)
	}
	root := model.FingerprintMatchGroupProjection{Operator: "all"}
	if strings.HasPrefix(source.SourceRuleID, "md5:") {
		root.Operator = "any"
		for _, value := range values[1:] {
			root.Matchers = append(root.Matchers, matcher("favicon_hash", "md5", "equals", value))
		}
	} else {
		if len(values) < 3 {
			return model.FingerprintRuleProjection{}, fmt.Errorf("invalid fscan regex rule")
		}
		evidenceType, target := "http_body", "body"
		if strings.EqualFold(values[1], "headers") || strings.EqualFold(values[1], "header") || strings.EqualFold(values[1], "cookie") {
			evidenceType, target = "http_header", ""
		}
		if _, err := regexp.Compile(values[2]); err != nil {
			return model.FingerprintRuleProjection{}, err
		}
		root.Matchers = append(root.Matchers, matcher(evidenceType, target, "regex", values[2]))
	}
	return model.FingerprintRuleProjection{Product: model.FingerprintProduct{CanonicalName: values[0]}, Protocol: "http", Root: root}, nil
}

func (nmapAdapter) Project(source model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	match, ok := parseNmapMatch(source.RawContent)
	if !ok {
		return model.FingerprintRuleProjection{}, fmt.Errorf("invalid Nmap match")
	}
	pattern, ok := nmapGoPattern(match.Pattern, match.Flags)
	if !ok {
		return model.FingerprintRuleProjection{}, fmt.Errorf("unsupported Nmap regex flags %q", match.Flags)
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return model.FingerprintRuleProjection{}, err
	}
	if !nmapTemplateSupported(match.Version) || !nmapTemplateSupported(match.CPE) {
		return model.FingerprintRuleProjection{}, fmt.Errorf("unsupported Nmap version template")
	}
	condition := matcher("tcp_banner", "banner", "regex", pattern)
	condition.VersionCapture = match.Version
	return model.FingerprintRuleProjection{
		Product:         model.FingerprintProduct{CanonicalName: firstNonEmpty(match.Product, match.Service), CPE: match.CPE},
		Protocol:        "tcp",
		SoftMatch:       match.Soft,
		VersionTemplate: match.Version,
		CPE:             match.CPE,
		Tags:            []string{"nmap-service"},
		Root:            model.FingerprintMatchGroupProjection{Operator: "all", Matchers: []model.FingerprintMatcher{condition}},
	}, nil
}

func normalizedGroupOperator(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "and") || strings.EqualFold(strings.TrimSpace(value), "all") {
		return "all"
	}
	return "any"
}

func webMatcherTarget(part string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(part)) {
	case "header", "headers":
		return "http_header", ""
	case "title":
		return "html_title", "title"
	default:
		return "http_body", "body"
	}
}

func normalizeFaviconHash(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if _, err := strconv.ParseInt(value, 10, 32); err == nil {
		return "mmh3", value, nil
	}
	if len(value) == 32 && strings.Trim(strings.ToLower(value), "0123456789abcdef") == "" {
		return "md5", strings.ToLower(value), nil
	}
	if len(value) == 64 && strings.Trim(strings.ToLower(value), "0123456789abcdef") == "" {
		return "sha256", strings.ToLower(value), nil
	}
	for _, candidate := range regexp.MustCompile(`-?[0-9]{1,10}`).FindAllString(value, -1) {
		if _, err := strconv.ParseInt(candidate, 10, 32); err == nil {
			return "mmh3", candidate, nil
		}
	}
	return "", "", fmt.Errorf("unsupported favicon hash %q", value)
}
