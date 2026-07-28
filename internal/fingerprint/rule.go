package fingerprint

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Protocol string

const (
	ProtocolHTTP  Protocol = "http"
	ProtocolHTTPS Protocol = "https"
	ProtocolTCP   Protocol = "tcp"
	ProtocolTLS   Protocol = "tls"
)

type MatchMode string

const (
	MatchAll MatchMode = "all"
	MatchAny MatchMode = "any"
)

type EvidenceTarget string

const (
	EvidenceHeader      EvidenceTarget = "header"
	EvidenceBody        EvidenceTarget = "body"
	EvidenceBanner      EvidenceTarget = "banner"
	EvidenceFaviconHash EvidenceTarget = "favicon_hash"
)

type MatchOperator string

const (
	MatchContains MatchOperator = "contains"
	MatchEquals   MatchOperator = "equals"
	MatchRegex    MatchOperator = "regex"
)

type FaviconHashAlgorithm string

const (
	FaviconHashMD5    FaviconHashAlgorithm = "md5"
	FaviconHashMMH3   FaviconHashAlgorithm = "mmh3"
	FaviconHashSHA256 FaviconHashAlgorithm = "sha256"
)

var ruleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)

// Rule is the normalized, source-independent fingerprint rule consumed by
// future local snapshot parsers and the deterministic compiler. Matchers are
// combined according to MatchMode and retain their original source ID.
type Rule struct {
	ID        string          `json:"id"`
	SourceID  string          `json:"source_id"`
	Product   ProductIdentity `json:"product"`
	Protocols []Protocol      `json:"protocols"`
	MatchMode MatchMode       `json:"match_mode,omitempty"`
	Matchers  []Matcher       `json:"matchers"`
}

// ProductIdentity describes the conclusion emitted when a rule matches.
// Version and CPE are optional because upstream data does not always contain
// safe version evidence; when present, CPE must use the CPE 2.3 formatted form.
type ProductIdentity struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	CPE     string `json:"cpe,omitempty"`
}

// Matcher describes one observable condition. HeaderName is meaningful only
// for header evidence and empty HeaderName matches the complete normalized
// header block. HashAlgorithm is meaningful only for favicon_hash.
type Matcher struct {
	Target          EvidenceTarget       `json:"target"`
	Operator        MatchOperator        `json:"operator"`
	Pattern         string               `json:"pattern"`
	HeaderName      string               `json:"header_name,omitempty"`
	HashAlgorithm   FaviconHashAlgorithm `json:"hash_algorithm,omitempty"`
	CaseInsensitive bool                 `json:"case_insensitive,omitempty"`
}

// Validate canonicalizes a rule and rejects ambiguous or unsupported evidence
// definitions before they can enter a compiled fingerprint set.
func (rule *Rule) Validate() error {
	rule.ID = strings.TrimSpace(strings.ToLower(rule.ID))
	rule.SourceID = strings.TrimSpace(strings.ToLower(rule.SourceID))
	if !ruleIDPattern.MatchString(rule.ID) {
		return errors.New("rule id must contain 1-128 lowercase letters, numbers, dots, slashes, underscores or hyphens")
	}
	if !sourceIDPattern.MatchString(rule.SourceID) {
		return errors.New("rule source_id is invalid")
	}
	if err := rule.Product.Validate(); err != nil {
		return fmt.Errorf("product: %w", err)
	}
	if err := rule.normalizeProtocols(); err != nil {
		return err
	}
	if rule.MatchMode == "" {
		rule.MatchMode = MatchAll
	}
	if rule.MatchMode != MatchAll && rule.MatchMode != MatchAny {
		return fmt.Errorf("unsupported match_mode: %s", rule.MatchMode)
	}
	if len(rule.Matchers) == 0 {
		return errors.New("rule requires at least one matcher")
	}

	requiresHTTP := false
	for index := range rule.Matchers {
		matcher := &rule.Matchers[index]
		if err := matcher.Validate(); err != nil {
			return fmt.Errorf("matcher %d: %w", index, err)
		}
		requiresHTTP = requiresHTTP || matcher.Target == EvidenceHeader || matcher.Target == EvidenceBody || matcher.Target == EvidenceFaviconHash
	}
	if requiresHTTP && !rule.supportsHTTP() {
		return errors.New("header, body and favicon evidence requires http or https protocol")
	}
	return nil
}

func (product *ProductIdentity) Validate() error {
	product.Vendor = strings.TrimSpace(product.Vendor)
	product.Name = strings.TrimSpace(product.Name)
	product.Version = strings.TrimSpace(product.Version)
	product.CPE = strings.TrimSpace(product.CPE)
	if product.Name == "" {
		return errors.New("name is required")
	}
	if strings.ContainsAny(product.Name, "\r\n") || strings.ContainsAny(product.Vendor, "\r\n") || strings.ContainsAny(product.Version, "\r\n") {
		return errors.New("vendor, name and version must not contain line breaks")
	}
	if product.CPE != "" && !validCPE23(product.CPE) {
		return errors.New("cpe must use a complete CPE 2.3 formatted value")
	}
	return nil
}

func (matcher *Matcher) Validate() error {
	matcher.HeaderName = strings.TrimSpace(strings.ToLower(matcher.HeaderName))
	matcher.HashAlgorithm = FaviconHashAlgorithm(strings.ToLower(strings.TrimSpace(string(matcher.HashAlgorithm))))
	if strings.TrimSpace(matcher.Pattern) == "" {
		return errors.New("pattern is required")
	}
	if matcher.Target != EvidenceHeader && matcher.Target != EvidenceBody && matcher.Target != EvidenceBanner && matcher.Target != EvidenceFaviconHash {
		return fmt.Errorf("unsupported target: %s", matcher.Target)
	}
	if matcher.Operator != MatchContains && matcher.Operator != MatchEquals && matcher.Operator != MatchRegex {
		return fmt.Errorf("unsupported operator: %s", matcher.Operator)
	}
	if matcher.Operator == MatchRegex {
		if _, err := regexp.Compile(matcher.Pattern); err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
	}

	switch matcher.Target {
	case EvidenceHeader:
		if matcher.HeaderName != "" && strings.ContainsAny(matcher.HeaderName, " \t\r\n:") {
			return errors.New("header matcher has an invalid header_name")
		}
		if matcher.HashAlgorithm != "" {
			return errors.New("header matcher must not set hash_algorithm")
		}
	case EvidenceBody, EvidenceBanner:
		if matcher.HeaderName != "" || matcher.HashAlgorithm != "" {
			return errors.New("body and banner matchers must not set header_name or hash_algorithm")
		}
	case EvidenceFaviconHash:
		if matcher.HeaderName != "" || matcher.Operator != MatchEquals {
			return errors.New("favicon_hash matcher requires equals operator and no header_name")
		}
		if !validFaviconHash(matcher.HashAlgorithm, matcher.Pattern) {
			return errors.New("favicon_hash matcher has an invalid hash_algorithm or pattern")
		}
	}
	return nil
}

func (rule *Rule) normalizeProtocols() error {
	if len(rule.Protocols) == 0 {
		return errors.New("rule requires at least one protocol")
	}
	seen := make(map[Protocol]struct{}, len(rule.Protocols))
	for index, protocol := range rule.Protocols {
		protocol = Protocol(strings.ToLower(strings.TrimSpace(string(protocol))))
		if protocol != ProtocolHTTP && protocol != ProtocolHTTPS && protocol != ProtocolTCP && protocol != ProtocolTLS {
			return fmt.Errorf("unsupported protocol: %s", protocol)
		}
		if _, exists := seen[protocol]; exists {
			return fmt.Errorf("duplicate protocol: %s", protocol)
		}
		seen[protocol] = struct{}{}
		rule.Protocols[index] = protocol
	}
	sort.Slice(rule.Protocols, func(left, right int) bool { return rule.Protocols[left] < rule.Protocols[right] })
	return nil
}

func (rule Rule) supportsHTTP() bool {
	for _, protocol := range rule.Protocols {
		if protocol == ProtocolHTTP || protocol == ProtocolHTTPS {
			return true
		}
	}
	return false
}

func validCPE23(value string) bool {
	if strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	parts := strings.Split(value, ":")
	if len(parts) != 13 || parts[0] != "cpe" || parts[1] != "2.3" {
		return false
	}
	if parts[2] != "a" && parts[2] != "h" && parts[2] != "o" {
		return false
	}
	for _, part := range parts[3:] {
		if part == "" {
			return false
		}
	}
	return true
}

func validFaviconHash(algorithm FaviconHashAlgorithm, value string) bool {
	switch algorithm {
	case FaviconHashMD5:
		return len(value) == 32 && strings.Trim(strings.ToLower(value), "0123456789abcdef") == ""
	case FaviconHashMMH3:
		parsed, err := strconv.ParseInt(value, 10, 32)
		return err == nil && parsed >= -2147483648 && parsed <= 2147483647
	case FaviconHashSHA256:
		return len(value) == 64 && strings.Trim(strings.ToLower(value), "0123456789abcdef") == ""
	default:
		return false
	}
}
