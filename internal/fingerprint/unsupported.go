package fingerprint

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golandproject/yscan/internal/model"
	"gopkg.in/yaml.v3"
)

const (
	unsupportedWebYAMLReason     = "web_yaml_semantics_not_supported"
	unsupportedServiceYAMLReason = "service_active_probe_pending"
	unsupportedWhatWebReason     = "whatweb_dynamic_semantics_not_supported"
	unsupportedWappalyzerReason  = "wappalyzer_dom_or_js_only"
)

type fingerprintHubWebYAMLSourceAdapter struct{}

func (fingerprintHubWebYAMLSourceAdapter) SourceKey() string      { return "fingerprinthub-web-yaml" }
func (fingerprintHubWebYAMLSourceAdapter) AdapterVersion() string { return "m11-fh-web-yaml-v1" }

type fingerprintHubServiceYAMLSourceAdapter struct{}

func (fingerprintHubServiceYAMLSourceAdapter) SourceKey() string {
	return "fingerprinthub-service-yaml"
}
func (fingerprintHubServiceYAMLSourceAdapter) AdapterVersion() string {
	return "m11-fh-service-yaml-v2"
}

type whatWebSourceAdapter struct{}

func (whatWebSourceAdapter) SourceKey() string      { return "whatweb" }
func (whatWebSourceAdapter) AdapterVersion() string { return "m11-whatweb-passive-v2" }

type wappalyzerAdapter struct{}

func (wappalyzerAdapter) SourceKey() string      { return "wappalyzer" }
func (wappalyzerAdapter) AdapterVersion() string { return "m11-wappalyzer-passive-v5" }

type fingerprintYAMLDocument struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string `yaml:"name"`
		Tags     string `yaml:"tags"`
		Metadata struct {
			Product   string   `yaml:"product"`
			Vendor    string   `yaml:"vendor"`
			CPE       string   `yaml:"cpe"`
			Version   string   `yaml:"version"`
			Rarity    int      `yaml:"rarity"`
			FOFAQuery []string `yaml:"fofa-query"`
		} `yaml:"metadata"`
	} `yaml:"info"`
	HTTP []fingerprintYAMLHTTP `yaml:"http"`
	TCP  []fingerprintYAMLTCP  `yaml:"tcp"`
}

type fingerprintYAMLHTTP struct {
	Method            string                   `yaml:"method"`
	Path              []string                 `yaml:"path"`
	MatchersCondition string                   `yaml:"matchers-condition"`
	Matchers          []fingerprintYAMLMatcher `yaml:"matchers"`
}

type fingerprintYAMLTCP struct {
	Name   string `yaml:"name"`
	Inputs []struct {
		Data string `yaml:"data"`
	} `yaml:"inputs"`
	Port       string                   `yaml:"port"`
	Extractors []fingerprintYAMLMatcher `yaml:"extractors"`
}

type fingerprintYAMLMatcher struct {
	Type            string   `yaml:"type"`
	Part            string   `yaml:"part"`
	Condition       string   `yaml:"condition"`
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Hash            []string `yaml:"hash"`
	Status          []int    `yaml:"status"`
	CaseInsensitive bool     `yaml:"case-insensitive"`
}

func (fingerprintHubWebYAMLSourceAdapter) Adapt(snapshot VerifiedSnapshot) ([]model.FingerprintSourceRule, error) {
	return adaptProjectedFiles(snapshot, "web-fingerprint/", ".yaml", func(rule model.FingerprintSourceRule) error {
		_, err := projectFingerprintHubWebYAML(rule)
		return err
	}, unsupportedWebYAMLReason)
}

func (fingerprintHubWebYAMLSourceAdapter) Project(rule model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	return projectFingerprintHubWebYAML(rule)
}

func projectFingerprintHubWebYAML(source model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	var document fingerprintYAMLDocument
	if err := yaml.Unmarshal([]byte(source.RawContent), &document); err != nil {
		return model.FingerprintRuleProjection{}, err
	}
	if len(document.HTTP) == 0 {
		return model.FingerprintRuleProjection{}, fmt.Errorf("no HTTP request")
	}
	root := model.FingerprintMatchGroupProjection{Operator: "any"}
	for _, request := range document.HTTP {
		if request.Method != "" && !strings.EqualFold(request.Method, "GET") {
			return model.FingerprintRuleProjection{}, fmt.Errorf("HTTP method %s requires active collection", request.Method)
		}
		for _, path := range request.Path {
			if path != "/" && path != "{{BaseURL}}/" {
				return model.FingerprintRuleProjection{}, fmt.Errorf("HTTP path %s requires active collection", path)
			}
		}
		requestGroup := model.FingerprintMatchGroupProjection{Operator: normalizedGroupOperator(request.MatchersCondition)}
		for _, upstream := range request.Matchers {
			if fofaQueryRequiresAllWords(document.Info.Metadata.FOFAQuery, upstream.Words) {
				upstream.Condition = "and"
			}
			condition, err := projectYAMLMatcher(upstream, "http")
			if err != nil {
				return model.FingerprintRuleProjection{}, err
			}
			requestGroup.Children = append(requestGroup.Children, condition)
		}
		if !validProjectedGroup(requestGroup) {
			return model.FingerprintRuleProjection{}, fmt.Errorf("empty HTTP matcher")
		}
		root.Children = append(root.Children, requestGroup)
	}
	product := firstNonEmpty(document.Info.Metadata.Product, document.Info.Name, document.ID, source.SourceRuleID)
	return model.FingerprintRuleProjection{Product: model.FingerprintProduct{CanonicalName: product, Vendor: document.Info.Metadata.Vendor, CPE: document.Info.Metadata.CPE}, Protocol: "http", CPE: document.Info.Metadata.CPE, Tags: strings.Split(document.Info.Tags, ","), Root: root}, nil
}

func projectYAMLMatcher(upstream fingerprintYAMLMatcher, protocol string) (model.FingerprintMatchGroupProjection, error) {
	group := model.FingerprintMatchGroupProjection{Operator: normalizedGroupOperator(upstream.Condition)}
	typeName := strings.ToLower(strings.TrimSpace(upstream.Type))
	if protocol == "tcp" {
		if typeName != "regex" {
			return group, fmt.Errorf("unsupported TCP matcher type %q", upstream.Type)
		}
		for _, value := range upstream.Regex {
			if _, err := regexp.Compile(value); err != nil {
				return group, fmt.Errorf("unsupported TCP regex: %w", err)
			}
			group.Matchers = append(group.Matchers, matcher("tcp_banner", "banner", "regex", value))
		}
		return group, nil
	}
	evidenceType, target := webMatcherTarget(upstream.Part)
	switch typeName {
	case "word":
		operator := "contains"
		if upstream.CaseInsensitive {
			operator = "contains_ci"
		}
		for _, value := range upstream.Words {
			group.Matchers = append(group.Matchers, matcher(evidenceType, target, operator, value))
		}
	case "regex":
		operator := "regex"
		if upstream.CaseInsensitive {
			operator = "regex_ci"
		}
		for _, value := range upstream.Regex {
			pattern := value
			if operator == "regex_ci" {
				pattern = "(?i)" + pattern
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return group, fmt.Errorf("unsupported HTTP regex: %w", err)
			}
			group.Matchers = append(group.Matchers, matcher(evidenceType, target, operator, value))
		}
	case "favicon":
		for _, value := range upstream.Hash {
			algorithm, normalized, err := normalizeFaviconHash(value)
			if err != nil {
				return group, err
			}
			group.Matchers = append(group.Matchers, matcher("favicon_hash", algorithm, "equals", normalized))
		}
	case "status":
		for _, status := range upstream.Status {
			group.Matchers = append(group.Matchers, matcher("status_code", "status", "equals", strconv.Itoa(status)))
		}
	default:
		return group, fmt.Errorf("unsupported HTTP matcher type %q", upstream.Type)
	}
	if len(group.Matchers) == 0 {
		return group, fmt.Errorf("matcher has no values")
	}
	return group, nil
}

func (fingerprintHubServiceYAMLSourceAdapter) Adapt(snapshot VerifiedSnapshot) ([]model.FingerprintSourceRule, error) {
	return adaptProjectedFiles(snapshot, "service-fingerprint/", ".yaml", func(rule model.FingerprintSourceRule) error {
		_, err := projectFingerprintHubServiceYAML(rule)
		return err
	}, unsupportedServiceYAMLReason)
}

func (fingerprintHubServiceYAMLSourceAdapter) Project(rule model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	return projectFingerprintHubServiceYAML(rule)
}

func projectFingerprintHubServiceYAML(source model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	var document fingerprintYAMLDocument
	if err := yaml.Unmarshal([]byte(source.RawContent), &document); err != nil {
		return model.FingerprintRuleProjection{}, err
	}
	if len(document.TCP) != 1 {
		return model.FingerprintRuleProjection{}, fmt.Errorf("unsupported TCP request count")
	}
	request := document.TCP[0]
	for _, input := range request.Inputs {
		if input.Data != "" {
			return model.FingerprintRuleProjection{}, fmt.Errorf("active TCP probe %s pending", request.Name)
		}
	}
	root := model.FingerprintMatchGroupProjection{Operator: "any"}
	for _, extractor := range request.Extractors {
		condition, err := projectYAMLMatcher(extractor, "tcp")
		if err != nil {
			return model.FingerprintRuleProjection{}, err
		}
		root.Children = append(root.Children, condition)
	}
	if !validProjectedGroup(root) {
		return model.FingerprintRuleProjection{}, fmt.Errorf("empty TCP extractor")
	}
	applyMatcherVersionCapture(&root, document.Info.Metadata.Version)
	product := firstNonEmpty(document.Info.Metadata.Product, document.Info.Name, document.ID, source.SourceRuleID)
	return model.FingerprintRuleProjection{Product: model.FingerprintProduct{CanonicalName: product, Vendor: document.Info.Metadata.Vendor, CPE: document.Info.Metadata.CPE}, Protocol: "tcp", VersionTemplate: document.Info.Metadata.Version, CPE: document.Info.Metadata.CPE, Tags: strings.Split(document.Info.Tags, ","), Root: root}, nil
}

func applyMatcherVersionCapture(group *model.FingerprintMatchGroupProjection, version string) {
	if group == nil || strings.TrimSpace(version) == "" {
		return
	}
	for index := range group.Matchers {
		if strings.HasPrefix(group.Matchers[index].Operator, "regex") {
			group.Matchers[index].VersionCapture = version
		}
	}
	for index := range group.Children {
		applyMatcherVersionCapture(&group.Children[index], version)
	}
}

func adaptProjectedFiles(snapshot VerifiedSnapshot, prefix, extension string, project func(model.FingerprintSourceRule) error, fallbackReason string) ([]model.FingerprintSourceRule, error) {
	paths := make([]string, 0, len(snapshot.Files))
	for sourcePath := range snapshot.Files {
		if strings.HasPrefix(sourcePath, prefix) && strings.HasSuffix(sourcePath, extension) {
			paths = append(paths, sourcePath)
		}
	}
	sort.Strings(paths)
	rules := make([]model.FingerprintSourceRule, 0, len(paths))
	for _, sourcePath := range paths {
		raw := snapshot.Files[sourcePath]
		rule := model.FingerprintSourceRule{SourceRuleID: strings.TrimSuffix(strings.TrimPrefix(sourcePath, prefix), extension), SourcePath: sourcePath, ContentSHA256: sha256Hex(raw), RawContent: string(raw), RawStructure: string(raw), ImportStatus: "executable"}
		if err := project(rule); err != nil {
			rule.ImportStatus = "unsupported"
			rule.ImportError = fallbackReason + ": " + err.Error()
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (whatWebSourceAdapter) Adapt(snapshot VerifiedSnapshot) ([]model.FingerprintSourceRule, error) {
	return adaptProjectedFiles(snapshot, "plugins/", ".rb", func(rule model.FingerprintSourceRule) error {
		_, err := projectWhatWeb(rule)
		return err
	}, unsupportedWhatWebReason)
}

func (whatWebSourceAdapter) Project(rule model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	return projectWhatWeb(rule)
}

var (
	whatWebName       = regexp.MustCompile(`(?m)^name\s+["']([^"']+)["']`)
	whatWebRegexp     = regexp.MustCompile(`:(regexp|version)\s*=>\s*/((?:\\.|[^/])*)/([ims]*)`)
	whatWebSearch     = regexp.MustCompile(`:search\s*=>\s*["']headers\[([^]]+)\]["']`)
	whatWebAnySearch  = regexp.MustCompile(`:search\s*=>\s*["']([^"']+)["']`)
	whatWebOffset     = regexp.MustCompile(`:offset\s*=>\s*([0-9]+)`)
	whatWebCertainty  = regexp.MustCompile(`:certainty\s*=>\s*([0-9]+)`)
	whatWebTextDouble = regexp.MustCompile(`:text\s*=>\s*"((?:\\.|[^"])*)"`)
	whatWebTextSingle = regexp.MustCompile(`:text\s*=>\s*'((?:\\.|[^'])*)'`)
)

func projectWhatWeb(source model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	raw := source.RawContent
	name := source.SourceRuleID
	if match := whatWebName.FindStringSubmatch(raw); len(match) == 2 {
		name = match[1]
	}
	root := model.FingerprintMatchGroupProjection{Operator: "any"}
	weakMatchers := 0
	for _, hash := range whatWebHashes(raw) {
		target := ""
		if search := whatWebAnySearch.FindStringSubmatch(hash); len(search) == 2 {
			searchValue := strings.ToLower(strings.TrimSpace(search[1]))
			if header := whatWebSearch.FindStringSubmatch(hash); len(header) == 2 {
				target = strings.ToLower(strings.TrimSpace(header[1]))
			} else if searchValue != "body" {
				if whatWebRegexp.MatchString(hash) || whatWebTextDouble.MatchString(hash) || whatWebTextSingle.MatchString(hash) {
					return model.FingerprintRuleProjection{}, fmt.Errorf("unsupported WhatWeb search target %q", searchValue)
				}
				continue
			}
		}
		if (strings.Contains(hash, ":status=>") || strings.Contains(hash, ":status =>") || strings.Contains(hash, ":md5=>") || strings.Contains(hash, ":md5 =>") || strings.Contains(hash, ":url=>") || strings.Contains(hash, ":url =>")) &&
			(whatWebRegexp.MatchString(hash) || whatWebTextDouble.MatchString(hash) || whatWebTextSingle.MatchString(hash)) {
			return model.FingerprintRuleProjection{}, fmt.Errorf("unsupported compound WhatWeb matcher")
		}
		certainty := 100
		if value := whatWebCertainty.FindStringSubmatch(hash); len(value) == 2 {
			certainty, _ = strconv.Atoi(value[1])
			if certainty < 1 || certainty > 100 {
				return model.FingerprintRuleProjection{}, fmt.Errorf("invalid WhatWeb certainty %d", certainty)
			}
		}
		matcherAdded := false
		if expression := whatWebRegexp.FindStringSubmatch(hash); len(expression) == 4 {
			pattern, ok := rubyRegexpToGo(expression[2], expression[3])
			if !ok {
				return model.FingerprintRuleProjection{}, fmt.Errorf("unsupported Ruby regular expression")
			}
			condition := matcher("http_body", "body", "regex", pattern)
			if target != "" {
				condition.EvidenceType, condition.Target = "http_header", target
			}
			if expression[1] == "version" {
				capture := 1
				if offset := whatWebOffset.FindStringSubmatch(hash); len(offset) == 2 {
					parsed, err := strconv.Atoi(offset[1])
					if err != nil {
						return model.FingerprintRuleProjection{}, fmt.Errorf("invalid WhatWeb version offset")
					}
					capture = parsed + 1
				}
				compiled, _ := regexp.Compile(pattern)
				if compiled.NumSubexp() == 0 && capture == 1 {
					capture = 0
				}
				if capture > compiled.NumSubexp() {
					return model.FingerprintRuleProjection{}, fmt.Errorf("WhatWeb version offset selects missing capture %d", capture)
				}
				condition.VersionCapture = "$" + strconv.Itoa(capture)
			} else if whatWebOffset.MatchString(hash) {
				return model.FingerprintRuleProjection{}, fmt.Errorf("WhatWeb offset without version is unsupported")
			}
			root.Matchers = append(root.Matchers, condition)
			matcherAdded = true
		}
		if !matcherAdded {
			text := ""
			if value := whatWebTextDouble.FindStringSubmatch(hash); len(value) == 2 {
				if decoded, err := strconv.Unquote(`"` + value[1] + `"`); err == nil {
					text = decoded
				}
			} else if value := whatWebTextSingle.FindStringSubmatch(hash); len(value) == 2 {
				text = strings.NewReplacer(`\\`, `\`, `\'`, `'`).Replace(value[1])
			}
			if text != "" {
				condition := matcher("http_body", "body", "contains", text)
				if target != "" {
					condition.EvidenceType, condition.Target = "http_header", target
				}
				root.Matchers = append(root.Matchers, condition)
				matcherAdded = true
			}
		}
		if matcherAdded && certainty < 100 {
			weakMatchers++
		}
	}
	if len(root.Matchers) == 0 {
		return model.FingerprintRuleProjection{}, fmt.Errorf("no static passive matcher")
	}
	if weakMatchers > 0 && weakMatchers != len(root.Matchers) {
		return model.FingerprintRuleProjection{}, fmt.Errorf("mixed strong and weak WhatWeb matchers cannot be represented")
	}
	return model.FingerprintRuleProjection{Product: model.FingerprintProduct{CanonicalName: name}, Protocol: "http", SoftMatch: weakMatchers == len(root.Matchers), Root: root}, nil
}

func whatWebHashes(raw string) []string {
	hashes := make([]string, 0)
	start, depth := -1, 0
	var quote byte
	inRegexp, escaped := false, false
	for index := 0; index < len(raw); index++ {
		current := raw[index]
		if start < 0 {
			if current == '{' {
				start, depth = index+1, 1
			}
			continue
		}
		if escaped {
			escaped = false
			continue
		}
		if current == '\\' && (quote != 0 || inRegexp) {
			escaped = true
			continue
		}
		if quote != 0 {
			if current == quote {
				quote = 0
			}
			continue
		}
		if inRegexp {
			if current == '/' {
				inRegexp = false
			}
			continue
		}
		switch current {
		case '\'', '"':
			quote = current
		case '/':
			previous := index - 1
			for previous >= start && (raw[previous] == ' ' || raw[previous] == '\t') {
				previous--
			}
			if previous >= start && raw[previous] == '>' {
				inRegexp = true
			}
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				hashes = append(hashes, raw[start:index])
				start = -1
			}
		}
	}
	return hashes
}

func rubyRegexpToGo(pattern, flags string) (string, bool) {
	if strings.TrimSpace(pattern) == "" || strings.Contains(flags, "x") {
		return "", false
	}
	prefix := ""
	if strings.Contains(flags, "i") {
		prefix += "i"
	}
	if strings.Contains(flags, "m") {
		prefix += "s"
	}
	if prefix != "" {
		pattern = "(?" + prefix + ")" + pattern
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return "", false
	}
	return pattern, true
}

func (wappalyzerAdapter) Adapt(snapshot VerifiedSnapshot) ([]model.FingerprintSourceRule, error) {
	paths := make([]string, 0, len(snapshot.Files))
	for sourcePath := range snapshot.Files {
		if strings.HasPrefix(sourcePath, "src/technologies/") && strings.HasSuffix(sourcePath, ".json") {
			paths = append(paths, sourcePath)
		}
	}
	sort.Strings(paths)
	rules := make([]model.FingerprintSourceRule, 0, 3931)
	for _, sourcePath := range paths {
		var technologies map[string]json.RawMessage
		if err := json.Unmarshal(snapshot.Files[sourcePath], &technologies); err != nil {
			return nil, fmt.Errorf("decode Wappalyzer %s: %w", sourcePath, err)
		}
		names := make([]string, 0, len(technologies))
		for name := range technologies {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			raw := technologies[name]
			rule := model.FingerprintSourceRule{SourceRuleID: name, SourcePath: sourcePath + "#/" + jsonPointerToken(name), ContentSHA256: sha256Hex(raw), RawContent: string(raw), RawStructure: string(raw), ImportStatus: "executable"}
			if _, err := projectWappalyzer(rule); err != nil {
				rule.ImportStatus, rule.ImportError = "unsupported", unsupportedWappalyzerReason+": "+err.Error()
			}
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func (wappalyzerAdapter) Project(rule model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	return projectWappalyzer(rule)
}

func projectWappalyzer(source model.FingerprintSourceRule) (model.FingerprintRuleProjection, error) {
	var technology map[string]json.RawMessage
	if err := json.Unmarshal([]byte(source.RawContent), &technology); err != nil {
		return model.FingerprintRuleProjection{}, err
	}
	if nonEmptyJSONValue(technology["requires"]) || nonEmptyJSONValue(technology["requiresCategory"]) {
		return model.FingerprintRuleProjection{}, fmt.Errorf("requires dependency semantics are not representable")
	}
	root := model.FingerprintMatchGroupProjection{Operator: "any"}
	strongMatchers, weakMatchers := 0, 0
	appendPatterns := func(evidenceType, target string, raw json.RawMessage) error {
		for _, value := range wappalyzerStringList(raw) {
			if value == "" {
				switch evidenceType {
				case "http_header", "html_meta", "http_cookie":
					if target != "" {
						root.Matchers = append(root.Matchers, matcher(evidenceType, target, "exists", "present"))
						strongMatchers++
					}
				}
				continue
			}
			pattern, version, confidence, ok := parseWappalyzerPattern(value)
			if !ok {
				return fmt.Errorf("unsupported pattern semantics: %q", value)
			}
			condition := matcher(evidenceType, target, "regex_ci", pattern)
			condition.VersionCapture = version
			root.Matchers = append(root.Matchers, condition)
			if confidence < 100 {
				weakMatchers++
			} else {
				strongMatchers++
			}
		}
		return nil
	}
	if err := appendPatterns("http_body", "body", technology["html"]); err != nil {
		return model.FingerprintRuleProjection{}, err
	}
	if err := appendPatterns("http_body", "body", technology["scriptSrc"]); err != nil {
		return model.FingerprintRuleProjection{}, err
	}
	if err := appendPatterns("http_body", "body", technology["text"]); err != nil {
		return model.FingerprintRuleProjection{}, err
	}
	if err := appendPatterns("http_url", "url", technology["url"]); err != nil {
		return model.FingerprintRuleProjection{}, err
	}
	for _, field := range []struct {
		name, evidence string
	}{{"headers", "http_header"}, {"meta", "html_meta"}, {"cookies", "http_cookie"}} {
		var values map[string]json.RawMessage
		if err := json.Unmarshal(technology[field.name], &values); err != nil {
			continue
		}
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := appendPatterns(field.evidence, strings.ToLower(key), values[key]); err != nil {
				return model.FingerprintRuleProjection{}, err
			}
		}
	}
	if len(root.Matchers) == 0 {
		return model.FingerprintRuleProjection{}, fmt.Errorf("no supported passive matcher")
	}
	if weakMatchers > 0 && strongMatchers > 0 {
		return model.FingerprintRuleProjection{}, fmt.Errorf("mixed strong and low-confidence matchers cannot be represented")
	}
	var cpe string
	_ = json.Unmarshal(technology["cpe"], &cpe)
	return model.FingerprintRuleProjection{Product: model.FingerprintProduct{CanonicalName: source.SourceRuleID}, Protocol: "http", SoftMatch: weakMatchers > 0, CPE: strings.TrimSpace(cpe), Root: root}, nil
}

func nonEmptyJSONValue(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null" && trimmed != `""` && trimmed != "[]"
}

func wappalyzerStringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return []string{single}
	}
	var values []string
	_ = json.Unmarshal(raw, &values)
	return values
}

func parseWappalyzerPattern(value string) (string, string, int, bool) {
	parts := strings.Split(value, `\;`)
	pattern := strings.TrimSpace(parts[0])
	if pattern == "" {
		return "", "", 0, false
	}
	version, confidence := "", 100
	for _, directive := range parts[1:] {
		switch {
		case strings.HasPrefix(directive, "version:"):
			var ok bool
			version, ok = normalizeWappalyzerVersion(strings.TrimPrefix(directive, "version:"))
			if !ok {
				return "", "", 0, false
			}
		case strings.HasPrefix(directive, "confidence:"):
			parsed, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(directive, "confidence:")))
			if err != nil || parsed < 0 || parsed > 100 {
				return "", "", 0, false
			}
			confidence = parsed
		default:
			return "", "", 0, false
		}
	}
	if _, err := regexp.Compile("(?i)" + pattern); err != nil {
		return "", "", 0, false
	}
	return pattern, version, confidence, true
}

var wappalyzerConditionalVersion = regexp.MustCompile(`^\\([0-9]+)\?([^:]*):(.*)$`)

func normalizeWappalyzerVersion(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", true
	}
	convertReferences := func(input string) string {
		return regexp.MustCompile(`\\([0-9]+)`).ReplaceAllString(input, `$$$1`)
	}
	if parts := wappalyzerConditionalVersion.FindStringSubmatch(value); len(parts) == 4 {
		return fmt.Sprintf("$WAPP(%s,%s,%s)", parts[1], strconv.Quote(convertReferences(parts[2])), strconv.Quote(convertReferences(parts[3]))), true
	}
	if strings.Contains(value, "?") {
		return "", false
	}
	return convertReferences(value), true
}

func jsonPointerToken(value string) string {
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(value)
}

func fingerprintHubWebYAMLAdapter() SourceAdapter { return fingerprintHubWebYAMLSourceAdapter{} }
func fingerprintHubServiceYAMLAdapter() SourceAdapter {
	return fingerprintHubServiceYAMLSourceAdapter{}
}
func whatWebAdapter() SourceAdapter { return whatWebSourceAdapter{} }
