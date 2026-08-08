package fingerprint

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"golandproject/yscan/internal/model"
)

const legacyBannerSourceKey = "legacy-banner"

type Evidence struct {
	Protocol             string
	Banner               string
	Headers              map[string]string
	Meta                 map[string]string
	Cookies              map[string]string
	Title                string
	Body                 string
	URL                  string
	FaviconHash          string // Compatibility input for callers predating typed hashes.
	FaviconMD5           string
	FaviconMMH3          string
	FaviconSHA256        string
	StatusCode           int
	HeaderTruncated      bool
	BodyTruncated        bool
	BannerTruncated      bool
	BannerCapturedLength int
	BannerCapturedSHA256 string
	HeaderCapturedLength int
	HeaderCapturedSHA256 string
	BodyCapturedLength   int
	BodyCapturedSHA256   string
}

type MatcherHit = model.FingerprintMatchEvidence

type Match struct {
	Product                 string
	SourceProduct           string
	ProductRole             string
	ExclusiveGroup          string
	Version                 string
	CPE                     string
	Tags                    []string
	Soft                    bool
	SourceKey               string
	SourceRuleID            string
	FingerprintImportID     int64
	FingerprintSourceRuleID int64
	MatcherHits             []MatcherHit
}

type Engine struct {
	rules                    []*compiledRule
	passiveRules             []*compiledRule
	passiveByProtocolAndType map[string]map[string][]*compiledRule
	candidateCache           sync.Map
	nmapProbes               map[string]nmapProbeProjection
	nmapProbeRules           map[string][]*compiledRule
}

type compiledRule struct {
	product, sourceProduct, productRole, exclusiveGroup, versionTemplate, cpe, protocol, source, sourceID string
	tags                                                                                                  []string
	soft                                                                                                  bool
	importID, sourceRuleID                                                                                int64
	order                                                                                                 int
	root                                                                                                  *compiledGroup
	nmapProbe                                                                                             *nmapProbeProjection
}

type RunEngineCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[string]*Engine
	order    []string
}

var defaultRunEngineCache = NewRunEngineCache(1)

type compiledGroup struct {
	id, parentID int64
	operator     string
	position     int
	matchers     []compiledMatcher
	children     []*compiledGroup
}

type compiledMatcher struct {
	id                                    int64
	evidenceType, target, operator, value string
	versionCapture                        string
	position                              int
	expression                            *regexp.Regexp
}

func LoadActiveEngine(db *sql.DB) (*Engine, error) {
	return loadEngine(db, `fingerprint_import.is_active = 1`, nil)
}

// LoadActiveLegacyBannerEngine loads only the small compatibility catalog
// used by v1 banner identification. V2 workflows always use frozen imports.
func LoadActiveLegacyBannerEngine(db *sql.DB) (*Engine, error) {
	return loadEngine(db, `fingerprint_import.is_active = 1 AND source.source_key = ?`, []any{legacyBannerSourceKey})
}

// LoadRunEngine loads only the immutable import revisions frozen when the run
// was created or claimed. Active imports may change while a run is executing.
func LoadRunEngine(db *sql.DB, runID int64) (*Engine, error) {
	if runID <= 0 {
		return nil, fmt.Errorf("scan task run ID is required")
	}
	return loadEngine(db, `EXISTS (
		SELECT 1 FROM scan_task_run_fingerprint_imports AS run_import
		WHERE run_import.scan_task_run_id = ?
			AND run_import.fingerprint_import_id = fingerprint_import.id
	)`, []any{runID})
}

func NewRunEngineCache(capacity int) *RunEngineCache {
	if capacity < 1 {
		capacity = 1
	}
	return &RunEngineCache{capacity: capacity, entries: make(map[string]*Engine)}
}

// LoadRunEngineCached reuses immutable compiled engines for runs that froze
// the exact same projection revisions. The bounded cache prevents revision
// history from becoming process-lifetime memory growth.
func LoadRunEngineCached(db *sql.DB, runID int64) (*Engine, error) {
	return defaultRunEngineCache.Load(db, runID)
}

func (cache *RunEngineCache) Load(db *sql.DB, runID int64) (*Engine, error) {
	if cache == nil || db == nil || runID <= 0 {
		return nil, fmt.Errorf("database and scan task run ID are required")
	}
	revision, err := runEngineRevisionKey(db, runID)
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf("%p:%s", db, revision)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if engine := cache.entries[key]; engine != nil {
		cache.touch(key)
		return engine, nil
	}
	engine, err := LoadRunEngine(db, runID)
	if err != nil {
		return nil, err
	}
	cache.entries[key] = engine
	cache.order = append(cache.order, key)
	for len(cache.order) > cache.capacity {
		delete(cache.entries, cache.order[0])
		cache.order = cache.order[1:]
	}
	return engine, nil
}

func (cache *RunEngineCache) touch(key string) {
	for index, candidate := range cache.order {
		if candidate != key {
			continue
		}
		copy(cache.order[index:], cache.order[index+1:])
		cache.order[len(cache.order)-1] = key
		return
	}
}

func runEngineRevisionKey(db *sql.DB, runID int64) (string, error) {
	rows, err := db.Query(`
		SELECT fingerprint_import.id, COALESCE(fingerprint_import.projection_sha256, '')
		FROM scan_task_run_fingerprint_imports AS run_import
		JOIN fingerprint_imports AS fingerprint_import ON fingerprint_import.id = run_import.fingerprint_import_id
		WHERE run_import.scan_task_run_id = ?
		ORDER BY fingerprint_import.id`, runID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	hash := sha256.New()
	for rows.Next() {
		var importID int64
		var projectionSHA string
		if err := rows.Scan(&importID, &projectionSHA); err != nil {
			return "", err
		}
		_, _ = fmt.Fprintf(hash, "%d:%s\n", importID, projectionSHA)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func loadEngine(db *sql.DB, filter string, args []any) (*Engine, error) {
	rows, err := db.Query(`
		SELECT fingerprint_import.id, source_rule.id, source.source_key, COALESCE(source_rule.source_rule_id, ''),
			COALESCE(source_rule.raw_structure, ''),
			rule.id, product.canonical_name, COALESCE(rule.source_product_name, ''), rule.product_role, rule.exclusive_group, rule.protocol, rule.soft_match,
			COALESCE(rule.version_template, ''), COALESCE(rule.cpe, ''), rule.tags_json,
			match_group.id, COALESCE(match_group.parent_id, 0), match_group.operator, match_group.position,
			matcher.id, matcher.evidence_type, COALESCE(matcher.target, ''), matcher.operator,
			matcher.value, COALESCE(matcher.version_capture, ''), matcher.position
		FROM fingerprint_rules AS rule
		JOIN fingerprint_source_rules AS source_rule ON source_rule.id = rule.fingerprint_source_rule_id
		JOIN fingerprint_imports AS fingerprint_import ON fingerprint_import.id = source_rule.fingerprint_import_id
		JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id
		JOIN fingerprint_products AS product ON product.id = rule.fingerprint_product_id
		JOIN fingerprint_match_groups AS match_group ON match_group.fingerprint_rule_id = rule.id
		LEFT JOIN fingerprint_matchers AS matcher ON matcher.fingerprint_match_group_id = match_group.id
		WHERE `+filter+` AND rule.status = 'executable'
		ORDER BY rule.id, match_group.id, matcher.position`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	engine := &Engine{
		passiveByProtocolAndType: make(map[string]map[string][]*compiledRule),
		nmapProbes:               make(map[string]nmapProbeProjection),
		nmapProbeRules:           make(map[string][]*compiledRule),
	}
	rulesByID := make(map[int64]*compiledRule)
	groupsByID := make(map[int64]*compiledGroup)
	groupRule := make(map[int64]int64)
	for rows.Next() {
		var importID, sourceRuleID, ruleID, groupID, parentID int64
		var matcherID sql.NullInt64
		var source, sourceID, rawStructure, product, sourceProduct, productRole, exclusiveGroup, protocol, versionTemplate, cpe, tagsJSON, groupOperator string
		var groupPosition, soft int
		var evidenceType, target, operator, value, versionCapture sql.NullString
		var matcherPosition sql.NullInt64
		if err := rows.Scan(
			&importID, &sourceRuleID, &source, &sourceID, &rawStructure, &ruleID, &product, &sourceProduct, &productRole, &exclusiveGroup, &protocol, &soft,
			&versionTemplate, &cpe, &tagsJSON, &groupID, &parentID, &groupOperator, &groupPosition,
			&matcherID, &evidenceType, &target, &operator, &value, &versionCapture, &matcherPosition,
		); err != nil {
			return nil, err
		}
		rule := rulesByID[ruleID]
		if rule == nil {
			rule = &compiledRule{product: product, sourceProduct: sourceProduct, productRole: productRole, exclusiveGroup: exclusiveGroup, versionTemplate: versionTemplate, cpe: cpe, protocol: protocol, source: source, sourceID: sourceID, soft: soft != 0, importID: importID, sourceRuleID: sourceRuleID}
			if err := json.Unmarshal([]byte(tagsJSON), &rule.tags); err != nil {
				return nil, fmt.Errorf("decode fingerprint rule %d tags: %w", ruleID, err)
			}
			if source == "nmap-service-probes" && strings.HasPrefix(strings.TrimSpace(rawStructure), "{") {
				var projection nmapProbeProjection
				if err := json.Unmarshal([]byte(rawStructure), &projection); err != nil {
					return nil, fmt.Errorf("decode Nmap probe projection for rule %d: %w", ruleID, err)
				}
				if projection.Mode == "active" {
					if !validReadOnlyNmapProjection(projection) {
						return nil, fmt.Errorf("Nmap rule %d has unsafe active probe projection", ruleID)
					}
					rule.nmapProbe = &projection
					if existing, exists := engine.nmapProbes[projection.Name]; exists && !sameNmapProbeProjection(existing, projection) {
						return nil, fmt.Errorf("Nmap probe %s has conflicting immutable projections", projection.Name)
					}
					engine.nmapProbes[projection.Name] = projection
					engine.nmapProbeRules[projection.Name] = append(engine.nmapProbeRules[projection.Name], rule)
				}
			}
			rulesByID[ruleID] = rule
			engine.rules = append(engine.rules, rule)
		}
		group := groupsByID[groupID]
		if group == nil {
			group = &compiledGroup{id: groupID, parentID: parentID, operator: groupOperator, position: groupPosition}
			groupsByID[groupID] = group
			groupRule[groupID] = ruleID
		}
		if matcherID.Valid {
			compiled := compiledMatcher{id: matcherID.Int64, evidenceType: evidenceType.String, target: target.String, operator: operator.String, value: value.String, versionCapture: versionCapture.String, position: int(matcherPosition.Int64)}
			if compiled.operator == "regex" || compiled.operator == "regex_ci" {
				pattern := compiled.value
				if compiled.operator == "regex_ci" {
					pattern = "(?i)" + pattern
				}
				compiled.expression, err = regexp.Compile(pattern)
				if err != nil {
					return nil, fmt.Errorf("compile normalized matcher %d: %w", compiled.id, err)
				}
			}
			group.matchers = append(group.matchers, compiled)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for groupID, group := range groupsByID {
		rule := rulesByID[groupRule[groupID]]
		if group.parentID == 0 {
			if rule.root != nil {
				return nil, fmt.Errorf("fingerprint rule has multiple root groups")
			}
			rule.root = group
		} else {
			parent := groupsByID[group.parentID]
			if parent == nil {
				return nil, fmt.Errorf("fingerprint group %d has missing parent", group.id)
			}
			parent.children = append(parent.children, group)
		}
	}
	for _, rule := range engine.rules {
		if rule.root == nil {
			return nil, fmt.Errorf("fingerprint rule has no root group")
		}
		sortCompiledGroup(rule.root)
	}
	engine.buildPassiveIndex()
	return engine, nil
}

func (engine *Engine) buildPassiveIndex() {
	for _, rule := range engine.rules {
		if rule.nmapProbe != nil {
			continue
		}
		rule.order = len(engine.passiveRules)
		engine.passiveRules = append(engine.passiveRules, rule)
		types := make(map[string]struct{})
		collectGroupEvidenceTypes(rule.root, types)
		byType := engine.passiveByProtocolAndType[rule.protocol]
		if byType == nil {
			byType = make(map[string][]*compiledRule)
			engine.passiveByProtocolAndType[rule.protocol] = byType
		}
		for evidenceType := range types {
			byType[evidenceType] = append(byType[evidenceType], rule)
		}
	}
}

func collectGroupEvidenceTypes(group *compiledGroup, result map[string]struct{}) {
	if group == nil {
		return
	}
	for _, matcher := range group.matchers {
		result[matcher.evidenceType] = struct{}{}
	}
	for _, child := range group.children {
		collectGroupEvidenceTypes(child, result)
	}
}

func sortCompiledGroup(group *compiledGroup) {
	sort.Slice(group.matchers, func(i, j int) bool { return group.matchers[i].position < group.matchers[j].position })
	sort.Slice(group.children, func(i, j int) bool { return group.children[i].position < group.children[j].position })
	for _, child := range group.children {
		sortCompiledGroup(child)
	}
}

func (engine *Engine) Match(evidence Evidence) []Match {
	if engine == nil {
		return nil
	}
	matches := make([]Match, 0)
	for _, rule := range engine.candidateRules(evidence) {
		if match, ok := matchCompiledRule(rule, evidence); ok {
			matches = append(matches, match)
		}
	}
	return matches
}

func (engine *Engine) candidateRules(evidence Evidence) []*compiledRule {
	types := availableEvidenceTypes(evidence)
	protocols := candidateProtocols(evidence.Protocol, engine.passiveByProtocolAndType)
	cacheKey := strings.Join(protocols, ",") + "|" + strings.Join(types, ",")
	if cached, ok := engine.candidateCache.Load(cacheKey); ok {
		return cached.([]*compiledRule)
	}
	seen := make(map[int]struct{})
	candidates := make([]*compiledRule, 0)
	for _, protocol := range protocols {
		byType := engine.passiveByProtocolAndType[protocol]
		for _, evidenceType := range types {
			for _, rule := range byType[evidenceType] {
				if _, exists := seen[rule.order]; exists {
					continue
				}
				seen[rule.order] = struct{}{}
				candidates = append(candidates, rule)
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].order < candidates[j].order })
	engine.candidateCache.Store(cacheKey, candidates)
	return candidates
}

func candidateProtocols(protocol string, indexes map[string]map[string][]*compiledRule) []string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		result := make([]string, 0, len(indexes))
		for candidate := range indexes {
			result = append(result, candidate)
		}
		sort.Strings(result)
		return result
	}
	result := []string{""}
	if protocol == "https" {
		result = append(result, "http", "https")
	} else {
		result = append(result, protocol)
	}
	return result
}

func availableEvidenceTypes(evidence Evidence) []string {
	types := make(map[string]struct{})
	protocol := strings.ToLower(strings.TrimSpace(evidence.Protocol))
	if protocol == "" || protocol == "http" || protocol == "https" {
		types["http_body"] = struct{}{}
	}
	if protocol == "" || protocol == "tcp" {
		types["tcp_banner"] = struct{}{}
	}
	if evidence.StatusCode != 0 {
		types["status_code"] = struct{}{}
	}
	if len(evidence.Headers) > 0 {
		types["http_header"] = struct{}{}
	}
	if len(evidence.Meta) > 0 {
		types["html_meta"] = struct{}{}
	}
	if len(evidence.Cookies) > 0 {
		types["http_cookie"] = struct{}{}
	}
	if evidence.Title != "" {
		types["html_title"] = struct{}{}
	}
	if evidence.URL != "" {
		types["http_url"] = struct{}{}
	}
	if evidence.FaviconHash != "" || evidence.FaviconMD5 != "" || evidence.FaviconMMH3 != "" || evidence.FaviconSHA256 != "" {
		types["favicon_hash"] = struct{}{}
	}
	result := make([]string, 0, len(types))
	for evidenceType := range types {
		result = append(result, evidenceType)
	}
	sort.Strings(result)
	return result
}

func matchCompiledRule(rule *compiledRule, evidence Evidence) (Match, bool) {
	outcome := matchGroup(rule.root, evidence, rule.cpe)
	if !outcome.matched {
		return Match{}, false
	}
	return Match{
		Product: rule.product, SourceProduct: rule.sourceProduct, ProductRole: rule.productRole, ExclusiveGroup: rule.exclusiveGroup, Version: firstNonEmpty(outcome.version, rule.versionTemplate), CPE: firstNonEmpty(outcome.cpe, rule.cpe),
		Tags: append([]string(nil), rule.tags...), Soft: rule.soft, SourceKey: rule.source, SourceRuleID: rule.sourceID,
		FingerprintImportID: rule.importID, FingerprintSourceRuleID: rule.sourceRuleID, MatcherHits: outcome.hits,
	}, true
}

// NmapTCPProbesForEndpoint returns immutable, read-only active probes whose
// upstream port policy includes this endpoint. Callers apply the per-endpoint
// execution cap and total Context budget.
func (engine *Engine) NmapTCPProbesForEndpoint(port int, service string) []NmapTCPProbe {
	if engine == nil || port < 1 || port > 65535 {
		return nil
	}
	probes := make([]NmapTCPProbe, 0)
	for _, projection := range engine.nmapProbes {
		if probe, ok := projection.runtimeProbe(port, service); ok {
			probes = append(probes, probe)
		}
	}
	sort.Slice(probes, func(i, j int) bool {
		if probes[i].Rarity != probes[j].Rarity {
			return probes[i].Rarity < probes[j].Rarity
		}
		if probes[i].Order != probes[j].Order {
			return probes[i].Order < probes[j].Order
		}
		return probes[i].Name < probes[j].Name
	})
	return probes
}

func (engine *Engine) MatchNmapTCPProbeResponse(probeName string, response []byte) []Match {
	if engine == nil || strings.TrimSpace(probeName) == "" || len(response) == 0 {
		return nil
	}
	names := []string{probeName}
	if projection, exists := engine.nmapProbes[probeName]; exists {
		names = append(names, projection.Fallback...)
	}
	evidence := NewBannerEvidence(string(response), len(response) >= maxNmapProbeRead)
	seenRules := make(map[int64]struct{})
	matches := make([]Match, 0)
	for _, name := range names {
		for _, rule := range engine.nmapProbeRules[name] {
			if _, exists := seenRules[rule.sourceRuleID]; exists {
				continue
			}
			seenRules[rule.sourceRuleID] = struct{}{}
			if match, ok := matchCompiledRule(rule, evidence); ok {
				matches = append(matches, match)
			}
		}
	}
	return matches
}

func validReadOnlyNmapProjection(projection nmapProbeProjection) bool {
	if projection.Mode != "active" || projection.SideEffect != "read_only" || projection.TimeoutMS < 1 || projection.TimeoutMS > 4000 {
		return false
	}
	probe := NmapTCPProbe{Name: projection.Name, Payload: projection.Payload, Ports: projection.Ports, SSLPorts: projection.SSLPorts}
	return isReadOnlyNmapProbe(probe)
}

func sameNmapProbeProjection(left, right nmapProbeProjection) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}

func (engine *Engine) MatchBanner(banner string) string {
	for _, match := range engine.Match(NewBannerEvidence(banner, false)) {
		if match.SourceKey == legacyBannerSourceKey && !match.Soft {
			return match.Product
		}
	}
	return ""
}

type groupOutcome struct {
	matched bool
	hits    []MatcherHit
	version string
	cpe     string
}

func matchGroup(group *compiledGroup, evidence Evidence, cpeTemplate string) groupOutcome {
	if group == nil {
		return groupOutcome{}
	}
	outcomes := make([]groupOutcome, 0, len(group.matchers)+len(group.children))
	for _, candidate := range group.matchers {
		outcomes = append(outcomes, matchNormalizedMatcher(candidate, evidence, cpeTemplate))
	}
	for _, child := range group.children {
		outcomes = append(outcomes, matchGroup(child, evidence, cpeTemplate))
	}
	result := groupOutcome{matched: group.operator == "all"}
	for _, outcome := range outcomes {
		if group.operator == "all" && !outcome.matched {
			return groupOutcome{}
		}
		if group.operator == "any" && outcome.matched {
			result.matched = true
		}
		if outcome.matched {
			result.hits = append(result.hits, outcome.hits...)
			result.version = firstNonEmpty(result.version, outcome.version)
			result.cpe = firstNonEmpty(result.cpe, outcome.cpe)
		}
	}
	if len(outcomes) == 0 {
		result.matched = false
	}
	return result
}

func matchNormalizedMatcher(matcher compiledMatcher, evidence Evidence, cpeTemplate string) groupOutcome {
	if matcher.target != "" && structuredEvidenceRequiresPresence(matcher.evidenceType) && !normalizedEvidencePresent(matcher, evidence) {
		return groupOutcome{}
	}
	observed, truncated := normalizedEvidenceValue(matcher, evidence)
	matched := false
	version, cpe := "", ""
	switch matcher.operator {
	case "exists":
		matched = normalizedEvidencePresent(matcher, evidence)
	case "equals":
		matched = strings.EqualFold(strings.TrimSpace(observed), strings.TrimSpace(matcher.value))
	case "contains", "contains_ci":
		if matcher.operator == "contains_ci" {
			matched = strings.Contains(strings.ToLower(observed), strings.ToLower(matcher.value))
		} else {
			matched = strings.Contains(observed, matcher.value)
		}
	case "like":
		pattern := regexp.QuoteMeta(matcher.value)
		pattern = strings.ReplaceAll(pattern, "%", ".*")
		pattern = strings.ReplaceAll(pattern, "_", ".")
		matched, _ = regexp.MatchString("^"+pattern+"$", observed)
	case "regex", "regex_ci":
		indices := matcher.expression.FindStringSubmatchIndex(observed)
		matched = indices != nil
		if matched {
			version = expandRegexTemplate(matcher.expression, matcher.versionCapture, observed, indices)
			cpe = expandRegexTemplate(matcher.expression, cpeTemplate, observed, indices)
		}
	}
	if !matched {
		return groupOutcome{}
	}
	sum := sha256.Sum256([]byte(observed))
	sha := hex.EncodeToString(sum[:])
	summary := fmt.Sprintf("%s", matcher.evidenceType)
	if matcher.target != "" {
		summary += " " + matcher.target
	}
	summary += fmt.Sprintf(" bytes=%d sha256=%s", len(observed), sha)
	if truncated {
		summary += " truncated"
	}
	return groupOutcome{matched: true, version: version, cpe: cpe, hits: []MatcherHit{{
		MatcherID: matcher.id, EvidenceType: matcher.evidenceType, Target: matcher.target, Operator: matcher.operator,
		ObservedSHA256: sha, ObservedLength: len(observed), Truncated: truncated, Summary: summary,
	}}}
}

func structuredEvidenceRequiresPresence(evidenceType string) bool {
	switch evidenceType {
	case "http_header", "html_meta", "http_cookie":
		return true
	default:
		return false
	}
}

func normalizedEvidencePresent(matcher compiledMatcher, evidence Evidence) bool {
	switch matcher.evidenceType {
	case "http_header":
		for key := range evidence.Headers {
			if strings.EqualFold(key, matcher.target) {
				return true
			}
		}
	case "html_meta":
		_, exists := evidence.Meta[strings.ToLower(matcher.target)]
		return exists
	case "http_cookie":
		_, exists := evidence.Cookies[strings.ToLower(matcher.target)]
		return exists
	}
	return false
}

func normalizedEvidenceValue(matcher compiledMatcher, evidence Evidence) (string, bool) {
	switch matcher.evidenceType {
	case "status_code":
		return strconv.Itoa(evidence.StatusCode), false
	case "http_header":
		if matcher.target != "" {
			return headerValue(evidence.Headers, matcher.target), evidence.HeaderTruncated
		}
		return normalizedHeaderText(evidence.Headers), evidence.HeaderTruncated
	case "html_meta":
		return evidence.Meta[strings.ToLower(matcher.target)], evidence.BodyTruncated
	case "http_cookie":
		return evidence.Cookies[strings.ToLower(matcher.target)], evidence.HeaderTruncated
	case "http_url":
		return evidence.URL, false
	case "html_title":
		return evidence.Title, evidence.BodyTruncated
	case "tcp_banner":
		return evidence.Banner, evidence.BannerTruncated
	case "favicon_hash":
		switch matcher.target {
		case "md5":
			return firstNonEmpty(evidence.FaviconMD5, legacyFaviconValue(evidence.FaviconHash, 32)), false
		case "mmh3":
			return firstNonEmpty(evidence.FaviconMMH3, legacyNumericFaviconValue(evidence.FaviconHash)), false
		case "sha256":
			return firstNonEmpty(evidence.FaviconSHA256, legacyFaviconValue(evidence.FaviconHash, 64)), false
		}
	default:
		return evidence.Body, evidence.BodyTruncated
	}
	return "", false
}

func expandRegexTemplate(expression *regexp.Regexp, template, observed string, indices []int) string {
	if expression == nil || strings.TrimSpace(template) == "" || indices == nil {
		return ""
	}
	expanded := wappConditionalTemplate.ReplaceAllStringFunc(template, func(value string) string {
		parts := wappConditionalTemplate.FindStringSubmatch(value)
		branch := parts[3]
		if regexCapture(observed, indices, parts[1]) != "" {
			branch = parts[2]
		}
		decoded, err := strconv.Unquote(`"` + branch + `"`)
		if err != nil {
			return ""
		}
		return decoded
	})
	expanded = nmapSubstTemplate.ReplaceAllStringFunc(expanded, func(value string) string {
		parts := nmapSubstTemplate.FindStringSubmatch(value)
		capture := regexCapture(observed, indices, parts[1])
		from, errFrom := strconv.Unquote(`"` + parts[2] + `"`)
		to, errTo := strconv.Unquote(`"` + parts[3] + `"`)
		if errFrom != nil || errTo != nil {
			return ""
		}
		return strings.ReplaceAll(capture, from, to)
	})
	expanded = nmapPrintableTemplate.ReplaceAllStringFunc(expanded, func(value string) string {
		parts := nmapPrintableTemplate.FindStringSubmatch(value)
		return printableCapture(regexCapture(observed, indices, parts[1]))
	})
	return string(expression.ExpandString(nil, expanded, observed, indices))
}

var (
	wappConditionalTemplate = regexp.MustCompile(`\$WAPP\(([0-9]+),"((?:\\.|[^"])*)","((?:\\.|[^"])*)"\)`)
	nmapSubstTemplate       = regexp.MustCompile(`\$SUBST\(([0-9]+),"((?:\\.|[^"])*)","((?:\\.|[^"])*)"\)`)
	nmapPrintableTemplate   = regexp.MustCompile(`\$P\(([0-9]+)\)`)
	nmapSimpleCapture       = regexp.MustCompile(`\$[0-9]+`)
)

func nmapTemplateSupported(template string) bool {
	remainder := nmapSubstTemplate.ReplaceAllString(template, "")
	remainder = nmapPrintableTemplate.ReplaceAllString(remainder, "")
	remainder = nmapSimpleCapture.ReplaceAllString(remainder, "")
	return !strings.Contains(remainder, "$")
}

func regexCapture(observed string, indices []int, rawIndex string) string {
	index, err := strconv.Atoi(rawIndex)
	if err != nil || index < 0 || index*2+1 >= len(indices) {
		return ""
	}
	start, end := indices[index*2], indices[index*2+1]
	if start < 0 || end < start || end > len(observed) {
		return ""
	}
	return observed[start:end]
}

func printableCapture(value string) string {
	var output strings.Builder
	for _, current := range []byte(value) {
		if current >= 0x20 && current <= 0x7e {
			output.WriteByte(current)
		}
	}
	return output.String()
}

func headerValue(headers map[string]string, expected string) string {
	for key, value := range headers {
		if strings.EqualFold(key, expected) {
			return value
		}
	}
	return ""
}

func normalizedHeaderText(headers map[string]string) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, key := range keys {
		out.WriteString(key)
		out.WriteString(": ")
		out.WriteString(headers[key])
		out.WriteByte('\n')
	}
	return out.String()
}

func legacyFaviconValue(values string, length int) string {
	for _, value := range strings.Fields(values) {
		if len(value) == length {
			return value
		}
	}
	return ""
}

func legacyNumericFaviconValue(values string) string {
	for _, value := range strings.Fields(values) {
		if _, err := strconv.ParseInt(value, 10, 32); err == nil {
			return value
		}
	}
	return ""
}

func headersFromBanner(banner string) map[string]string {
	headers := map[string]string{}
	for _, line := range strings.Split(banner, "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok {
			headers[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return headers
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
