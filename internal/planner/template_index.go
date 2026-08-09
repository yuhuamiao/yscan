package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

const NucleiTemplateIndexAdapterVersion = "nuclei-template-index-v5"

const (
	maxNucleiTemplateFileBytes   = 512 << 10
	maxNucleiTemplateTotalBytes  = 64 << 20
	maxNucleiTemplateFiles       = 20_000
	maxNucleiRequestsPerTemplate = 4
	maxNucleiPathsPerRequest     = 8
	maxNucleiInputsPerRequest    = 4
	maxNucleiMatchersPerRequest  = 16
	maxNucleiMatcherValues       = 64
	maxNucleiMatcherValueBytes   = 4096
)

type NucleiProductSelector struct {
	Vendor  string
	Product string
}

type NucleiCPEConstraint struct {
	Part    string
	Vendor  string
	Product string
	Version string
}

// NucleiTemplateIndexEntry is a content-pinned, low-side-effect template
// projection. AbsolutePath is execution-only and is never persisted.
type NucleiTemplateIndexEntry struct {
	TemplateID          string
	Path                string
	SHA256              string
	Content             []byte
	Protocols           []string
	Products            []string
	CPEs                []string
	Tags                []string
	ProductSelectors    []NucleiProductSelector
	CPEConstraints      []NucleiCPEConstraint
	ReviewedTagProducts []string
	SelectionNames      []string
}

type NucleiTemplateIndex struct {
	Root               string
	Revision           string
	Templates          []NucleiTemplateIndexEntry
	bySelector         map[string][]int
	filteredBySelector map[string][]NucleiTemplateIndexEntry
}

type nucleiIndexDocument struct {
	ID   string `yaml:"id"`
	Info struct {
		Classification struct {
			CPE interface{} `yaml:"cpe"`
		} `yaml:"classification"`
		Metadata map[string]interface{} `yaml:"metadata"`
		Tags     interface{}            `yaml:"tags"`
	} `yaml:"info"`
	HTTP []struct {
		Method string   `yaml:"method"`
		Raw    []string `yaml:"raw"`
	} `yaml:"http"`
	TCP []struct {
		Inputs []struct {
			Data string `yaml:"data"`
		} `yaml:"inputs"`
	} `yaml:"tcp"`
	Headless   yaml.Node `yaml:"headless"`
	Code       yaml.Node `yaml:"code"`
	Javascript yaml.Node `yaml:"javascript"`
	File       yaml.Node `yaml:"file"`
	Workflow   yaml.Node `yaml:"workflows"`
}

var unsafeAutomaticTemplateTags = map[string]struct{}{
	"auth": {}, "bruteforce": {}, "code": {}, "csrf": {}, "default-login": {}, "deserialization": {}, "dos": {},
	"fuzz": {}, "fuzzing": {}, "headless": {}, "intrusive": {}, "javascript": {}, "lfi": {}, "oast": {}, "rce": {},
	"redirect": {}, "sqli": {}, "ssrf": {}, "takeover": {}, "upload": {}, "xss": {}, "xxe": {},
}

var actionableAutomaticTemplateTags = map[string]struct{}{
	"config": {}, "cve": {}, "exposure": {}, "misconfig": {}, "misconfiguration": {}, "panel": {},
	"unauth": {}, "vuln": {}, "vulnerability": {},
}

// Tags are execution selectors only after an explicit source review. Generic
// ecosystem/runtime tags never become product identities automatically.
var reviewedAutomaticProductTags = map[string]string{
	"apache": "apache", "avtech": "avtech", "dropbear": "dropbear", "iis": "iis", "jenkins": "jenkins",
	"mysql": "mysql", "nginx": "nginx", "openssh": "openssh", "redis": "redis", "wordpress": "wordpress",
}

// BuildNucleiTemplateIndex parses a local template tree into a deterministic
// executable projection. Files that cannot be represented conservatively are
// ignored rather than guessed.
func BuildNucleiTemplateIndex(root string) (*NucleiTemplateIndex, error) {
	base, err := filepath.Abs(strings.TrimSpace(root))
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(base)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("nuclei template root is not a directory: %s", root)
	}
	entries := make([]NucleiTemplateIndexEntry, 0)
	filteredBySelector := make(map[string][]NucleiTemplateIndexEntry)
	fileCount := 0
	totalBytes := int64(0)
	err = filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if path != base && (strings.HasPrefix(name, ".") || name == "helpers" || (filepath.Dir(path) == base && name == "dast")) {
				return filepath.SkipDir
			}
			return nil
		}
		extension := strings.ToLower(filepath.Ext(path))
		if extension != ".yaml" && extension != ".yml" {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("nuclei template candidate is a symbolic link: %s", path)
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("nuclei template candidate is not a regular file: %s", path)
		}
		fileCount++
		if fileCount > maxNucleiTemplateFiles {
			return fmt.Errorf("nuclei template file budget exceeded: %d", maxNucleiTemplateFiles)
		}
		declaredBytes := fileInfo.Size()
		if declaredBytes < 0 || declaredBytes > maxNucleiTemplateTotalBytes-totalBytes {
			return fmt.Errorf("nuclei template byte budget exceeded: %d", maxNucleiTemplateTotalBytes)
		}
		if declaredBytes > maxNucleiTemplateFileBytes {
			totalBytes += declaredBytes
			return nil
		}
		content, accountedBytes, err := readBoundedNucleiTemplate(path, maxNucleiTemplateTotalBytes-totalBytes)
		if err != nil {
			return err
		}
		totalBytes += accountedBytes
		if content == nil {
			return nil
		}
		var rootNode yaml.Node
		if err := yaml.Unmarshal(content, &rootNode); err != nil {
			return nil
		}
		var document nucleiIndexDocument
		if err := rootNode.Decode(&document); err != nil {
			return nil
		}
		if !safeAutomaticNucleiTemplate(rootNode) {
			markPolicyFilteredSelectors(filteredBySelector, document)
			return nil
		}
		projection, ok := projectNucleiTemplateForIndex(document)
		if !ok {
			markPolicyFilteredSelectors(filteredBySelector, document)
			return nil
		}
		relative, err := filepath.Rel(base, path)
		if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return errors.New("nuclei template escaped index root")
		}
		if unsafeAutomaticTemplateIdentity(document.ID, filepath.ToSlash(relative)) {
			markPolicyFilteredSelectors(filteredBySelector, document)
			return nil
		}
		digest := sha256.Sum256(content)
		projection.TemplateID = strings.TrimSpace(document.ID)
		projection.Path = filepath.ToSlash(relative)
		projection.SHA256 = hex.EncodeToString(digest[:])
		projection.Content = append([]byte(nil), content...)
		entries = append(entries, projection)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(left, right int) bool {
		if entries[left].TemplateID != entries[right].TemplateID {
			return entries[left].TemplateID < entries[right].TemplateID
		}
		return entries[left].Path < entries[right].Path
	})
	hasher := sha256.New()
	for _, entry := range entries {
		_, _ = fmt.Fprintf(hasher, "%s\x00%s\x00%s\x00%s\x00%s\n", entry.TemplateID, entry.Path, entry.SHA256, strings.Join(entry.Protocols, ","), strings.Join(entry.SelectionNames, ","))
	}
	index := &NucleiTemplateIndex{
		Root: base, Revision: NucleiTemplateIndexAdapterVersion + ":" + hex.EncodeToString(hasher.Sum(nil)),
		Templates: entries, bySelector: make(map[string][]int), filteredBySelector: filteredBySelector,
	}
	for templateIndex, entry := range entries {
		for _, selector := range entry.SelectionNames {
			index.bySelector[selector] = append(index.bySelector[selector], templateIndex)
		}
	}
	return index, nil
}

func readBoundedNucleiTemplate(path string, remainingBytes int64) ([]byte, int64, error) {
	file, err := openNucleiTemplateFile(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !fileInfo.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("nuclei template descriptor is not a regular file: %s", path)
	}
	accountedBytes := fileInfo.Size()
	if accountedBytes < 0 || accountedBytes > remainingBytes {
		return nil, 0, fmt.Errorf("nuclei template byte budget exceeded: %d", maxNucleiTemplateTotalBytes)
	}
	if accountedBytes > maxNucleiTemplateFileBytes {
		return nil, accountedBytes, nil
	}
	content, err := io.ReadAll(io.LimitReader(file, maxNucleiTemplateFileBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if size := int64(len(content)); size > accountedBytes {
		accountedBytes = size
	}
	postReadInfo, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !postReadInfo.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("nuclei template descriptor changed file type: %s", path)
	}
	if postReadInfo.Size() > accountedBytes {
		accountedBytes = postReadInfo.Size()
	}
	if accountedBytes < 0 || accountedBytes > remainingBytes {
		return nil, 0, fmt.Errorf("nuclei template byte budget exceeded: %d", maxNucleiTemplateTotalBytes)
	}
	if len(content) > maxNucleiTemplateFileBytes {
		return nil, accountedBytes, nil
	}
	return content, accountedBytes, nil
}

// PolicyFiltered reports whether at least one actionable template for this
// exact product/protocol was excluded by the strict execution projection. It
// never exposes or executes the rejected template.
func (index *NucleiTemplateIndex) PolicyFiltered(product, cpe, protocol string) bool {
	if index == nil {
		return false
	}
	selectors := productAliasesForTemplateIndex(product)
	endpointCPE, hasEndpointCPE := parseNucleiCPE(cpe)
	if hasEndpointCPE {
		selectors = append(selectors, productAliasesForTemplateIndex(endpointCPE.Product)...)
	}
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "https" {
		protocol = "http"
	}
	for _, selector := range normalizedIndexValues(selectors) {
		for _, entry := range index.filteredBySelector[selector+"\x00"+protocol] {
			if templateProtocolCompatible(entry.Protocols, protocol) && templateProductCompatible(entry, product, endpointCPE, hasEndpointCPE) {
				return true
			}
		}
	}
	return false
}

func markPolicyFilteredSelectors(filtered map[string][]NucleiTemplateIndexEntry, document nucleiIndexDocument) {
	entry, ok := projectNucleiTemplateSelectors(document)
	if !ok {
		return
	}
	for _, selector := range entry.SelectionNames {
		for _, protocol := range entry.Protocols {
			key := selector + "\x00" + protocol
			filtered[key] = append(filtered[key], entry)
		}
	}
}

func projectNucleiTemplateSelectors(document nucleiIndexDocument) (NucleiTemplateIndexEntry, bool) {
	tags := normalizedIndexValues(interfaceStrings(document.Info.Tags))
	actionable := false
	for _, tag := range tags {
		if _, allowed := actionableAutomaticTemplateTags[tag]; allowed {
			actionable = true
		}
	}
	if !actionable {
		return NucleiTemplateIndexEntry{}, false
	}
	products := normalizedIndexValues(interfaceStrings(document.Info.Metadata["product"]))
	vendors := normalizedIndexValues(interfaceStrings(document.Info.Metadata["vendor"]))
	productSelectors := make([]NucleiProductSelector, 0, len(products))
	selectors := make([]string, 0, len(products)+len(tags))
	for _, product := range products {
		vendor := ""
		if len(vendors) == 1 {
			vendor = vendors[0]
		}
		productSelectors = append(productSelectors, NucleiProductSelector{Vendor: vendor, Product: product})
		selectors = append(selectors, productAliasesForTemplateIndex(product)...)
	}
	cpes := uniqueTrimmedIndexValues(interfaceStrings(document.Info.Classification.CPE))
	cpeConstraints := make([]NucleiCPEConstraint, 0, len(cpes))
	for _, rawCPE := range cpes {
		constraint, ok := parseNucleiCPE(rawCPE)
		if !ok {
			return NucleiTemplateIndexEntry{}, false
		}
		cpeConstraints = append(cpeConstraints, constraint)
		selectors = append(selectors, productAliasesForTemplateIndex(constraint.Product)...)
	}
	reviewedTags := make([]string, 0)
	for _, tag := range tags {
		if product, reviewed := reviewedAutomaticProductTags[tag]; reviewed {
			reviewedTags = append(reviewedTags, product)
			selectors = append(selectors, productAliasesForTemplateIndex(product)...)
		}
	}
	protocols := make([]string, 0, 2)
	if len(document.HTTP) > 0 {
		protocols = append(protocols, "http")
	}
	if len(document.TCP) > 0 {
		protocols = append(protocols, "tcp")
	}
	selectors = normalizedIndexValues(selectors)
	if len(protocols) == 0 || len(selectors) == 0 {
		return NucleiTemplateIndexEntry{}, false
	}
	return NucleiTemplateIndexEntry{
		Protocols: protocols, Products: products, CPEs: cpes, Tags: tags,
		ProductSelectors: productSelectors, CPEConstraints: cpeConstraints,
		ReviewedTagProducts: normalizedIndexValues(reviewedTags), SelectionNames: selectors,
	}, true
}

func projectNucleiTemplateForIndex(document nucleiIndexDocument) (NucleiTemplateIndexEntry, bool) {
	if strings.TrimSpace(document.ID) == "" || nodeHasContent(document.Headless) || nodeHasContent(document.Code) || nodeHasContent(document.Javascript) || nodeHasContent(document.File) || nodeHasContent(document.Workflow) {
		return NucleiTemplateIndexEntry{}, false
	}
	projection, ok := projectNucleiTemplateSelectors(document)
	if !ok {
		return NucleiTemplateIndexEntry{}, false
	}
	for _, tag := range projection.Tags {
		if _, unsafe := unsafeAutomaticTemplateTags[tag]; unsafe {
			return NucleiTemplateIndexEntry{}, false
		}
	}
	protocols := make([]string, 0, 2)
	if len(document.HTTP) > 0 {
		for _, request := range document.HTTP {
			method := strings.ToUpper(strings.TrimSpace(request.Method))
			if method != "" && method != "GET" && method != "HEAD" {
				return NucleiTemplateIndexEntry{}, false
			}
			for _, raw := range request.Raw {
				firstLine := strings.ToUpper(strings.TrimSpace(strings.SplitN(raw, "\n", 2)[0]))
				if firstLine != "" && !strings.HasPrefix(firstLine, "GET ") && !strings.HasPrefix(firstLine, "HEAD ") {
					return NucleiTemplateIndexEntry{}, false
				}
			}
		}
		protocols = append(protocols, "http")
	}
	if len(document.TCP) > 0 {
		for _, request := range document.TCP {
			for _, input := range request.Inputs {
				if !safeReadOnlyTCPInput(input.Data) {
					return NucleiTemplateIndexEntry{}, false
				}
			}
		}
		protocols = append(protocols, "tcp")
	}
	if len(protocols) == 0 {
		return NucleiTemplateIndexEntry{}, false
	}
	projection.Protocols = protocols
	return projection, true
}

func unsafeAutomaticTemplateIdentity(templateID, path string) bool {
	identity := strings.ToLower(templateID + " " + path)
	identity = strings.NewReplacer("_", "-", "/", "-", "\\", "-").Replace(identity)
	for _, marker := range []string{
		"bruteforce", "code-injection", "command-injection", "default-login", "deserialization", "file-upload",
		"remote-code-execution", "-rce", "-ssti", "sql-injection", "-sqli", "-ssrf", "takeover", "-xss", "-xxe",
	} {
		if strings.Contains(identity, marker) {
			return true
		}
	}
	return false
}

func (index *NucleiTemplateIndex) Select(product, cpe, protocol string) []NucleiTemplateIndexEntry {
	if index == nil {
		return nil
	}
	selectors := productAliasesForTemplateIndex(product)
	endpointCPE, hasEndpointCPE := parseNucleiCPE(cpe)
	if hasEndpointCPE {
		selectors = append(selectors, productAliasesForTemplateIndex(endpointCPE.Product)...)
	}
	seen := make(map[int]struct{})
	result := make([]NucleiTemplateIndexEntry, 0)
	for _, selector := range normalizedIndexValues(selectors) {
		for _, templateIndex := range index.bySelector[selector] {
			entry := index.Templates[templateIndex]
			if _, exists := seen[templateIndex]; exists || !templateProtocolCompatible(entry.Protocols, protocol) || !templateProductCompatible(entry, product, endpointCPE, hasEndpointCPE) {
				continue
			}
			seen[templateIndex] = struct{}{}
			result = append(result, entry)
		}
	}
	return result
}

func templateProductCompatible(entry NucleiTemplateIndexEntry, product string, endpointCPE NucleiCPEConstraint, hasEndpointCPE bool) bool {
	if len(entry.CPEConstraints) > 0 {
		if !hasEndpointCPE {
			return false
		}
		for _, constraint := range entry.CPEConstraints {
			if cpeConstraintCompatible(constraint, endpointCPE) {
				return true
			}
		}
		return false
	}
	for _, selector := range entry.ProductSelectors {
		if !templateProductNameEqual(selector.Product, product) {
			continue
		}
		if selector.Vendor == "" || (hasEndpointCPE && normalizeTemplateSelector(selector.Vendor) == normalizeTemplateSelector(endpointCPE.Vendor)) {
			return true
		}
	}
	for _, reviewed := range entry.ReviewedTagProducts {
		if templateProductNameEqual(reviewed, product) {
			return true
		}
	}
	return false
}

func templateProductNameEqual(left, right string) bool {
	rightAliases := normalizedIndexValues(productAliasesForTemplateIndex(right))
	for _, leftAlias := range normalizedIndexValues(productAliasesForTemplateIndex(left)) {
		for _, rightAlias := range rightAliases {
			if leftAlias == rightAlias {
				return true
			}
		}
	}
	return false
}

func cpeConstraintCompatible(template, endpoint NucleiCPEConstraint) bool {
	if template.Part != endpoint.Part || normalizeTemplateSelector(template.Vendor) != normalizeTemplateSelector(endpoint.Vendor) || !templateProductNameEqual(template.Product, endpoint.Product) {
		return false
	}
	return template.Version == "" || template.Version == "*" || template.Version == "-" || (endpoint.Version != "" && endpoint.Version != "*" && endpoint.Version != "-" && strings.EqualFold(template.Version, endpoint.Version))
}

func safeReadOnlyTCPInput(value string) bool {
	if len(value) > 1024 || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	value = strings.ReplaceAll(value, `\r`, "\r")
	value = strings.ReplaceAll(value, `\n`, "\n")
	if strings.Contains(value, `\`) {
		return false
	}
	value = strings.ReplaceAll(value, "\r\n", "\n")
	if strings.Contains(value, "\r") {
		return false
	}
	value = strings.TrimSuffix(value, "\n")
	if strings.TrimSpace(value) == "" {
		return true
	}
	for _, frame := range strings.Split(value, "\n") {
		if frame == "" || strings.TrimSpace(frame) != frame {
			return false
		}
		fields := strings.Fields(strings.ToLower(frame))
		if len(fields) == 0 {
			return false
		}
		switch fields[0] {
		case "info":
			if len(fields) > 2 || (len(fields) == 2 && !safeRedisInfoSection(fields[1])) {
				return false
			}
		case "ping", "quit":
			if len(fields) != 1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func safeRedisInfoSection(value string) bool {
	_, ok := map[string]struct{}{
		"server": {}, "clients": {}, "memory": {}, "persistence": {}, "stats": {}, "replication": {},
		"cpu": {}, "commandstats": {}, "latencystats": {}, "sentinel": {}, "cluster": {}, "modules": {},
		"keyspace": {}, "errorstats": {}, "all": {}, "default": {}, "everything": {},
	}[strings.ToLower(strings.TrimSpace(value))]
	return ok
}

func templateProtocolCompatible(protocols []string, endpointProtocol string) bool {
	endpointProtocol = strings.ToLower(strings.TrimSpace(endpointProtocol))
	for _, protocol := range protocols {
		if protocol == "http" && (endpointProtocol == "http" || endpointProtocol == "https") {
			return true
		}
		if protocol == "tcp" && endpointProtocol == "tcp" {
			return true
		}
	}
	return false
}

func productAliasesForTemplateIndex(value string) []string {
	value = normalizeTemplateSelector(value)
	switch value {
	case "apache", "apache http server", "apache httpd", "httpd":
		return []string{"apache", "apache http server", "apache httpd", "httpd"}
	case "dropbear sshd", "dropbear ssh server", "dropbear":
		return []string{"dropbear", "dropbear sshd", "dropbear ssh server"}
	case "microsoft iis", "iis":
		return []string{"iis", "microsoft iis"}
	}
	if value == "" {
		return nil
	}
	return []string{value}
}

func normalizeTemplateSelector(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer("_", " ", "-", " ", ".", " ").Replace(value)
	return strings.Join(strings.Fields(value), " ")
}

func parseNucleiCPE(value string) (NucleiCPEConstraint, bool) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) >= 6 && parts[0] == "cpe" && parts[1] == "2.3" {
		result := NucleiCPEConstraint{Part: strings.ToLower(parts[2]), Vendor: normalizeTemplateSelector(parts[3]), Product: normalizeTemplateSelector(parts[4]), Version: strings.TrimSpace(parts[5])}
		return result, result.Part != "" && result.Vendor != "" && result.Product != ""
	}
	if len(parts) >= 4 && parts[0] == "cpe" && strings.HasPrefix(parts[1], "/") {
		version := "*"
		if len(parts) >= 5 {
			version = strings.TrimSpace(parts[4])
		}
		result := NucleiCPEConstraint{Part: strings.ToLower(strings.TrimPrefix(parts[1], "/")), Vendor: normalizeTemplateSelector(parts[2]), Product: normalizeTemplateSelector(parts[3]), Version: version}
		return result, result.Part != "" && result.Vendor != "" && result.Product != ""
	}
	return NucleiCPEConstraint{}, false
}

func interfaceStrings(value interface{}) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		return strings.Split(typed, ",")
	case []string:
		return typed
	case []interface{}:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			result = append(result, interfaceStrings(item)...)
		}
		return result
	default:
		return []string{fmt.Sprint(typed)}
	}
}

func normalizedIndexValues(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = normalizeTemplateSelector(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func uniqueTrimmedIndexValues(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func genericTemplateSelector(value string) bool {
	_, generic := map[string]struct{}{
		"cve": {}, "discovery": {}, "exposure": {}, "http": {}, "https": {}, "info": {}, "misconfiguration": {},
		"network": {}, "ssl": {}, "tcp": {}, "tech": {}, "technology": {}, "tls": {}, "unauth": {}, "vuln": {},
	}[value]
	return generic
}

func safeAutomaticNucleiTemplate(root yaml.Node) bool {
	document := yamlDocumentMapping(root)
	if document == nil {
		return false
	}
	return validateYAMLMapping(document, map[string]func(*yaml.Node) bool{
		"id":   yamlScalar,
		"info": validateNucleiInfo,
		"http": validateNucleiHTTPRequests,
		"tcp":  validateNucleiTCPRequests,
	})
}

func validateNucleiInfo(node *yaml.Node) bool {
	text := yamlScalarOrSequence
	return validateYAMLMapping(node, map[string]func(*yaml.Node) bool{
		"name": text, "author": text, "severity": yamlScalar, "description": text,
		"impact": text, "remediation": text, "reference": text, "tags": text,
		"classification": func(value *yaml.Node) bool {
			return validateYAMLMapping(value, map[string]func(*yaml.Node) bool{
				"cpe": text, "cvss-metrics": text, "cvss-score": yamlScalar, "cwe-id": text,
				"cve-id": text, "epss-score": yamlScalar, "epss-percentile": yamlScalar,
			})
		},
		"metadata": func(value *yaml.Node) bool {
			return validateYAMLMapping(value, map[string]func(*yaml.Node) bool{
				"product": text, "vendor": text, "max-request": yamlNonNegativeInteger, "verified": yamlBoolean,
				"shodan-query": text,
			})
		},
	})
}

func validateNucleiHTTPRequests(node *yaml.Node) bool {
	return validateYAMLSequenceLimit(node, maxNucleiRequestsPerTemplate, func(request *yaml.Node) bool {
		return validateYAMLMapping(request, map[string]func(*yaml.Node) bool{
			"method": func(value *yaml.Node) bool {
				method := strings.ToUpper(strings.TrimSpace(value.Value))
				return yamlScalar(value) && (method == "GET" || method == "HEAD")
			},
			"path":               validateSafeHTTPPaths,
			"matchers-condition": validateMatcherCondition,
			"matchers":           validateNucleiMatchers,
		})
	})
}

func validateSafeHTTPPaths(node *yaml.Node) bool {
	return validateScalarValuesLimit(node, maxNucleiPathsPerRequest, safeAutomaticHTTPURL)
}

func safeAutomaticHTTPURL(value string) bool {
	if len(value) > 4096 || strings.Contains(value, "§") || strings.Contains(strings.ToLower(value), "interactsh") {
		return false
	}
	expanded := value
	for {
		start := strings.Index(expanded, "{{")
		if start < 0 {
			break
		}
		endOffset := strings.Index(expanded[start+2:], "}}")
		if endOffset < 0 {
			return false
		}
		end := start + 2 + endOffset
		variable := strings.TrimSpace(expanded[start+2 : end])
		if variable != "BaseURL" && variable != "RootURL" {
			return false
		}
		expanded = expanded[:start] + "http://caasm.invalid" + expanded[end+2:]
	}
	parsed, err := url.Parse(expanded)
	if err != nil || parsed.Scheme != "http" || parsed.Host != "caasm.invalid" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		query, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			return false
		}
		for name, values := range query {
			if authenticationParameterName(recursiveURLDecode(name)) {
				return false
			}
			for _, value := range values {
				if containsAuthenticationMarker(recursiveURLDecode(value)) {
					return false
				}
			}
		}
		// Automatic execution intentionally rejects every query. Query-bearing
		// templates require an explicit content-SHA review outside this projection.
		return false
	}
	decodedPath := parsed.EscapedPath()
	for attempts := 0; attempts < 3; attempts++ {
		decoded, err := url.PathUnescape(decodedPath)
		if err != nil {
			return false
		}
		if decoded == decodedPath {
			break
		}
		decodedPath = decoded
	}
	if strings.ContainsAny(decodedPath, "%?#\x00\r\n") {
		return false
	}
	for _, segment := range strings.Split(strings.ToLower(decodedPath), "/") {
		segment = strings.TrimSpace(segment)
		if unsafeAutomaticHTTPPathSegment(segment) {
			return false
		}
	}
	return true
}

var unsafeAutomaticHTTPPathSegments = map[string]struct{}{
	"command": {}, "delete": {}, "drop": {}, "execute": {}, "flush": {}, "flushall": {}, "install": {},
	"logout": {}, "reboot": {}, "remove": {}, "reset": {}, "restart": {}, "shutdown": {}, "truncate": {},
	"update": {}, "upgrade": {}, "upload": {}, "write": {},
}

func unsafeAutomaticHTTPPathSegment(segment string) bool {
	for _, token := range strings.FieldsFunc(strings.ToLower(segment), func(character rune) bool {
		return !unicode.IsLetter(character) && !unicode.IsDigit(character)
	}) {
		if _, unsafe := unsafeAutomaticHTTPPathSegments[token]; unsafe {
			return true
		}
		if authenticationParameterName(token) {
			return true
		}
	}
	return authenticationParameterName(segment)
}

func authenticationParameterName(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer("-", "", "_", "", ".", "").Replace(value)
	_, unsafe := map[string]struct{}{
		"apikey": {}, "auth": {}, "authorization": {}, "credential": {}, "login": {}, "pass": {}, "passwd": {},
		"password": {}, "pwd": {}, "secret": {}, "session": {}, "token": {}, "user": {}, "username": {},
	}[value]
	return unsafe
}

func recursiveURLDecode(value string) string {
	for attempts := 0; attempts < 3; attempts++ {
		decoded, err := url.QueryUnescape(value)
		if err != nil || decoded == value {
			break
		}
		value = decoded
	}
	return value
}

func containsAuthenticationMarker(value string) bool {
	for _, field := range strings.FieldsFunc(strings.ToLower(value), func(character rune) bool {
		return character == '=' || character == '&' || character == '?' || character == '/' || character == ':' || character == ';'
	}) {
		if authenticationParameterName(field) {
			return true
		}
	}
	return false
}

func validateNucleiTCPRequests(node *yaml.Node) bool {
	return validateYAMLSequenceLimit(node, maxNucleiRequestsPerTemplate, func(request *yaml.Node) bool {
		return validateYAMLMapping(request, map[string]func(*yaml.Node) bool{
			"inputs": func(value *yaml.Node) bool {
				return validateYAMLSequenceLimit(value, maxNucleiInputsPerRequest, func(input *yaml.Node) bool {
					return validateYAMLMapping(input, map[string]func(*yaml.Node) bool{
						"data": func(data *yaml.Node) bool { return yamlScalar(data) && safeReadOnlyTCPInput(data.Value) },
					})
				})
			},
			"host": func(value *yaml.Node) bool {
				return validateScalarValues(value, func(host string) bool {
					host = strings.TrimSpace(host)
					return host == "{{Hostname}}" || host == "tls://{{Hostname}}"
				})
			},
			"port": func(value *yaml.Node) bool {
				if !yamlScalar(value) {
					return false
				}
				for _, raw := range strings.Split(value.Value, ",") {
					port, err := strconv.Atoi(strings.TrimSpace(raw))
					if err != nil || port < 1 || port > 65535 {
						return false
					}
				}
				return true
			},
			"read-size": func(value *yaml.Node) bool {
				if !yamlNonNegativeInteger(value) {
					return false
				}
				size, _ := strconv.Atoi(value.Value)
				return size <= 16384
			},
			"matchers-condition": validateMatcherCondition,
			"matchers":           validateNucleiMatchers,
		})
	})
}

func validateNucleiMatchers(node *yaml.Node) bool {
	return validateYAMLSequenceLimit(node, maxNucleiMatchersPerRequest, func(matcher *yaml.Node) bool {
		return validateYAMLMapping(matcher, map[string]func(*yaml.Node) bool{
			"type": yamlScalar, "part": yamlScalar, "condition": validateMatcherCondition,
			"words": boundedMatcherValues, "regex": boundedMatcherValues, "binary": boundedMatcherValues,
			"status": boundedMatcherValues, "size": boundedMatcherValues, "dsl": boundedMatcherValues,
			"negative": yamlBoolean, "case-insensitive": yamlBoolean, "internal": yamlBoolean,
			"encoding": yamlScalar, "name": yamlScalar,
		})
	})
}

func boundedMatcherValues(node *yaml.Node) bool {
	return validateScalarValuesLimit(node, maxNucleiMatcherValues, func(value string) bool {
		return len(value) <= maxNucleiMatcherValueBytes && !strings.Contains(strings.ToLower(value), "interactsh")
	})
}

func validateMatcherCondition(node *yaml.Node) bool {
	value := strings.ToLower(strings.TrimSpace(node.Value))
	return yamlScalar(node) && (value == "and" || value == "or")
}

func yamlDocumentMapping(root yaml.Node) *yaml.Node {
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil
	}
	return root.Content[0]
}

func validateYAMLMapping(node *yaml.Node, allowed map[string]func(*yaml.Node) bool) bool {
	if node == nil || node.Kind != yaml.MappingNode || len(node.Content)%2 != 0 {
		return false
	}
	seen := make(map[string]struct{}, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index]
		value := node.Content[index+1]
		if key.Kind != yaml.ScalarNode {
			return false
		}
		name := strings.TrimSpace(key.Value)
		validator, ok := allowed[name]
		if !ok || validator == nil {
			return false
		}
		if _, duplicate := seen[name]; duplicate || !validator(value) {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

func validateYAMLSequence(node *yaml.Node, validate func(*yaml.Node) bool) bool {
	return validateYAMLSequenceLimit(node, 0, validate)
}

func validateYAMLSequenceLimit(node *yaml.Node, limit int, validate func(*yaml.Node) bool) bool {
	if node == nil || node.Kind != yaml.SequenceNode || len(node.Content) == 0 {
		return false
	}
	if limit > 0 && len(node.Content) > limit {
		return false
	}
	for _, value := range node.Content {
		if !validate(value) {
			return false
		}
	}
	return true
}

func validateScalarValues(node *yaml.Node, validate func(string) bool) bool {
	return validateScalarValuesLimit(node, 0, validate)
}

func validateScalarValuesLimit(node *yaml.Node, limit int, validate func(string) bool) bool {
	if yamlScalar(node) {
		return validate(node.Value)
	}
	return validateYAMLSequenceLimit(node, limit, func(value *yaml.Node) bool { return yamlScalar(value) && validate(value.Value) })
}

func yamlScalar(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.ScalarNode && node.Tag != "!!null" && node.Tag != "!!binary"
}

func yamlScalarOrSequence(node *yaml.Node) bool {
	return validateScalarValues(node, func(value string) bool {
		return !strings.Contains(strings.ToLower(value), "interactsh")
	})
}

func yamlNonNegativeInteger(node *yaml.Node) bool {
	if !yamlScalar(node) {
		return false
	}
	value, err := strconv.Atoi(strings.TrimSpace(node.Value))
	return err == nil && value >= 0
}

func yamlBoolean(node *yaml.Node) bool {
	if !yamlScalar(node) {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(node.Value))
	return value == "true" || value == "false"
}

func nodeHasContent(node yaml.Node) bool {
	return node.Kind != 0 && len(node.Content) > 0
}
