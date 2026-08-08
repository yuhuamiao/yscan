package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const NucleiTemplateIndexAdapterVersion = "nuclei-template-index-v2"

// NucleiTemplateIndexEntry is a content-pinned, low-side-effect template
// projection. AbsolutePath is execution-only and is never persisted.
type NucleiTemplateIndexEntry struct {
	TemplateID     string
	Path           string
	AbsolutePath   string
	SHA256         string
	Protocols      []string
	Products       []string
	CPEs           []string
	Tags           []string
	SelectionNames []string
}

type NucleiTemplateIndex struct {
	Root       string
	Revision   string
	Templates  []NucleiTemplateIndexEntry
	bySelector map[string][]int
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
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var document nucleiIndexDocument
		if err := yaml.Unmarshal(content, &document); err != nil {
			return nil
		}
		projection, ok := projectNucleiTemplateForIndex(document)
		if !ok {
			return nil
		}
		relative, err := filepath.Rel(base, path)
		if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return errors.New("nuclei template escaped index root")
		}
		if unsafeAutomaticTemplateIdentity(document.ID, filepath.ToSlash(relative)) {
			return nil
		}
		digest := sha256.Sum256(content)
		projection.TemplateID = strings.TrimSpace(document.ID)
		projection.Path = filepath.ToSlash(relative)
		projection.AbsolutePath = path
		projection.SHA256 = hex.EncodeToString(digest[:])
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
		Templates: entries, bySelector: make(map[string][]int),
	}
	for templateIndex, entry := range entries {
		for _, selector := range entry.SelectionNames {
			index.bySelector[selector] = append(index.bySelector[selector], templateIndex)
		}
	}
	return index, nil
}

func projectNucleiTemplateForIndex(document nucleiIndexDocument) (NucleiTemplateIndexEntry, bool) {
	if strings.TrimSpace(document.ID) == "" || nodeHasContent(document.Headless) || nodeHasContent(document.Code) || nodeHasContent(document.Javascript) || nodeHasContent(document.File) || nodeHasContent(document.Workflow) {
		return NucleiTemplateIndexEntry{}, false
	}
	tags := normalizedIndexValues(interfaceStrings(document.Info.Tags))
	actionable := false
	for _, tag := range tags {
		if _, unsafe := unsafeAutomaticTemplateTags[tag]; unsafe {
			return NucleiTemplateIndexEntry{}, false
		}
		if _, allowed := actionableAutomaticTemplateTags[tag]; allowed {
			actionable = true
		}
	}
	if !actionable {
		return NucleiTemplateIndexEntry{}, false
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
	products := normalizedIndexValues(interfaceStrings(document.Info.Metadata["product"]))
	cpes := uniqueTrimmedIndexValues(interfaceStrings(document.Info.Classification.CPE))
	selectors := make([]string, 0, len(products)+len(cpes)+len(tags))
	for _, product := range products {
		selectors = append(selectors, productAliasesForTemplateIndex(product)...)
	}
	for _, cpe := range cpes {
		if product := cpeProductSelector(cpe); product != "" {
			selectors = append(selectors, productAliasesForTemplateIndex(product)...)
		}
	}
	for _, tag := range tags {
		if !genericTemplateSelector(tag) {
			selectors = append(selectors, productAliasesForTemplateIndex(tag)...)
		}
	}
	selectors = normalizedIndexValues(selectors)
	if len(selectors) == 0 {
		return NucleiTemplateIndexEntry{}, false
	}
	return NucleiTemplateIndexEntry{Protocols: protocols, Products: products, CPEs: cpes, Tags: tags, SelectionNames: selectors}, true
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
	if cpeProduct := cpeProductSelector(cpe); cpeProduct != "" {
		selectors = append(selectors, productAliasesForTemplateIndex(cpeProduct)...)
	}
	seen := make(map[int]struct{})
	result := make([]NucleiTemplateIndexEntry, 0)
	for _, selector := range normalizedIndexValues(selectors) {
		for _, templateIndex := range index.bySelector[selector] {
			if _, exists := seen[templateIndex]; exists || !templateProtocolCompatible(index.Templates[templateIndex].Protocols, protocol) {
				continue
			}
			seen[templateIndex] = struct{}{}
			result = append(result, index.Templates[templateIndex])
		}
	}
	return result
}

func safeReadOnlyTCPInput(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return true
	}
	value = strings.ReplaceAll(value, "\\r", "")
	value = strings.ReplaceAll(value, "\\n", "")
	for _, prefix := range []string{"info", "ping", "quit", "version", "help", "stats", "status"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
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

func cpeProductSelector(value string) string {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) >= 5 && parts[0] == "cpe" && parts[1] == "2.3" {
		return normalizeTemplateSelector(parts[4])
	}
	if len(parts) >= 4 && parts[0] == "cpe" && strings.HasPrefix(parts[1], "/") {
		return normalizeTemplateSelector(parts[3])
	}
	return ""
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

func nodeHasContent(node yaml.Node) bool {
	return node.Kind != 0 && len(node.Content) > 0
}
