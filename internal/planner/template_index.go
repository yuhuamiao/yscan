package planner

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var nucleiTemplateProtocols = map[string]struct{}{
	"code":       {},
	"dns":        {},
	"file":       {},
	"headless":   {},
	"http":       {},
	"javascript": {},
	"network":    {},
	"smtp":       {},
	"ssl":        {},
	"tcp":        {},
	"websocket":  {},
	"whois":      {},
}

var nucleiTemplateSeverities = map[string]struct{}{
	"critical": {},
	"high":     {},
	"medium":   {},
	"low":      {},
	"info":     {},
	"unknown":  {},
}

// TemplateMetadata is the subset of a local Nuclei template used for
// deterministic planning. Path is always relative to the indexed directory.
type TemplateMetadata struct {
	ID        string   `json:"id"`
	Path      string   `json:"path"`
	Protocols []string `json:"protocols"`
	Tags      []string `json:"tags"`
	Severity  string   `json:"severity"`
}

// TemplateIndexDiagnostic describes one template file that could not be
// indexed safely. Diagnostics never cause valid sibling templates to vanish.
type TemplateIndexDiagnostic struct {
	Path   string `json:"path"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// TemplateIndex contains the usable local template metadata and diagnostics
// for skipped files. No network access or Nuclei executable is involved.
type TemplateIndex struct {
	Templates   []TemplateMetadata        `json:"templates"`
	Diagnostics []TemplateIndexDiagnostic `json:"diagnostics"`
}

// BuildNucleiTemplateIndex reads a local templates directory recursively. A
// malformed or unsupported template produces a diagnostic and does not block
// indexing the remaining files. Duplicate template IDs are excluded because a
// later selector must never choose an arbitrary duplicate.
func BuildNucleiTemplateIndex(root string) (TemplateIndex, error) {
	resolvedRoot, err := validateTemplateIndexRoot(root)
	if err != nil {
		return TemplateIndex{}, err
	}

	index := TemplateIndex{}
	err = filepath.WalkDir(resolvedRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		relativePath := templateIndexRelativePath(resolvedRoot, path)
		if walkErr != nil {
			if path == resolvedRoot {
				return walkErr
			}
			index.Diagnostics = append(index.Diagnostics, TemplateIndexDiagnostic{
				Path:   relativePath,
				Code:   "walk_error",
				Reason: walkErr.Error(),
			})
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			index.Diagnostics = append(index.Diagnostics, TemplateIndexDiagnostic{
				Path:   relativePath,
				Code:   "symlink_skipped",
				Reason: "symbolic links are not indexed outside the reviewed template tree",
			})
			return nil
		}
		if !isNucleiTemplateFile(path) {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			index.Diagnostics = append(index.Diagnostics, TemplateIndexDiagnostic{
				Path:   relativePath,
				Code:   "stat_error",
				Reason: err.Error(),
			})
			return nil
		}
		if !info.Mode().IsRegular() {
			index.Diagnostics = append(index.Diagnostics, TemplateIndexDiagnostic{
				Path:   relativePath,
				Code:   "non_regular_file",
				Reason: "template candidates must be regular files",
			})
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			index.Diagnostics = append(index.Diagnostics, TemplateIndexDiagnostic{
				Path:   relativePath,
				Code:   "read_error",
				Reason: err.Error(),
			})
			return nil
		}
		metadata, diagnostics := parseNucleiTemplateFile(relativePath, data)
		index.Templates = append(index.Templates, metadata...)
		index.Diagnostics = append(index.Diagnostics, diagnostics...)
		return nil
	})
	if err != nil {
		return TemplateIndex{}, fmt.Errorf("walk nuclei templates %s: %w", resolvedRoot, err)
	}

	index.excludeDuplicateTemplateIDs()
	index.sort()
	return index, nil
}

func validateTemplateIndexRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("empty nuclei templates path")
	}
	resolvedRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve nuclei templates path: %w", err)
	}
	info, err := os.Stat(resolvedRoot)
	if err != nil {
		return "", fmt.Errorf("nuclei templates path not found: %s", resolvedRoot)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("nuclei templates path is not a directory: %s", resolvedRoot)
	}
	return resolvedRoot, nil
}

func isNucleiTemplateFile(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	return extension == ".yaml" || extension == ".yml"
}

func templateIndexRelativePath(root, path string) string {
	relativePath, err := filepath.Rel(root, path)
	if err != nil || relativePath == "." {
		return "."
	}
	return filepath.ToSlash(relativePath)
}

func parseNucleiTemplateFile(path string, data []byte) ([]TemplateMetadata, []TemplateIndexDiagnostic) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	documents := make([]yaml.Node, 0, 1)
	for {
		var document yaml.Node
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, []TemplateIndexDiagnostic{{
				Path:   path,
				Code:   "invalid_yaml",
				Reason: err.Error(),
			}}
		}
		if document.Kind != 0 {
			documents = append(documents, document)
		}
	}
	if len(documents) != 1 {
		return nil, []TemplateIndexDiagnostic{{
			Path:   path,
			Code:   "invalid_document_count",
			Reason: "a Nuclei template file must contain exactly one YAML document",
		}}
	}

	metadata, diagnostic := parseNucleiTemplateDocument(path, &documents[0])
	if diagnostic != nil {
		return nil, []TemplateIndexDiagnostic{*diagnostic}
	}
	return []TemplateMetadata{metadata}, nil
}

func parseNucleiTemplateDocument(path string, document *yaml.Node) (TemplateMetadata, *TemplateIndexDiagnostic) {
	root, diagnostic := nucleiTemplateMapping(path, document)
	if diagnostic != nil {
		return TemplateMetadata{}, diagnostic
	}

	id, diagnostic := nucleiTemplateRequiredScalar(path, root, "id", "missing_id")
	if diagnostic != nil {
		return TemplateMetadata{}, diagnostic
	}
	if strings.ContainsAny(id, " \t\r\n") {
		return TemplateMetadata{}, templateIndexDiagnostic(path, "invalid_id", "template id must not contain whitespace")
	}

	info, found, duplicate := nucleiTemplateMappingValue(root, "info")
	if duplicate {
		return TemplateMetadata{}, templateIndexDiagnostic(path, "duplicate_info", "template contains multiple info fields")
	}
	if !found || info.Kind != yaml.MappingNode {
		return TemplateMetadata{}, templateIndexDiagnostic(path, "missing_info", "template requires an info mapping")
	}
	severity, diagnostic := nucleiTemplateRequiredScalar(path, info, "severity", "missing_severity")
	if diagnostic != nil {
		return TemplateMetadata{}, diagnostic
	}
	severity = strings.ToLower(severity)
	if _, ok := nucleiTemplateSeverities[severity]; !ok {
		return TemplateMetadata{}, templateIndexDiagnostic(path, "invalid_severity", "severity must be critical, high, medium, low, info or unknown")
	}
	tags, diagnostic := nucleiTemplateTags(path, info)
	if diagnostic != nil {
		return TemplateMetadata{}, diagnostic
	}
	protocols, workflow, diagnostic := nucleiTemplateProtocolNames(path, root)
	if diagnostic != nil {
		return TemplateMetadata{}, diagnostic
	}
	if workflow && len(protocols) == 0 {
		return TemplateMetadata{}, templateIndexDiagnostic(path, "workflow_not_indexed", "workflow files are not direct executable templates")
	}
	if len(protocols) == 0 {
		return TemplateMetadata{}, templateIndexDiagnostic(path, "missing_protocol", "template has no recognized executable protocol")
	}

	return TemplateMetadata{
		ID:        id,
		Path:      path,
		Protocols: protocols,
		Tags:      tags,
		Severity:  severity,
	}, nil
}

func nucleiTemplateMapping(path string, document *yaml.Node) (*yaml.Node, *TemplateIndexDiagnostic) {
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, templateIndexDiagnostic(path, "invalid_document", "template root must be a YAML mapping")
	}
	return document.Content[0], nil
}

func nucleiTemplateRequiredScalar(path string, mapping *yaml.Node, field, missingCode string) (string, *TemplateIndexDiagnostic) {
	value, found, duplicate := nucleiTemplateMappingValue(mapping, field)
	if duplicate {
		return "", templateIndexDiagnostic(path, "duplicate_"+field, "template contains multiple "+field+" fields")
	}
	if !found || value.Kind != yaml.ScalarNode {
		return "", templateIndexDiagnostic(path, missingCode, "template requires a scalar "+field+" field")
	}
	valueText := strings.TrimSpace(value.Value)
	if valueText == "" {
		return "", templateIndexDiagnostic(path, missingCode, "template requires a non-empty "+field+" field")
	}
	return valueText, nil
}

func nucleiTemplateTags(path string, info *yaml.Node) ([]string, *TemplateIndexDiagnostic) {
	value, found, duplicate := nucleiTemplateMappingValue(info, "tags")
	if duplicate {
		return nil, templateIndexDiagnostic(path, "duplicate_tags", "template contains multiple tags fields")
	}
	if !found || isEmptyYAMLNode(value) {
		return nil, nil
	}

	values := make([]string, 0)
	switch value.Kind {
	case yaml.ScalarNode:
		values = append(values, value.Value)
	case yaml.SequenceNode:
		for _, item := range value.Content {
			if item.Kind != yaml.ScalarNode {
				return nil, templateIndexDiagnostic(path, "invalid_tags", "each tag must be a scalar string")
			}
			values = append(values, item.Value)
		}
	default:
		return nil, templateIndexDiagnostic(path, "invalid_tags", "tags must be a comma-separated string or string list")
	}

	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		for _, tag := range strings.Split(value, ",") {
			tag = strings.ToLower(strings.TrimSpace(tag))
			if tag == "" {
				continue
			}
			if strings.ContainsAny(tag, "\r\n") {
				return nil, templateIndexDiagnostic(path, "invalid_tags", "tags must not contain line breaks")
			}
			seen[tag] = struct{}{}
		}
	}
	tags := make([]string, 0, len(seen))
	for tag := range seen {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags, nil
}

func nucleiTemplateProtocolNames(path string, root *yaml.Node) ([]string, bool, *TemplateIndexDiagnostic) {
	protocols := make([]string, 0)
	workflow := false
	for index := 0; index < len(root.Content); index += 2 {
		key := strings.ToLower(strings.TrimSpace(root.Content[index].Value))
		value := root.Content[index+1]
		if key == "workflows" {
			workflow = true
			continue
		}
		if _, ok := nucleiTemplateProtocols[key]; !ok {
			continue
		}
		if isEmptyYAMLNode(value) {
			return nil, workflow, templateIndexDiagnostic(path, "empty_protocol", "protocol "+key+" has no definition")
		}
		protocols = append(protocols, key)
	}
	sort.Strings(protocols)
	return protocols, workflow, nil
}

func nucleiTemplateMappingValue(mapping *yaml.Node, field string) (*yaml.Node, bool, bool) {
	var value *yaml.Node
	for index := 0; index < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value != field {
			continue
		}
		if value != nil {
			return nil, true, true
		}
		value = mapping.Content[index+1]
	}
	return value, value != nil, false
}

func isEmptyYAMLNode(node *yaml.Node) bool {
	if node == nil || node.Kind == 0 || node.Tag == "!!null" {
		return true
	}
	return (node.Kind == yaml.SequenceNode || node.Kind == yaml.MappingNode) && len(node.Content) == 0
}

func templateIndexDiagnostic(path, code, reason string) *TemplateIndexDiagnostic {
	return &TemplateIndexDiagnostic{Path: path, Code: code, Reason: reason}
}

func (index *TemplateIndex) excludeDuplicateTemplateIDs() {
	byID := make(map[string][]int)
	for position, template := range index.Templates {
		byID[template.ID] = append(byID[template.ID], position)
	}
	duplicates := make(map[int]struct{})
	for id, positions := range byID {
		if len(positions) < 2 {
			continue
		}
		for _, position := range positions {
			duplicates[position] = struct{}{}
			index.Diagnostics = append(index.Diagnostics, TemplateIndexDiagnostic{
				Path:   index.Templates[position].Path,
				Code:   "duplicate_template_id",
				Reason: "template id is duplicated: " + id,
			})
		}
	}
	if len(duplicates) == 0 {
		return
	}
	filtered := make([]TemplateMetadata, 0, len(index.Templates)-len(duplicates))
	for position, template := range index.Templates {
		if _, duplicate := duplicates[position]; !duplicate {
			filtered = append(filtered, template)
		}
	}
	index.Templates = filtered
}

func (index *TemplateIndex) sort() {
	sort.Slice(index.Templates, func(left, right int) bool {
		if index.Templates[left].ID != index.Templates[right].ID {
			return index.Templates[left].ID < index.Templates[right].ID
		}
		return index.Templates[left].Path < index.Templates[right].Path
	})
	sort.Slice(index.Diagnostics, func(left, right int) bool {
		leftDiagnostic := index.Diagnostics[left]
		rightDiagnostic := index.Diagnostics[right]
		if leftDiagnostic.Path != rightDiagnostic.Path {
			return leftDiagnostic.Path < rightDiagnostic.Path
		}
		if leftDiagnostic.Code != rightDiagnostic.Code {
			return leftDiagnostic.Code < rightDiagnostic.Code
		}
		return leftDiagnostic.Reason < rightDiagnostic.Reason
	})
}
