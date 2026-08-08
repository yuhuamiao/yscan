package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golandproject/yscan/internal/model"
)

type ReviewedTemplateCandidate struct {
	Mapping      model.FingerprintTemplateMapping
	AbsolutePath string
}

// ResolveReviewedTemplateCandidates binds a reviewed mapping to the exact
// local file that was reviewed. A changed file is never silently executed.
func ResolveReviewedTemplateCandidates(root string, mappings []model.FingerprintTemplateMapping) ([]ReviewedTemplateCandidate, error) {
	base, err := filepath.Abs(strings.TrimSpace(root))
	if err != nil {
		return nil, err
	}
	result := make([]ReviewedTemplateCandidate, 0, len(mappings))
	seen := make(map[string]struct{})
	for _, mapping := range mappings {
		if !mapping.Enabled || mapping.ReviewStatus != "approved" || mapping.SideEffect != "read_only" {
			continue
		}
		path := filepath.Join(base, filepath.Clean(mapping.TemplatePath))
		if !strings.HasPrefix(path, base+string(os.PathSeparator)) {
			return nil, fmt.Errorf("template mapping %d escapes template root", mapping.ID)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read reviewed template %s: %w", mapping.TemplatePath, err)
		}
		sum := sha256.Sum256(content)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), mapping.TemplateSHA256) {
			return nil, fmt.Errorf("reviewed template content changed: %s", mapping.TemplatePath)
		}
		key := mapping.TemplateID + "\x00" + path + "\x00" + mapping.TemplateSHA256
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, ReviewedTemplateCandidate{Mapping: mapping, AbsolutePath: path})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].AbsolutePath < result[j].AbsolutePath })
	return result, nil
}
