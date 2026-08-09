package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golandproject/yscan/internal/model"
)

var ErrPinnedTemplateMissing = errors.New("pinned nuclei template missing or changed")

type ReviewedTemplateCandidate struct {
	Mapping model.FingerprintTemplateMapping
	Pinned  PinnedNucleiTemplate
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
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("%w: read reviewed template %s: %v", ErrPinnedTemplateMissing, mapping.TemplatePath, err)
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			_ = file.Close()
			return nil, fmt.Errorf("%w: reviewed template is not a regular file: %s", ErrPinnedTemplateMissing, mapping.TemplatePath)
		}
		content, err := io.ReadAll(file)
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("%w: read reviewed template %s: %v", ErrPinnedTemplateMissing, mapping.TemplatePath, err)
		}
		sum := sha256.Sum256(content)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), mapping.TemplateSHA256) {
			return nil, fmt.Errorf("%w: reviewed template content changed: %s", ErrPinnedTemplateMissing, mapping.TemplatePath)
		}
		key := mapping.TemplateID + "\x00" + path + "\x00" + mapping.TemplateSHA256 + "\x00" + strings.ToLower(strings.TrimSpace(mapping.ProductKey))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, ReviewedTemplateCandidate{Mapping: mapping, Pinned: PinnedNucleiTemplate{TemplateID: mapping.TemplateID, Path: mapping.TemplatePath, SHA256: hex.EncodeToString(sum[:]), Content: append([]byte(nil), content...)}})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Pinned.Path != result[j].Pinned.Path {
			return result[i].Pinned.Path < result[j].Pinned.Path
		}
		return result[i].Mapping.ProductKey < result[j].Mapping.ProductKey
	})
	return result, nil
}
