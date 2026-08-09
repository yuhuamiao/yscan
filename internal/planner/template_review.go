package planner

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

//go:embed reviewed_nuclei_templates.json
var reviewedNucleiTemplateManifest []byte

type ReviewedNucleiTemplateMatrix struct {
	Revision  string                           `json:"revision"`
	Templates []ReviewedNucleiTemplateManifest `json:"templates"`
}

type ReviewedNucleiTemplateManifest struct {
	TemplateID     string `json:"template_id"`
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	Product        string `json:"product"`
	CPE            string `json:"cpe"`
	Protocol       string `json:"protocol"`
	RequestSummary string `json:"request_summary"`
	SideEffect     string `json:"side_effect"`
}

func LoadReviewedNucleiTemplateMatrix() (ReviewedNucleiTemplateMatrix, error) {
	decoder := json.NewDecoder(bytes.NewReader(reviewedNucleiTemplateManifest))
	decoder.DisallowUnknownFields()
	var matrix ReviewedNucleiTemplateMatrix
	if err := decoder.Decode(&matrix); err != nil {
		return ReviewedNucleiTemplateMatrix{}, fmt.Errorf("decode reviewed nuclei template matrix: %w", err)
	}
	if strings.TrimSpace(matrix.Revision) == "" || len(matrix.Templates) < 2 {
		return ReviewedNucleiTemplateMatrix{}, fmt.Errorf("reviewed nuclei template matrix requires a revision and at least two templates")
	}
	seen := make(map[string]struct{}, len(matrix.Templates))
	protocols := make(map[string]struct{}, 2)
	for _, item := range matrix.Templates {
		key := item.TemplateID + "\x00" + item.Path
		protocol := strings.ToLower(strings.TrimSpace(item.Protocol))
		digest, digestErr := hex.DecodeString(item.SHA256)
		cleanPath := filepath.ToSlash(filepath.Clean(item.Path))
		if item.TemplateID == "" || item.Path == "" || filepath.IsAbs(item.Path) || cleanPath != item.Path || strings.HasPrefix(cleanPath, "../") || digestErr != nil || len(digest) != 32 || item.Product == "" || item.RequestSummary == "" || item.SideEffect != "read_only" || (protocol != "tcp" && protocol != "http") {
			return ReviewedNucleiTemplateMatrix{}, fmt.Errorf("invalid reviewed nuclei template entry: %s", item.TemplateID)
		}
		if item.CPE != "" {
			if _, ok := parseNucleiCPE(item.CPE); !ok {
				return ReviewedNucleiTemplateMatrix{}, fmt.Errorf("invalid reviewed nuclei template CPE: %s", item.TemplateID)
			}
		}
		if _, duplicate := seen[key]; duplicate {
			return ReviewedNucleiTemplateMatrix{}, fmt.Errorf("duplicate reviewed nuclei template entry: %s", item.TemplateID)
		}
		seen[key] = struct{}{}
		protocols[protocol] = struct{}{}
	}
	if _, ok := protocols["tcp"]; !ok {
		return ReviewedNucleiTemplateMatrix{}, fmt.Errorf("reviewed nuclei template matrix has no TCP product")
	}
	if _, ok := protocols["http"]; !ok {
		return ReviewedNucleiTemplateMatrix{}, fmt.Errorf("reviewed nuclei template matrix has no HTTP product")
	}
	return matrix, nil
}

func ValidateReviewedNucleiTemplateMatrix(index *NucleiTemplateIndex) (ReviewedNucleiTemplateMatrix, error) {
	if index == nil {
		return ReviewedNucleiTemplateMatrix{}, fmt.Errorf("nuclei template index is required")
	}
	matrix, err := LoadReviewedNucleiTemplateMatrix()
	if err != nil {
		return ReviewedNucleiTemplateMatrix{}, err
	}
	for _, reviewed := range matrix.Templates {
		matched := false
		for _, candidate := range index.Select(reviewed.Product, reviewed.CPE, reviewed.Protocol) {
			if candidate.TemplateID == reviewed.TemplateID && candidate.Path == reviewed.Path && strings.EqualFold(candidate.SHA256, reviewed.SHA256) {
				matched = true
				break
			}
		}
		if !matched {
			return ReviewedNucleiTemplateMatrix{}, fmt.Errorf("reviewed nuclei template is absent or changed: %s (%s)", reviewed.TemplateID, reviewed.Path)
		}
	}
	return matrix, nil
}
