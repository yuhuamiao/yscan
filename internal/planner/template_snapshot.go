package planner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type PinnedNucleiTemplate struct {
	TemplateID string
	Path       string
	SHA256     string
	Content    []byte
}

type NucleiTemplateSnapshot struct {
	directory string
	Paths     []string
}

func (entry NucleiTemplateIndexEntry) PinnedTemplate() PinnedNucleiTemplate {
	return PinnedNucleiTemplate{TemplateID: entry.TemplateID, Path: entry.Path, SHA256: entry.SHA256, Content: append([]byte(nil), entry.Content...)}
}

// MaterializePinnedNucleiTemplates writes the already audited bytes to a
// private, read-only, content-addressed directory. Nuclei never receives an
// upstream path that can change after indexing.
func MaterializePinnedNucleiTemplates(templates []PinnedNucleiTemplate) (*NucleiTemplateSnapshot, error) {
	if len(templates) == 0 {
		return nil, errors.New("at least one pinned nuclei template is required")
	}
	directory, err := os.MkdirTemp("", "caasm-nuclei-snapshot-*")
	if err != nil {
		return nil, err
	}
	snapshot := &NucleiTemplateSnapshot{directory: directory}
	cleanupOnError := func(err error) (*NucleiTemplateSnapshot, error) {
		_ = snapshot.Close()
		return nil, err
	}
	unique := make(map[string]PinnedNucleiTemplate)
	for _, template := range templates {
		digest := sha256.Sum256(template.Content)
		actual := hex.EncodeToString(digest[:])
		if len(template.Content) == 0 || !strings.EqualFold(strings.TrimSpace(template.SHA256), actual) {
			return cleanupOnError(fmt.Errorf("%w: hash mismatch: %s", ErrPinnedTemplateMissing, template.Path))
		}
		unique[actual] = template
	}
	digests := make([]string, 0, len(unique))
	for digest := range unique {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	for _, digest := range digests {
		path := filepath.Join(directory, digest+".yaml")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
		if err != nil {
			return cleanupOnError(err)
		}
		content := unique[digest].Content
		if _, err := file.Write(content); err != nil {
			_ = file.Close()
			return cleanupOnError(err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return cleanupOnError(err)
		}
		if err := file.Close(); err != nil {
			return cleanupOnError(err)
		}
		snapshot.Paths = append(snapshot.Paths, path)
	}
	if err := os.Chmod(directory, 0500); err != nil {
		return cleanupOnError(err)
	}
	return snapshot, nil
}

func (snapshot *NucleiTemplateSnapshot) Close() error {
	if snapshot == nil || snapshot.directory == "" {
		return nil
	}
	directory := snapshot.directory
	snapshot.directory = ""
	_ = os.Chmod(directory, 0700)
	return os.RemoveAll(directory)
}
