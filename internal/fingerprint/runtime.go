package fingerprint

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var reviewedRuleCache sync.Map

// LoadReviewedRules loads only the checked-in manifest snapshots. Callers own
// lifecycle caching; this function never fetches a remote source.
func LoadReviewedRules(root string) (Compilation, error) {
	resolvedRoot, err := resolveReviewedRoot(root)
	if err != nil {
		return Compilation{}, err
	}
	if cached, ok := reviewedRuleCache.Load(resolvedRoot); ok {
		return cached.(Compilation), nil
	}
	data, err := os.ReadFile(filepath.Join(resolvedRoot, "manifest.json"))
	if err != nil {
		return Compilation{}, err
	}
	manifest, err := ParseSourceManifest(data)
	if err != nil {
		return Compilation{}, err
	}
	rules := make([]Rule, 0)
	for _, source := range manifest.Sources {
		snapshotPath, err := reviewedSnapshotPath(resolvedRoot, source.Snapshot)
		if err != nil {
			return Compilation{}, err
		}
		snapshot, err := os.ReadFile(snapshotPath)
		if err != nil {
			return Compilation{}, err
		}
		parsed, err := ParseFingerprintHubSnapshot(source.ID, snapshot)
		if err != nil {
			return Compilation{}, err
		}
		rules = append(rules, parsed.Rules...)
	}
	compiled, err := CompileRules(rules)
	if err == nil {
		reviewedRuleCache.Store(resolvedRoot, compiled)
	}
	return compiled, err
}

func resolveReviewedRoot(root string) (string, error) {
	root = filepath.Clean(root)
	if filepath.IsAbs(root) {
		return root, nil
	}
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(directory, root)
		if info, err := os.Stat(filepath.Join(candidate, "manifest.json")); err == nil && !info.IsDir() {
			return filepath.Abs(candidate)
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", fmt.Errorf("reviewed fingerprint manifest not found under %s", root)
		}
		directory = parent
	}
}

// reviewedSnapshotPath keeps a checked-in manifest relocatable with the
// application data directory. It accepts only the manifest's fingerprint
// subtree and never follows a path outside the configured root.
func reviewedSnapshotPath(root, snapshot string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	snapshot = filepath.ToSlash(filepath.Clean(snapshot))
	const marker = "data/fingerprints/"
	if index := strings.Index(snapshot, marker); index >= 0 {
		snapshot = snapshot[index+len(marker):]
	}
	if snapshot == "." || strings.HasPrefix(snapshot, "../") || filepath.IsAbs(snapshot) {
		return "", fmt.Errorf("invalid reviewed fingerprint snapshot: %s", snapshot)
	}
	resolved := filepath.Join(root, snapshot)
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("fingerprint snapshot escapes root: %s", snapshot)
	}
	return resolved, nil
}
