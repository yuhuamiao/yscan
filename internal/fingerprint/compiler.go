package fingerprint

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Compilation is the deterministic result of normalizing local source rules.
// Conflicting IDs are excluded from Rules and retained in Conflicts so a later
// review can resolve them without losing the competing source definitions.
type Compilation struct {
	Rules     []Rule         `json:"rules"`
	Conflicts []RuleConflict `json:"conflicts"`
}

// RuleConflict records every distinct validated candidate sharing one rule ID.
// Candidates are deterministically ordered and retain their source IDs.
type RuleConflict struct {
	ID         string `json:"id"`
	Candidates []Rule `json:"candidates"`
}

// CompileRules validates, canonicalizes and deterministically deduplicates an
// input rule set. Exact duplicates collapse to one rule. Distinct definitions
// using the same ID become conflicts instead of silently replacing one source
// with another.
func CompileRules(input []Rule) (Compilation, error) {
	entries := make([]compiledRule, 0, len(input))
	for index, inputRule := range input {
		rule := cloneRule(inputRule)
		if err := rule.Validate(); err != nil {
			return Compilation{}, fmt.Errorf("validate rule %d: %w", index, err)
		}
		encoded, err := json.Marshal(rule)
		if err != nil {
			return Compilation{}, fmt.Errorf("encode rule %s: %w", rule.ID, err)
		}
		entries = append(entries, compiledRule{rule: rule, canonical: string(encoded)})
	}

	sort.Slice(entries, func(left, right int) bool {
		if entries[left].rule.ID != entries[right].rule.ID {
			return entries[left].rule.ID < entries[right].rule.ID
		}
		return entries[left].canonical < entries[right].canonical
	})

	result := Compilation{}
	for start := 0; start < len(entries); {
		end := start + 1
		for end < len(entries) && entries[end].rule.ID == entries[start].rule.ID {
			end++
		}
		candidates := uniqueCompiledRules(entries[start:end])
		if len(candidates) == 1 {
			result.Rules = append(result.Rules, candidates[0])
		} else {
			result.Conflicts = append(result.Conflicts, RuleConflict{
				ID:         entries[start].rule.ID,
				Candidates: candidates,
			})
		}
		start = end
	}
	return result, nil
}

type compiledRule struct {
	rule      Rule
	canonical string
}

func uniqueCompiledRules(entries []compiledRule) []Rule {
	unique := make([]Rule, 0, len(entries))
	lastCanonical := ""
	for index, entry := range entries {
		if index != 0 && entry.canonical == lastCanonical {
			continue
		}
		unique = append(unique, entry.rule)
		lastCanonical = entry.canonical
	}
	return unique
}

func cloneRule(rule Rule) Rule {
	copy := rule
	copy.Protocols = append([]Protocol(nil), rule.Protocols...)
	copy.Matchers = append([]Matcher(nil), rule.Matchers...)
	return copy
}
