package planner

// TemplateSafetyPolicy defines the Nuclei tags excluded from every validation
// run. Template metadata indexing and path-level selection are intentionally
// not part of the current product.
type TemplateSafetyPolicy struct {
	ExcludedTags []string
}

var defaultExcludedTemplateTags = []string{"intrusive", "dos", "auth"}

// DefaultTemplateSafetyPolicy returns a copy of the product's conservative
// default.
func DefaultTemplateSafetyPolicy() TemplateSafetyPolicy {
	return TemplateSafetyPolicy{
		ExcludedTags: append([]string(nil), defaultExcludedTemplateTags...),
	}
}
