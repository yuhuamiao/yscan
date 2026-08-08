package fingerprint

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"

	"golandproject/yscan/internal/model"
)

type fscanAdapter struct{}

func (fscanAdapter) SourceKey() string { return "fscan-native-web" }

func (fscanAdapter) Adapt(snapshot VerifiedSnapshot) ([]model.FingerprintSourceRule, error) {
	raw := snapshot.Files["rules.go"]
	sets, err := fscanRuleLiterals(raw)
	if err != nil {
		return nil, err
	}
	rules := make([]model.FingerprintSourceRule, 0, len(sets.regex)+len(sets.md5))
	for index, literal := range sets.regex {
		rules = append(rules, model.FingerprintSourceRule{SourceRuleID: fmt.Sprintf("regex:%d", index), SourcePath: fmt.Sprintf("rules.go#RuleDatas/%d", index), ContentSHA256: sha256Hex([]byte(literal)), RawContent: literal, RawStructure: literal, ImportStatus: "executable"})
	}
	for index, literal := range sets.md5 {
		rules = append(rules, model.FingerprintSourceRule{SourceRuleID: fmt.Sprintf("md5:%d", index), SourcePath: fmt.Sprintf("rules.go#Md5Datas/%d", index), ContentSHA256: sha256Hex([]byte(literal)), RawContent: literal, RawStructure: literal, ImportStatus: "executable"})
	}
	return rules, nil
}

type fscanLiterals struct{ regex, md5 []string }

func fscanRuleLiterals(raw []byte) (fscanLiterals, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "rules.go", raw, 0)
	if err != nil {
		return fscanLiterals{}, err
	}
	var out fscanLiterals
	for _, declaration := range file.Decls {
		gen, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				continue
			}
			name := value.Names[0].Name
			list, ok := value.Values[0].(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, element := range list.Elts {
				start, end := fset.Position(element.Pos()).Offset, fset.Position(element.End()).Offset
				if start < 0 || end <= start || end > len(raw) {
					return fscanLiterals{}, fmt.Errorf("invalid fscan rule position")
				}
				switch name {
				case "RuleDatas":
					out.regex = append(out.regex, string(raw[start:end]))
				case "Md5Datas":
					out.md5 = append(out.md5, string(raw[start:end]))
				}
			}
		}
	}
	if len(out.regex) != 242 || len(out.md5) != 30 {
		return fscanLiterals{}, fmt.Errorf("unexpected fscan native rule totals: regex=%d md5=%d", len(out.regex), len(out.md5))
	}
	return out, nil
}

func parseFscanLiteral(raw string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "rule.go", "package fixture\nvar rule = struct{Name, Type, Rule, Md5Str string}"+raw, 0)
	if err != nil {
		return nil, err
	}
	decl := file.Decls[0].(*ast.GenDecl).Specs[0].(*ast.ValueSpec).Values[0].(*ast.CompositeLit)
	values := make([]string, 0, len(decl.Elts))
	for _, element := range decl.Elts {
		if keyed, ok := element.(*ast.KeyValueExpr); ok {
			element = keyed.Value
		}
		basic, ok := element.(*ast.BasicLit)
		if !ok || basic.Kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(basic.Value)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}
