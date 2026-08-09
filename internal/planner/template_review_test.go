package planner

import (
	"os"
	"testing"
)

func TestReviewedNucleiTemplateMatrixDeclaresTCPAndHTTP(t *testing.T) {
	matrix, err := LoadReviewedNucleiTemplateMatrix()
	if err != nil {
		t.Fatal(err)
	}
	if matrix.Revision != "caasm-reviewed-nuclei-v1" || len(matrix.Templates) != 3 {
		t.Fatalf("matrix=%#v", matrix)
	}
	products := map[string]string{}
	for _, item := range matrix.Templates {
		products[item.Product] = item.Protocol
	}
	if products["redis"] != "tcp" || products["php"] != "http" || products["python"] != "http" {
		t.Fatalf("reviewed coverage=%#v", products)
	}
}

func TestRealReviewedNucleiTemplateMatrix(t *testing.T) {
	root := os.Getenv("YSCAN_REAL_NUCLEI_TEMPLATES")
	if root == "" {
		t.Skip("set YSCAN_REAL_NUCLEI_TEMPLATES for reviewed template acceptance")
	}
	index, err := BuildNucleiTemplateIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateReviewedNucleiTemplateMatrix(index); err != nil {
		t.Fatal(err)
	}
	changed := false
	for position := range index.Templates {
		if index.Templates[position].TemplateID == "exposed-redis" {
			index.Templates[position].SHA256 = "changed"
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("reviewed Redis template is absent")
	}
	if _, err := ValidateReviewedNucleiTemplateMatrix(index); err == nil {
		t.Fatal("changed reviewed template unexpectedly passed")
	}
}
