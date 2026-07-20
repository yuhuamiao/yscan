package vuln

import (
	"reflect"
	"testing"
)

func TestBuildNucleiArgsIncludesNormalizedTags(t *testing.T) {
	args := buildNucleiArgs("targets.txt", "templates", []string{"http", " Redis ", "http"})
	want := []string{"-jsonl", "-silent", "-l", "targets.txt", "-t", "templates", "-tags", "http,redis"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("args = %v, want %v", args, want)
	}
}

func TestBuildNucleiArgsOmitsEmptyTags(t *testing.T) {
	args := buildNucleiArgs("targets.txt", "templates", nil)
	for _, arg := range args {
		if arg == "-tags" {
			t.Fatal("empty tags must not add -tags")
		}
	}
}
