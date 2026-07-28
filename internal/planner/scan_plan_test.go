package planner

import (
	"reflect"
	"testing"

	"golandproject/yscan/internal/model"
)

func TestTemplateGroupsForRequiredServices(t *testing.T) {
	services := []string{"http", "redis", "mongodb", "elasticsearch", "docker-api", "kubernetes-api"}
	for _, service := range services {
		t.Run(service, func(t *testing.T) {
			groups := TemplateGroupsForService(service)
			if len(groups) == 0 {
				t.Fatalf("no template groups for %s", service)
			}
			for _, group := range groups {
				for _, excluded := range DefaultExcludedTemplateTags() {
					if group == excluded {
						t.Fatalf("%s includes excluded template tag %q", service, group)
					}
				}
			}
		})
	}
}

func TestDefaultExcludedTemplateTagsReturnsCopy(t *testing.T) {
	tags := DefaultExcludedTemplateTags()
	want := []string{"intrusive", "dos", "auth"}
	if !reflect.DeepEqual(tags, want) {
		t.Fatalf("excluded tags = %v, want %v", tags, want)
	}
	tags[0] = "mutated"
	if DefaultExcludedTemplateTags()[0] == "mutated" {
		t.Fatal("excluded tags must not expose mutable internal state")
	}
}

func TestTemplateGroupsForServiceReturnsCopy(t *testing.T) {
	groups := TemplateGroupsForService("nginx")
	groups[0] = "mutated"
	if TemplateGroupsForService("http")[0] == "mutated" {
		t.Fatal("template groups must not expose mutable internal state")
	}
}

func TestTemplateGroupsForScanResultsUsesServiceAndPortFallback(t *testing.T) {
	groups := TemplateGroupsForScanResults([]model.ScanResult{
		{Address: "192.168.1.10:80", Open: true, Service: "nginx"},
		{Address: "192.168.1.10:2375", Open: true, Service: "unknown"},
		{Address: "192.168.1.10:9999", Open: true, Service: "unknown"},
	})
	want := []string{"docker", "exposure", "http", "misconfiguration", "technologies"}
	if !reflect.DeepEqual(groups, want) {
		t.Fatalf("groups = %v, want %v", groups, want)
	}
}
