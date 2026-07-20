package planner

import (
	"net"
	"sort"
	"strings"

	"golandproject/yscan/internal/model"
)

var serviceTemplateGroups = map[string][]string{
	"http":           {"http", "misconfiguration", "technologies"},
	"redis":          {"redis", "misconfiguration"},
	"mongodb":        {"mongodb", "misconfiguration"},
	"elasticsearch":  {"elasticsearch", "misconfiguration"},
	"docker-api":     {"docker", "misconfiguration", "exposure"},
	"kubernetes-api": {"kubernetes", "misconfiguration", "exposure"},
}

var serviceAliases = map[string]string{
	"http-unknown": "http",
	"nginx":        "http",
	"apache":       "http",
	"iis":          "http",
	"caddy":        "http",
	"jetty":        "http",
	"lighttpd":     "http",
	"docker":       "docker-api",
	"kubernetes":   "kubernetes-api",
	"k8s":          "kubernetes-api",
}

// TemplateGroupsForService returns a copy of the static Nuclei template tags
// suitable for a recognized service.
func TemplateGroupsForService(service string) []string {
	service = strings.ToLower(strings.TrimSpace(service))
	if alias, ok := serviceAliases[service]; ok {
		service = alias
	}

	groups := serviceTemplateGroups[service]
	return append([]string(nil), groups...)
}

// TemplateGroupsForScanResults merges template tags for the services found on
// one host. Port fallbacks cover common APIs when banner identification fails.
func TemplateGroupsForScanResults(results []model.ScanResult) []string {
	seen := make(map[string]struct{})
	for _, result := range results {
		if !result.Open {
			continue
		}
		service := firstService(result)
		for _, group := range TemplateGroupsForService(service) {
			seen[group] = struct{}{}
		}
	}

	groups := make([]string, 0, len(seen))
	for group := range seen {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	return groups
}

func firstService(result model.ScanResult) string {
	for _, service := range []string{result.Product, result.Service} {
		if len(TemplateGroupsForService(service)) > 0 {
			return service
		}
	}

	_, portText, err := net.SplitHostPort(result.Address)
	if err != nil {
		return ""
	}
	switch portText {
	case "80", "443", "8080", "8443", "8888":
		return "http"
	case "6379":
		return "redis"
	case "27017":
		return "mongodb"
	case "9200":
		return "elasticsearch"
	case "2375", "2376":
		return "docker-api"
	case "6443":
		return "kubernetes-api"
	default:
		return ""
	}
}
