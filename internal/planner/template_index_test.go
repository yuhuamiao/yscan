package planner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNucleiTemplateIndexSelectsPinnedReadOnlyProductCandidates(t *testing.T) {
	root := t.TempDir()
	writeTemplateIndexFixture(t, root, "http/php.yaml", `
id: php-config-exposure
info:
  name: PHP Config Exposure
  severity: medium
  classification:
    cpe: cpe:2.3:a:php:php:*:*:*:*:*:*:*:*
  metadata:
    vendor: php
    product: php
  tags: php,config,exposure
http:
  - method: GET
    path: ["{{BaseURL}}"]
`)
	writeTemplateIndexFixture(t, root, "network/redis.yaml", `
id: exposed-redis
info:
  name: Redis Exposure
  severity: high
  tags: network,redis,unauth,exposure,tcp,discovery
tcp:
  - inputs:
      - data: "info\r\nquit\r\n"
`)
	writeTemplateIndexFixture(t, root, "http/nginx-cpe.yaml", `
id: nginx-cpe-check
info:
  name: Nginx CPE Check
  severity: medium
  classification:
    cpe: cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*
  tags: nginx,misconfiguration
http:
  - method: HEAD
`)
	writeTemplateIndexFixture(t, root, "unsafe/post.yaml", `
id: unsafe-post
info:
  name: Unsafe PHP Write
  severity: high
  metadata: {product: php}
  tags: php,vuln
http:
  - method: POST
    path: ["{{BaseURL}}/write"]
`)
	writeTemplateIndexFixture(t, root, "unsafe/headless.yaml", `
id: unsafe-headless
info:
  name: Unsafe Browser
  severity: medium
  metadata: {product: php}
  tags: php,headless,xss
headless:
  - steps: []
`)
	writeTemplateIndexFixture(t, root, "http/php-detect.yaml", `
id: php-detect
info:
  name: PHP Detect
  severity: info
  metadata: {product: php}
  tags: tech,php,discovery
http:
  - method: GET
`)
	writeTemplateIndexFixture(t, root, "dast/python-code-injection.yaml", `
id: python-code-injection
info:
  name: Python Code Injection
  severity: high
  metadata: {product: python}
  tags: python,vuln
http:
  - method: GET
`)

	index, err := BuildNucleiTemplateIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	if index.Revision == "" || len(index.Templates) != 3 {
		t.Fatalf("index revision=%q templates=%#v", index.Revision, index.Templates)
	}
	php := index.Select("php", "", "https")
	if len(php) != 1 || php[0].TemplateID != "php-config-exposure" || php[0].SHA256 == "" || php[0].Path != "http/php.yaml" {
		t.Fatalf("PHP candidates=%#v", php)
	}
	redis := index.Select("redis", "cpe:2.3:a:redislabs:redis:*:*:*:*:*:*:*:*", "tcp")
	if len(redis) != 1 || redis[0].TemplateID != "exposed-redis" {
		t.Fatalf("Redis candidates=%#v", redis)
	}
	if got := index.Select("php", "", "tcp"); len(got) != 0 {
		t.Fatalf("HTTP template crossed protocol: %#v", got)
	}
	nginx := index.Select("nginx", "", "http")
	if len(nginx) != 1 || nginx[0].TemplateID != "nginx-cpe-check" {
		t.Fatalf("CPE-only candidates=%#v", nginx)
	}
}

func TestNucleiTemplateIndexRevisionIsDeterministicAndContentBound(t *testing.T) {
	root := t.TempDir()
	path := writeTemplateIndexFixture(t, root, "php.yaml", `
id: php-config-exposure
info:
  name: PHP Config Exposure
  severity: medium
  metadata: {product: php}
  tags: php,config,exposure
http:
  - method: GET
`)
	first, err := BuildNucleiTemplateIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildNucleiTemplateIndex(root)
	if err != nil || second.Revision != first.Revision {
		t.Fatalf("deterministic revision first=%q second=%q err=%v", first.Revision, second.Revision, err)
	}
	if err := os.WriteFile(path, []byte(`
id: php-config-exposure
info:
  name: PHP Config Exposure Changed
  severity: medium
  metadata: {product: php}
  tags: php,config,exposure
http:
  - method: GET
`), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := BuildNucleiTemplateIndex(root)
	if err != nil || changed.Revision == first.Revision {
		t.Fatalf("content change revision first=%q changed=%q err=%v", first.Revision, changed.Revision, err)
	}
}

func TestRealNucleiTemplateIndexCoverage(t *testing.T) {
	root := os.Getenv("YSCAN_REAL_NUCLEI_TEMPLATES")
	if root == "" {
		t.Skip("set YSCAN_REAL_NUCLEI_TEMPLATES for the local template-tree acceptance")
	}
	index, err := BuildNucleiTemplateIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Templates) < 100 || index.Revision == "" {
		t.Fatalf("real index is unexpectedly small: templates=%d revision=%q", len(index.Templates), index.Revision)
	}
	php := index.Select("php", "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", "http")
	redis := index.Select("redis", "", "tcp")
	if len(php) == 0 || len(redis) == 0 {
		t.Fatalf("real index coverage php=%d redis=%d", len(php), len(redis))
	}
	for _, candidates := range [][]NucleiTemplateIndexEntry{php, redis} {
		for _, candidate := range candidates {
			for _, tag := range candidate.Tags {
				if _, unsafe := unsafeAutomaticTemplateTags[tag]; unsafe {
					t.Fatalf("unsafe candidate selected: %#v", candidate)
				}
			}
			if unsafeAutomaticTemplateIdentity(candidate.TemplateID, candidate.Path) {
				t.Fatalf("unsafe candidate identity selected: %#v", candidate)
			}
		}
	}
	for _, forbidden := range []string{"php-detect", "sshd-dropbear-detect", "redis-honeypot-detect", "python-code-injection", "twig-php-ssti"} {
		for _, candidate := range index.Templates {
			if candidate.TemplateID == forbidden {
				t.Fatalf("detection or intrusive template entered automatic index: %#v", candidate)
			}
		}
	}
	t.Logf("real template index: executable=%d php=%d redis=%d revision=%s", len(index.Templates), len(php), len(redis), index.Revision)
}

func writeTemplateIndexFixture(t *testing.T, root, relative, content string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
