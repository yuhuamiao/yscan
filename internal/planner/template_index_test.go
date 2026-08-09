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
	writeTemplateIndexFixture(t, root, "unsafe/payload-auth.yaml", `
id: unsafe-payload-auth
info:
  name: Unsafe Payload Authentication
  severity: high
  metadata: {product: php}
  tags: php,vuln
http:
  - method: GET
    path: ["{{BaseURL}}/login?username={{username}}&password={{password}}"]
    payloads:
      username: [admin]
      password: [admin]
    attack: pitchfork
`)
	writeTemplateIndexFixture(t, root, "unsafe/header-auth.yaml", `
id: unsafe-header-auth
info:
  name: Unsafe Authorization Header
  severity: high
  metadata: {product: php}
  tags: php,vuln
http:
  - method: GET
    path: ["{{BaseURL}}"]
    headers:
      Authorization: Basic dGVzdDp0ZXN0
`)
	writeTemplateIndexFixture(t, root, "unsafe/redirect.yaml", `
id: unsafe-redirect
info:
  name: Unsafe Redirect
  severity: medium
  metadata: {product: php}
  tags: php,vuln
http:
  - method: GET
    path: ["{{BaseURL}}"]
    redirects: true
`)
	writeTemplateIndexFixture(t, root, "unsafe/oast.yaml", `
id: unsafe-oast
info:
  name: Unsafe OAST
  severity: high
  metadata: {product: php}
  tags: php,vuln,oast
http:
  - method: GET
    path: ["{{BaseURL}}/{{interactsh-url}}"]
`)
	writeTemplateIndexFixture(t, root, "unsafe/runtime-tag.yaml", `
id: runtime-tag-is-not-a-product
info:
  name: Runtime Tag Is Not A Product
  severity: medium
  tags: python,config
http:
  - method: GET
    path: ["{{BaseURL}}"]
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
	if !index.PolicyFiltered("php", "", "https") {
		t.Fatal("unsafe PHP payload/auth templates were not recorded as policy-filtered")
	}
	if index.PolicyFiltered("python", "", "http") {
		t.Fatal("unreviewed runtime tag must not become a rejected product selector")
	}
	php := index.Select("php", "cpe:2.3:a:php:php:8.2:*:*:*:*:*:*:*", "https")
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
	if got := index.Select("nginx", "", "http"); len(got) != 0 {
		t.Fatalf("CPE-constrained template matched without endpoint CPE: %#v", got)
	}
	if got := index.Select("nginx", "cpe:2.3:a:other:nginx:*:*:*:*:*:*:*:*", "http"); len(got) != 0 {
		t.Fatalf("CPE-constrained template crossed vendor: %#v", got)
	}
	nginx := index.Select("nginx", "cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*", "http")
	if len(nginx) != 1 || nginx[0].TemplateID != "nginx-cpe-check" {
		t.Fatalf("CPE-only candidates=%#v", nginx)
	}
}

func TestNucleiTemplateIndexHonorsCPEVersionAndReviewedTags(t *testing.T) {
	root := t.TempDir()
	writeTemplateIndexFixture(t, root, "nginx-version.yaml", `
id: nginx-version
info:
  name: Nginx Version Check
  severity: high
  classification:
    cpe: cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*
  tags: cve,nginx
http:
  - method: GET
    path: ["{{BaseURL}}"]
`)
	writeTemplateIndexFixture(t, root, "redis-reviewed-tag.yaml", `
id: redis-reviewed-tag
info:
  name: Redis Reviewed Tag
  severity: high
  tags: redis,exposure
tcp:
  - inputs:
      - data: "info\r\nquit\r\n"
`)
	index, err := BuildNucleiTemplateIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := index.Select("nginx", "cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*", "http"); len(got) != 0 {
		t.Fatalf("version-constrained template crossed version: %#v", got)
	}
	if got := index.Select("nginx", "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*", "http"); len(got) != 1 {
		t.Fatalf("exact CPE candidate=%#v", got)
	}
	if got := index.Select("redis", "", "tcp"); len(got) != 1 || got[0].TemplateID != "redis-reviewed-tag" {
		t.Fatalf("reviewed product tag candidate=%#v", got)
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
	if len(index.Templates) != 177 || index.Revision != "nuclei-template-index-v3:4f4a86d882371294568bc68bac65899f2e0930805362105de3985824717d9f23" {
		t.Fatalf("real index changed: templates=%d revision=%q", len(index.Templates), index.Revision)
	}
	redis := index.Select("redis", "", "tcp")
	if len(redis) != 1 {
		t.Fatalf("real index coverage redis=%d", len(redis))
	}
	for _, candidates := range [][]NucleiTemplateIndexEntry{redis} {
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
	for _, forbidden := range []string{"CVE-2013-4982", "php-detect", "sshd-dropbear-detect", "redis-honeypot-detect", "python-code-injection", "twig-php-ssti"} {
		for _, candidate := range index.Templates {
			if candidate.TemplateID == forbidden {
				t.Fatalf("detection or intrusive template entered automatic index: %#v", candidate)
			}
		}
	}
	t.Logf("real template index: executable=%d redis=%d revision=%s", len(index.Templates), len(redis), index.Revision)
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
