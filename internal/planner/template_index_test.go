package planner

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

func TestSafeReadOnlyTCPInputValidatesEveryRedisFrame(t *testing.T) {
	for _, value := range []string{"INFO\r\nQUIT\r\n", "INFO server\r\n", "PING\r\n", `INFO\r\nQUIT\r\n`} {
		if !safeReadOnlyTCPInput(value) {
			t.Fatalf("read-only Redis input rejected: %q", value)
		}
	}
	for _, value := range []string{
		"INFO\r\nFLUSHALL\r\n", "INFO\r\nSET key value\r\n", "PING message\r\n", "INFO server extra\r\n",
		"INFO\r\nUNKNOWN\r\n", "INFO\x00QUIT", `INFO\r\nFLUSHALL\r\n`, "INFO\rQUIT\r\n",
	} {
		if safeReadOnlyTCPInput(value) {
			t.Fatalf("unsafe Redis input accepted: %q", value)
		}
	}
}

func TestSafeAutomaticHTTPURLRejectsAuthenticationEncodingAndActions(t *testing.T) {
	for _, value := range []string{"{{BaseURL}}", "{{RootURL}}/php.ini", "{{BaseURL}}/health/check"} {
		if !safeAutomaticHTTPURL(value) {
			t.Fatalf("safe URL rejected: %q", value)
		}
	}
	for _, value := range []string{
		"{{BaseURL}}/check?user=admin&pass=admin", "{{BaseURL}}/check?%75ser=admin", "{{BaseURL}}/check?mode=read",
		"{{BaseURL}}/%64elete", "{{BaseURL}}/safe%252fdelete", "{{BaseURL}}/reset", "{{BaseURL}}/login",
		"{{BaseURL}}/reboot.cgi", "{{BaseURL}}/shutdown.action", "{{BaseURL}}/reset-password",
		"{{BaseURL}}/factory_reset.cgi",
		"{{BaseURL}}/%72eboot.cgi", "{{BaseURL}}/%2572eboot.cgi", "{{BaseURL}}/%252572eboot.cgi",
		"{{BaseURL}}/shutdown%252eaction", "{{BaseURL}}/reset%252dpassword",
		"{{BaseURL}}/{{username}}", "{{BaseURL}}/{{interactsh-url}}",
	} {
		if safeAutomaticHTTPURL(value) {
			t.Fatalf("unsafe URL accepted: %q", value)
		}
	}
}

func TestPolicyFilteredUsesExactCPEVendorVersionAndProtocol(t *testing.T) {
	root := t.TempDir()
	writeTemplateIndexFixture(t, root, "unsafe-exact.yaml", `
id: nginx-unsafe-exact
info:
  name: Nginx Unsafe Exact
  severity: high
  classification:
    cpe: cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*
  tags: nginx,vuln
http:
  - method: GET
    path: ["{{BaseURL}}"]
    payloads: {value: [test]}
`)
	writeTemplateIndexFixture(t, root, "unsafe-other-vendor.yaml", `
id: nginx-unsafe-other-vendor
info:
  name: Other Vendor Nginx
  severity: high
  classification:
    cpe: cpe:2.3:a:other:nginx:1.25.0:*:*:*:*:*:*:*
  tags: nginx,vuln
http:
  - method: GET
    path: ["{{BaseURL}}"]
    payloads: {value: [test]}
`)
	index, err := BuildNucleiTemplateIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	if !index.PolicyFiltered("nginx", "cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*", "https") {
		t.Fatal("exact rejected template did not produce policy_filtered")
	}
	for _, endpoint := range []struct{ cpe, protocol string }{
		{"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*", "http"},
		{"cpe:2.3:a:other:nginx:1.24.0:*:*:*:*:*:*:*", "http"},
		{"cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*", "tcp"},
	} {
		if index.PolicyFiltered("nginx", endpoint.cpe, endpoint.protocol) {
			t.Fatalf("unrelated rejected template leaked to %s/%s", endpoint.cpe, endpoint.protocol)
		}
	}
}

func TestNucleiTemplateIndexEnforcesFileAndStructureBudgets(t *testing.T) {
	root := t.TempDir()
	oversized := bytes.Repeat([]byte("x"), maxNucleiTemplateFileBytes+1)
	if err := os.WriteFile(filepath.Join(root, "oversized.yaml"), oversized, 0600); err != nil {
		t.Fatal(err)
	}
	requests := strings.Repeat("  - method: GET\n    path: [\"{{BaseURL}}\"]\n", maxNucleiRequestsPerTemplate+1)
	writeTemplateIndexFixture(t, root, "too-many-requests.yaml", `
id: too-many-requests
info:
  name: Too Many Requests
  severity: medium
  metadata: {product: nginx}
  tags: nginx,exposure
http:
`+requests)
	writeTemplateIndexFixture(t, root, "safe.yaml", `
id: bounded-safe
info:
  name: Bounded Safe
  severity: medium
  metadata: {product: nginx}
  tags: nginx,exposure
http:
  - method: GET
    path: ["{{BaseURL}}"]
`)
	index, err := BuildNucleiTemplateIndex(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Templates) != 1 || index.Templates[0].TemplateID != "bounded-safe" {
		t.Fatalf("budget projection=%#v", index.Templates)
	}

	matcherValues := strings.Repeat("          - value\n", maxNucleiMatcherValues+1)
	raw := `
id: too-many-values
info:
  name: Too Many Matcher Values
  severity: medium
  metadata: {product: nginx}
  tags: nginx,exposure
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers:
      - type: word
        words:
` + matcherValues
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &document); err != nil {
		t.Fatal(err)
	}
	if safeAutomaticNucleiTemplate(document) {
		t.Fatal("matcher value budget was not enforced")
	}
}

func TestNucleiTemplateIndexCountsOversizedFilesAgainstTotalBudget(t *testing.T) {
	root := t.TempDir()
	fileBytes := int64(maxNucleiTemplateFileBytes + 1)
	fileCount := int(maxNucleiTemplateTotalBytes/fileBytes) + 2
	for index := 0; index < fileCount; index++ {
		path := filepath.Join(root, fmt.Sprintf("oversized-%03d.yaml", index))
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(fileBytes); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := BuildNucleiTemplateIndex(root); err == nil || !strings.Contains(err.Error(), "byte budget exceeded") {
		t.Fatalf("oversized candidates did not exhaust total budget: %v", err)
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
	if len(index.Templates) != 366 || index.Revision != "nuclei-template-index-v5:d1cf38288bce60e512b1dd03f6f59ca29375ac344f67ae9480268e61008b28d0" {
		t.Fatalf("real index changed: templates=%d revision=%q", len(index.Templates), index.Revision)
	}
	redis := index.Select("redis", "", "tcp")
	if len(redis) != 1 {
		t.Fatalf("real index coverage redis=%d", len(redis))
	}
	php := index.Select("php", "cpe:2.3:a:php:php:8.1.2:*:*:*:*:*:*:*", "http")
	phpINI := false
	for _, candidate := range php {
		if candidate.TemplateID == "php-ini" && candidate.Path == "http/exposures/files/php-ini.yaml" && candidate.SHA256 == "933e2e60a0c1fa0d7fb3be463e8af3f3e958188bd7440653c9dfa689562ae806" {
			phpINI = true
		}
	}
	if !phpINI {
		t.Fatalf("reviewed PHP template missing from candidates: %#v", php)
	}
	for _, candidates := range [][]NucleiTemplateIndexEntry{redis, php} {
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
	t.Logf("real template index: executable=%d redis=%d php=%d revision=%s", len(index.Templates), len(redis), len(php), index.Revision)
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
