package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golandproject/yscan/internal/fingerprint"
	"golandproject/yscan/internal/storage"
)

type baseline struct {
	Revision         string            `json:"revision"`
	Fixtures         []fixture         `json:"fixtures"`
	SemanticFixtures []semanticFixture `json:"semantic_fixtures"`
}

type fixture struct {
	Category        string `json:"category"`
	SourceKey       string `json:"source_key"`
	SourceCommit    string `json:"source_commit"`
	SourceRuleID    string `json:"source_rule_id"`
	Protocol        string `json:"protocol"`
	EvidenceType    string `json:"evidence_type"`
	Target          string `json:"target,omitempty"`
	Operator        string `json:"operator"`
	ObservedValue   string `json:"observed_value"`
	ExpectedProduct string `json:"expected_product"`
	ExpectedVersion string `json:"expected_version"`
	ExpectedCPE     string `json:"expected_cpe"`
}

type evidenceFixture struct {
	Protocol      string            `json:"protocol"`
	Banner        string            `json:"banner,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Meta          map[string]string `json:"meta,omitempty"`
	Cookies       map[string]string `json:"cookies,omitempty"`
	Title         string            `json:"title,omitempty"`
	Body          string            `json:"body,omitempty"`
	URL           string            `json:"url,omitempty"`
	FaviconMD5    string            `json:"favicon_md5,omitempty"`
	FaviconMMH3   string            `json:"favicon_mmh3,omitempty"`
	FaviconSHA256 string            `json:"favicon_sha256,omitempty"`
}

type semanticFixture struct {
	CaseID          string          `json:"case_id"`
	Category        string          `json:"category"`
	SourceKey       string          `json:"source_key"`
	SourceCommit    string          `json:"source_commit"`
	SourceRuleID    string          `json:"source_rule_id"`
	Mode            string          `json:"mode"`
	ProbeName       string          `json:"probe_name,omitempty"`
	ProbePort       int             `json:"probe_port,omitempty"`
	Service         string          `json:"service,omitempty"`
	Evidence        evidenceFixture `json:"evidence"`
	Negative        evidenceFixture `json:"negative_evidence"`
	Features        []string        `json:"features"`
	EvidenceOrigin  string          `json:"evidence_origin"`
	ExpectedProduct string          `json:"expected_product"`
	ExpectedVersion string          `json:"expected_version"`
	ExpectedCPE     string          `json:"expected_cpe"`
	ExpectedSoft    bool            `json:"expected_soft"`
}

type semanticSeed struct {
	CaseID, Category, SourceKey, SourceRuleID, Mode, ProbeName, Service string
	ProbePort                                                           int
	Evidence, Negative                                                  evidenceFixture
	Features                                                            []string
}

type category struct {
	Name     string
	Keywords []string
}

var categories = []category{
	{"web_framework", []string{"wordpress", "drupal", "django", "flask", "rails", "laravel", "thinkphp", "spring", "struts", "asp.net", "joomla", "vue", "react", "angular", "bootstrap", "next.js", "nuxt", "discuz", "php", "ruby"}},
	{"middleware", []string{"nginx", "apache", "iis", "tomcat", "jetty", "weblogic", "websphere", "jboss", "traefik", "haproxy", "caddy", "varnish", "squid", "envoy", "kong", "openresty", "lighttpd", "resin", "wildfly", "undertow"}},
	{"database_cache", []string{"mysql", "postgres", "mssql", "sql server", "oracle", "mongodb", "redis", "memcache", "elastic", "cassandra", "influx", "couch", "db2", "mariadb", "neo4j", "clickhouse", "solr", "hbase", "firebird", "riak"}},
	{"remote_management", []string{"ssh", "telnet", "rdp", "vnc", "winrm", "ftp", "smb", "ldap", "rpc", "teamviewer", "citrix", "remote", "x11", "nfs", "radmin", "vpn", "terminal", "pcanywhere", "nomachine", "webmin"}},
	{"container_k8s", []string{"kubernetes", "kube", "docker", "registry", "harbor", "rancher", "portainer", "etcd", "containerd", "openshift", "nomad", "mesos", "istio", "traefik", "prometheus", "grafana", "helm", "calico", "ceph", "minio"}},
	{"china_common", []string{"致远", "泛微", "用友", "金蝶", "蓝凌", "宝塔", "深信服", "绿盟", "topsec", "safe3", "奇安信", "天融信", "华为", "h3c", "锐捷", "dahua", "hikvision", "亿赛通", "帆软", "seeyon"}},
}

func main() {
	output := flag.String("output", "internal/fingerprint/testdata/t299/baseline.json", "baseline output path")
	flag.Parse()
	log.SetOutput(os.Stderr)

	temporary, err := os.MkdirTemp("", "caasm-t299-")
	must(err)
	defer os.RemoveAll(temporary)
	db, err := storage.InitDBAt(filepath.Join(temporary, "baseline.db"))
	must(err)
	defer db.Close()

	registry, err := fingerprint.NewEmbeddedRegistry(db)
	must(err)
	for _, source := range registry.Manifest.Sources {
		_, err := registry.Import(context.Background(), source.SourceKey, "")
		must(err)
	}

	fixtures, err := selectFixtures(db)
	must(err)
	semanticFixtures, err := selectSemanticFixtures(db)
	must(err)
	encoded, err := json.MarshalIndent(baseline{Revision: "t299-v3", Fixtures: fixtures, SemanticFixtures: semanticFixtures}, "", "  ")
	must(err)
	must(os.MkdirAll(filepath.Dir(*output), 0o755))
	must(os.WriteFile(*output, append(encoded, '\n'), 0o644))
	fmt.Printf("wrote %d category fixtures and %d semantic fixtures to %s\n", len(fixtures), len(semanticFixtures), *output)
}

func selectFixtures(db *sql.DB) ([]fixture, error) {
	rows, err := db.Query(`
		SELECT source.source_key, fingerprint_import.commit_hash, source_rule.source_rule_id,
			product.canonical_name, rule.protocol, matcher.evidence_type, COALESCE(matcher.target, ''),
			matcher.operator, matcher.value, COALESCE(rule.version_template, ''), COALESCE(rule.cpe, '')
		FROM fingerprint_rules rule
		JOIN fingerprint_source_rules source_rule ON source_rule.id = rule.fingerprint_source_rule_id
		JOIN fingerprint_imports fingerprint_import ON fingerprint_import.id = source_rule.fingerprint_import_id AND fingerprint_import.is_active = 1
		JOIN fingerprint_sources source ON source.id = fingerprint_import.fingerprint_source_id
		JOIN fingerprint_products product ON product.id = rule.fingerprint_product_id
		JOIN fingerprint_match_groups match_group ON match_group.fingerprint_rule_id = rule.id
		JOIN fingerprint_matchers matcher ON matcher.fingerprint_match_group_id = match_group.id
		WHERE rule.status = 'executable' AND source.source_key <> 'legacy-banner'
			AND COALESCE(source_rule.source_rule_id, '') <> ''
			AND (SELECT COUNT(*) FROM fingerprint_match_groups g WHERE g.fingerprint_rule_id = rule.id) = 1
			AND (SELECT COUNT(*) FROM fingerprint_matchers m JOIN fingerprint_match_groups g ON g.id = m.fingerprint_match_group_id WHERE g.fingerprint_rule_id = rule.id) = 1
			AND matcher.operator IN ('contains', 'contains_ci', 'equals', 'exists')
		ORDER BY product.canonical_name, source.source_key, source_rule.source_rule_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var candidates []fixture
	for rows.Next() {
		var value fixture
		if err := rows.Scan(&value.SourceKey, &value.SourceCommit, &value.SourceRuleID, &value.ExpectedProduct,
			&value.Protocol, &value.EvidenceType, &value.Target, &value.Operator, &value.ObservedValue,
			&value.ExpectedVersion, &value.ExpectedCPE); err != nil {
			return nil, err
		}
		candidates = append(candidates, value)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	used := make(map[string]struct{})
	selected := make([]fixture, 0, 120)
	for _, group := range categories {
		count := 0
		for _, candidate := range candidates {
			key := candidate.SourceKey + "\x00" + candidate.SourceRuleID
			if _, exists := used[key]; exists || !containsKeyword(candidate.ExpectedProduct, group.Keywords) {
				continue
			}
			candidate.Category = group.Name
			selected = append(selected, candidate)
			used[key] = struct{}{}
			count++
			if count == 20 {
				break
			}
		}
		if count != 20 {
			return nil, fmt.Errorf("category %s has %d eligible unique fixtures, want 20", group.Name, count)
		}
	}
	return selected, nil
}

func selectSemanticFixtures(db *sql.DB) ([]semanticFixture, error) {
	engine, err := fingerprint.LoadActiveEngine(db)
	if err != nil {
		return nil, err
	}
	seeds := semanticSeeds()
	result := make([]semanticFixture, 0, len(seeds))
	for _, seed := range seeds {
		var commit, status string
		if err := db.QueryRow(`
			SELECT fingerprint_import.commit_hash, source_rule.import_status
			FROM fingerprint_source_rules AS source_rule
			JOIN fingerprint_imports AS fingerprint_import ON fingerprint_import.id = source_rule.fingerprint_import_id AND fingerprint_import.is_active = 1
			JOIN fingerprint_sources AS source ON source.id = fingerprint_import.fingerprint_source_id
			WHERE source.source_key = ? AND source_rule.source_rule_id = ?`, seed.SourceKey, seed.SourceRuleID).Scan(&commit, &status); err != nil {
			return nil, fmt.Errorf("resolve semantic fixture %s: %w", seed.CaseID, err)
		}
		if status != "executable" {
			return nil, fmt.Errorf("semantic fixture %s source rule is %s", seed.CaseID, status)
		}
		match, ok := semanticSeedMatch(engine, seed, seed.Evidence)
		if !ok {
			return nil, fmt.Errorf("semantic fixture %s positive evidence did not match", seed.CaseID)
		}
		if _, matched := semanticSeedMatch(engine, seed, seed.Negative); matched {
			return nil, fmt.Errorf("semantic fixture %s negative evidence matched", seed.CaseID)
		}
		result = append(result, semanticFixture{
			CaseID: seed.CaseID, Category: seed.Category, SourceKey: seed.SourceKey, SourceCommit: commit,
			SourceRuleID: seed.SourceRuleID, Mode: seed.Mode, ProbeName: seed.ProbeName, ProbePort: seed.ProbePort,
			Service: seed.Service, Evidence: seed.Evidence, Negative: seed.Negative, Features: seed.Features,
			EvidenceOrigin:  "curated-real-response",
			ExpectedProduct: match.Product, ExpectedVersion: match.Version, ExpectedCPE: match.CPE, ExpectedSoft: match.Soft,
		})
	}
	return result, nil
}

func semanticSeedMatch(engine *fingerprint.Engine, seed semanticSeed, evidence evidenceFixture) (fingerprint.Match, bool) {
	var matches []fingerprint.Match
	if seed.Mode == "nmap_active" {
		allowed := false
		for _, probe := range engine.NmapTCPProbesForEndpoint(seed.ProbePort, seed.Service) {
			if probe.Name == seed.ProbeName {
				allowed = true
				break
			}
		}
		if !allowed {
			return fingerprint.Match{}, false
		}
		matches = engine.MatchNmapTCPProbeResponse(seed.ProbeName, []byte(evidence.Banner))
	} else {
		matches = engine.Match(fingerprint.Evidence{
			Protocol: evidence.Protocol, Banner: evidence.Banner, Headers: evidence.Headers, Meta: evidence.Meta,
			Cookies: evidence.Cookies, Title: evidence.Title, Body: evidence.Body, URL: evidence.URL,
			FaviconMD5: evidence.FaviconMD5, FaviconMMH3: evidence.FaviconMMH3, FaviconSHA256: evidence.FaviconSHA256,
		})
	}
	for _, match := range matches {
		if match.SourceKey == seed.SourceKey && match.SourceRuleID == seed.SourceRuleID {
			return match, true
		}
	}
	return fingerprint.Match{}, false
}

func semanticSeeds() []semanticSeed {
	tcpNegative := evidenceFixture{Protocol: "tcp", Banner: "T299 negative banner\r\n"}
	return []semanticSeed{
		{CaseID: "fh-v3-apache-struts-header", Category: "web_framework", SourceKey: "fingerprinthub-web-v3", SourceRuleID: "index:195", Mode: "passive", Evidence: evidenceFixture{Protocol: "http", Headers: map[string]string{"Location": "/index.action"}}, Negative: evidenceFixture{Protocol: "http", Headers: map[string]string{"Location": "/login"}}, Features: []string{"http_header"}},
		{CaseID: "fh-v4-nginx-header", Category: "middleware", SourceKey: "fingerprinthub-web-v4", SourceRuleID: "nginx", Mode: "passive", Evidence: evidenceFixture{Protocol: "http", Headers: map[string]string{"Server": "nginx/1.27.5"}}, Negative: evidenceFixture{Protocol: "http", Headers: map[string]string{"Server": "fixture"}}, Features: []string{"http_header"}},
		{CaseID: "ehole-apache-airflow-title", Category: "middleware", SourceKey: "ehole", SourceRuleID: "Apache Airflow:100", Mode: "passive", Evidence: evidenceFixture{Protocol: "http", Title: "Airflow - Login"}, Negative: evidenceFixture{Protocol: "http", Title: "Sign in"}, Features: []string{"html_title"}},
		{CaseID: "fscan-bt-panel-body", Category: "china_common", SourceKey: "fscan-native-web", SourceRuleID: "regex:0", Mode: "passive", Evidence: evidenceFixture{Protocol: "http", Body: `<img src="https://app.bt.cn/static/app.png">`}, Negative: evidenceFixture{Protocol: "http", Body: `<img src="/static/app.png">`}, Features: []string{"http_body", "regex"}},
		{CaseID: "fh-service-lukemftpd", Category: "remote_management", SourceKey: "fingerprinthub-service-yaml", SourceRuleID: "null/ftp/1002551213", Mode: "passive", Evidence: evidenceFixture{Protocol: "tcp", Banner: "220 fixture FTP server (lukemftpd 1.2) ready.\r\n"}, Negative: tcpNegative, Features: []string{"tcp_banner", "regex", "version"}},
		{CaseID: "tcp-securetransport", Category: "remote_management", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:NULL:327", Mode: "passive", Evidence: evidenceFixture{Protocol: "tcp", Banner: "220 host FTP server (SecureTransport 5.2) ready.\r\n"}, Negative: tcpNegative, Features: []string{"tcp_banner", "regex", "version", "cpe"}},
		{CaseID: "tcp-3com-ftpd", Category: "remote_management", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:NULL:329", Mode: "passive", Evidence: evidenceFixture{Protocol: "tcp", Banner: "220 3Com 3CDaemon FTP Server Version 2.0\r\n"}, Negative: tcpNegative, Features: []string{"tcp_banner", "regex", "version"}},
		{CaseID: "tcp-guild-ftpd", Category: "remote_management", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:NULL:331", Mode: "passive", Evidence: evidenceFixture{Protocol: "tcp", Banner: "220-GuildFTPd FTP Server (c) 2020-2024\r\n220-Version 1.2\r\n"}, Negative: tcpNegative, Features: []string{"tcp_banner", "regex", "version", "cpe"}},
		{CaseID: "tcp-iis-denied", Category: "remote_management", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:NULL:338", Mode: "passive", Evidence: evidenceFixture{Protocol: "tcp", Banner: "530 Connection refused, unknown IP address.\r\n"}, Negative: tcpNegative, Features: []string{"tcp_banner", "regex", "cpe"}},
		{CaseID: "tcp-iis-version", Category: "remote_management", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:NULL:339", Mode: "passive", Evidence: evidenceFixture{Protocol: "tcp", Banner: "220 IIS 10.0 FTP\r\n"}, Negative: tcpNegative, Features: []string{"tcp_banner", "regex", "version", "cpe"}},
		{CaseID: "tcp-vsftpd-bind", Category: "remote_management", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:NULL:349", Mode: "passive", Evidence: evidenceFixture{Protocol: "tcp", Banner: "500 OOPS: could not bind listening IPv4 socket\r\n"}, Negative: tcpNegative, Features: []string{"tcp_banner", "regex", "cpe"}},
		{CaseID: "tcp-vsftpd-error", Category: "remote_management", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:NULL:350", Mode: "passive", Evidence: evidenceFixture{Protocol: "tcp", Banner: "500 OOPS: vsftpd: configuration error\r\n"}, Negative: tcpNegative, Features: []string{"tcp_banner", "regex", "cpe"}},
		{CaseID: "tcp-filezilla-static", Category: "remote_management", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:NULL:354", Mode: "passive", Evidence: evidenceFixture{Protocol: "tcp", Banner: "220 FTP Server - FileZilla\r\n"}, Negative: tcpNegative, Features: []string{"tcp_banner", "regex", "cpe"}},
		{CaseID: "tcp-filezilla-version", Category: "remote_management", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:NULL:358", Mode: "passive", Evidence: evidenceFixture{Protocol: "tcp", Banner: "220 FileZilla Server 1.9.0\r\n"}, Negative: tcpNegative, Features: []string{"tcp_banner", "regex", "version", "cpe"}},
		{CaseID: "tcp-gnu-inetutils", Category: "remote_management", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:NULL:363", Mode: "passive", Evidence: evidenceFixture{Protocol: "tcp", Banner: "220 (none) FTP server (GNU inetutils 2.4) ready.\r\n"}, Negative: tcpNegative, Features: []string{"tcp_banner", "regex", "version", "cpe"}},
		{CaseID: "probe-bitcoin-jsonrpc", Category: "database_cache", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:GetRequest:4803", Mode: "nmap_active", ProbeName: "GetRequest", ProbePort: 80, Service: "unknown", Evidence: evidenceFixture{Protocol: "tcp", Banner: "HTTP/1.0 405 Method Not Allowed\r\nContent-Type: text/html; charset=ISO-8859-1\r\n\r\nJSONRPC server handles only POST requests"}, Negative: tcpNegative, Features: []string{"nmap_active", "regex"}},
		{CaseID: "probe-distributed-keyproxy", Category: "middleware", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:GetRequest:4831", Mode: "nmap_active", ProbeName: "GetRequest", ProbePort: 80, Service: "unknown", Evidence: evidenceFixture{Protocol: "tcp", Banner: "HTTP/1.0 302 Found\r\nLocation: http://www.distributed.net/\r\n\r\n"}, Negative: tcpNegative, Features: []string{"nmap_active", "regex"}},
		{CaseID: "probe-docker", Category: "container_k8s", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:GetRequest:4832", Mode: "nmap_active", ProbeName: "GetRequest", ProbePort: 80, Service: "unknown", Evidence: evidenceFixture{Protocol: "tcp", Banner: "HTTP/1.0 404 Not Found\r\nContent-Type: application/json\r\nDate: fixture\r\nContent-Length: 29\r\n\r\n{\"message\":\"page not found\"}\n"}, Negative: tcpNegative, Features: []string{"nmap_active", "regex", "soft"}},
		{CaseID: "probe-elasticsearch", Category: "database_cache", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:GetRequest:4837", Mode: "nmap_active", ProbeName: "GetRequest", ProbePort: 80, Service: "unknown", Evidence: evidenceFixture{Protocol: "tcp", Banner: "This is not an HTTP port"}, Negative: tcpNegative, Features: []string{"nmap_active", "regex", "cpe"}},
		{CaseID: "probe-ethereum-jsonrpc", Category: "database_cache", SourceKey: "nmap-service-probes", SourceRuleID: "tcp:GetRequest:4840", Mode: "nmap_active", ProbeName: "GetRequest", ProbePort: 80, Service: "unknown", Evidence: evidenceFixture{Protocol: "tcp", Banner: "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nVary: Origin\r\nDate: fixture\r\nContent-Length: 55\r\n\r\n{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"EOF\"}}\n"}, Negative: tcpNegative, Features: []string{"nmap_active", "regex"}},
		{CaseID: "whatweb-4d-offset", Category: "middleware", SourceKey: "whatweb", SourceRuleID: "4d", Mode: "passive", Evidence: evidenceFixture{Protocol: "http", Headers: map[string]string{"Server": "4D_v19_SQL/12.3"}}, Negative: evidenceFixture{Protocol: "http", Headers: map[string]string{"Server": "Apache"}}, Features: []string{"http_header", "regex", "version", "offset"}},
		{CaseID: "whatweb-jenkins-version", Category: "web_framework", SourceKey: "whatweb", SourceRuleID: "jenkins", Mode: "passive", Evidence: evidenceFixture{Protocol: "http", Headers: map[string]string{"X-Jenkins": "2.452.1"}}, Negative: evidenceFixture{Protocol: "http", Headers: map[string]string{"Server": "Jenkins"}}, Features: []string{"http_header", "regex", "version"}},
		{CaseID: "wapp-nagacommerce-meta", Category: "web_framework", SourceKey: "wappalyzer", SourceRuleID: "NagaCommerce", Mode: "passive", Evidence: evidenceFixture{Protocol: "http", Meta: map[string]string{"generator": "NagaCommerce"}}, Negative: evidenceFixture{Protocol: "http", Meta: map[string]string{"generator": "other"}}, Features: []string{"html_meta", "regex"}},
		{CaseID: "wapp-naver-script-version", Category: "web_framework", SourceKey: "wappalyzer", SourceRuleID: "Naver Maps", Mode: "passive", Evidence: evidenceFixture{Protocol: "http", Body: `<script src="https://openapi.map.naver.com/openapi/v3.0/maps.js"></script>`}, Negative: evidenceFixture{Protocol: "http", Body: `<script src="/maps.js"></script>`}, Features: []string{"http_body", "regex", "version"}},
		{CaseID: "wapp-neos-header-version", Category: "web_framework", SourceKey: "wappalyzer", SourceRuleID: "Neos CMS", Mode: "passive", Evidence: evidenceFixture{Protocol: "http", Headers: map[string]string{"X-Flow-Powered": "Neos/8.3"}}, Negative: evidenceFixture{Protocol: "http", Headers: map[string]string{"X-Flow-Powered": "Flow"}}, Features: []string{"http_header", "regex", "version"}},
		{CaseID: "wapp-netsuite-cookie", Category: "web_framework", SourceKey: "wappalyzer", SourceRuleID: "NetSuite", Mode: "passive", Evidence: evidenceFixture{Protocol: "http", Cookies: map[string]string{"ns_ver": ""}}, Negative: evidenceFixture{Protocol: "http", Cookies: map[string]string{}}, Features: []string{"http_cookie", "exists"}},
		{CaseID: "wapp-netlify-url", Category: "container_k8s", SourceKey: "wappalyzer", SourceRuleID: "Netlify", Mode: "passive", Evidence: evidenceFixture{Protocol: "https", URL: "https://fixture.netlify.app/"}, Negative: evidenceFixture{Protocol: "https", URL: "https://example.invalid/"}, Features: []string{"http_url", "regex"}},
		{CaseID: "fh-jenkins-and", Category: "web_framework", SourceKey: "fingerprinthub-web-yaml", SourceRuleID: "jenkins/jenkins", Mode: "passive", Evidence: evidenceFixture{Protocol: "http", Headers: map[string]string{"X-Jenkins": "2.452", "X-Jenkins-Session": "fixture"}}, Negative: evidenceFixture{Protocol: "http", Headers: map[string]string{"X-Jenkins": "2.452"}}, Features: []string{"http_header", "group_all"}},
		{CaseID: "fh-jenkins-favicon-or", Category: "web_framework", SourceKey: "fingerprinthub-web-yaml", SourceRuleID: "jenkins/jenkins", Mode: "passive", Evidence: evidenceFixture{Protocol: "http", FaviconMD5: "23e8c7bd78e8cd826c5a6073b15068b1"}, Negative: evidenceFixture{Protocol: "http", FaviconMD5: "00000000000000000000000000000000"}, Features: []string{"favicon_hash", "group_any"}},
		{CaseID: "fh-harbor-regex", Category: "container_k8s", SourceKey: "fingerprinthub-web-yaml", SourceRuleID: "goharbor/harbor", Mode: "passive", Evidence: evidenceFixture{Protocol: "https", Body: "<TITLE>Harbor Registry</TITLE>"}, Negative: evidenceFixture{Protocol: "https", Body: "registry"}, Features: []string{"http_body", "regex"}},
		{CaseID: "fh-seeyon-and", Category: "china_common", SourceKey: "fingerprinthub-web-yaml", SourceRuleID: "00_unknown/yonyou-seeyon-oa", Mode: "passive", Evidence: evidenceFixture{Protocol: "http", Body: "seeyon seeyonproductid"}, Negative: evidenceFixture{Protocol: "http", Body: "seeyon"}, Features: []string{"http_body", "group_all", "group_any"}},
	}
}

func containsKeyword(value string, keywords []string) bool {
	value = strings.ToLower(value)
	for _, keyword := range keywords {
		if strings.Contains(value, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
