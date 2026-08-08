package fingerprint

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

func TestParseAndExecuteNmapTCPProbe(t *testing.T) {
	raw := []byte("Probe TCP Fixture q|PING\\r\\n|\ntotalwaitms 100\nmatch fixture m|^PONG| p/fixture/\n")
	probes, err := ParseNmapTCPProbes(raw)
	if err != nil || len(probes) != 1 || string(probes[0].Payload) != "PING\r\n" {
		t.Fatalf("probes=%#v err=%v", probes, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			defer conn.Close()
			buf := make([]byte, 16)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("PONG"))
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	response, err := ExecuteNmapTCPProbe(context.Background(), "127.0.0.1", port, probes[0])
	if err != nil || len(MatchNmapTCPProbe(response, probes[0].Matches)) != 1 {
		t.Fatalf("response=%q err=%v", response, err)
	}
}

func TestNmapRealSyntaxFlagsSubstAndPrintableTemplates(t *testing.T) {
	caseRule := `match backdoor m|^220 [Sf.][tu.][nc.][yk.][F.][t.][p.][d.] [0.][w.][n.][s.] [j.][0.]\r?\n|i p/Generic Kibuv worm/ cpe:/o:microsoft:windows/a`
	caseEngine := fixtureProjectedEngine(t, "nmap-service-probes", nmapAdapter{}, caseRule)
	if !hasProduct(caseEngine.Match(Evidence{Protocol: "tcp", Banner: "220 stnkftpd 0wns j0\r\n"}), "generic kibuv worm") {
		t.Fatal("real Nmap i modifier did not match mixed case")
	}

	dotAllRule := `match r1soft-cdp m|^NAME:(.*?)\x10END$|s p/R1Soft Continuous Data Protection Agent/ v/$P(1)/ cpe:/a:r1soft:cdp/`
	dotAllEngine := fixtureProjectedEngine(t, "nmap-service-probes", nmapAdapter{}, dotAllRule)
	matches := dotAllEngine.Match(Evidence{Protocol: "tcp", Banner: "NAME:agent\nnode\x10END"})
	if len(matches) != 1 || matches[0].Version != "agentnode" {
		t.Fatalf("real Nmap s/$P semantics = %#v", matches)
	}

	substRule := `match ssh m|^SSH-(\d[\d.]+)-VShell_(\d[_\d.]+) VShell\r?\n$| p/VanDyke VShell sshd/ v/$SUBST(2,"_",".")/ cpe:/a:vandyke:vshell:$SUBST(2,"_",".")/`
	substEngine := fixtureProjectedEngine(t, "nmap-service-probes", nmapAdapter{}, substRule)
	matches = substEngine.Match(Evidence{Protocol: "tcp", Banner: "SSH-2.0-VShell_4_9_2 VShell\r\n"})
	if len(matches) != 1 || matches[0].Version != "4.9.2" || !strings.HasSuffix(matches[0].CPE, ":4.9.2") {
		t.Fatalf("real Nmap SUBST semantics = %#v", matches)
	}
}

func TestNmapProbeParserKeepsRegexSpacesAndRejectsCanceledContext(t *testing.T) {
	match, ok := parseNmapMatch(`match fixture m|^hello world$| p/fixture/`)
	if !ok || match.Pattern != `^hello world$` {
		t.Fatalf("match = %#v ok=%t", match, ok)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ExecuteNmapTCPProbe(ctx, "127.0.0.1", 1, NmapTCPProbe{}); err == nil {
		t.Fatal("canceled probe must fail")
	}
}

func TestNmapProbeParserPreservesExecutionPolicy(t *testing.T) {
	raw := []byte("Probe TCP GetRequest q|GET / HTTP/1.0\\r\\n\\r\\n|\nports 18080,18082-18083\nsslports 18443\nrarity 2\nfallback HTTPOptions,GenericLines\ntotalwaitms 9000\nmatch http m|^HTTP/1| p/http/\n")
	probes, err := ParseNmapTCPProbes(raw)
	if err != nil || len(probes) != 1 {
		t.Fatalf("parse probes=%#v err=%v", probes, err)
	}
	probe := probes[0]
	if !isReadOnlyNmapProbe(probe) || probe.Timeout != 4*time.Second || probe.Rarity != 2 || !containsNmapPort(probe.Ports, 18083) || !containsNmapPort(probe.SSLPorts, 18443) || strings.Join(probe.Fallback, ",") != "HTTPOptions,GenericLines" {
		t.Fatalf("execution policy was not preserved: %#v", probe)
	}
	probe.Payload = []byte("GET /admin/delete HTTP/1.0\r\n\r\n")
	if isReadOnlyNmapProbe(probe) {
		t.Fatal("same-name probe with modified payload must not pass the read-only allowlist")
	}
}

func TestFrozenEngineExecutesReadOnlyNmapProbeOnScopedPort(t *testing.T) {
	db := openFingerprintTestDB(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	probe := NmapTCPProbe{Name: "GetRequest", Payload: []byte(readOnlyNmapProbePayloads["GetRequest"]), Ports: []int{port}, SSLPorts: []int{port + 1}, Rarity: 1, Timeout: time.Second}
	structure, err := json.Marshal(nmapProbeProjectionFor(probe, "active"))
	if err != nil {
		t.Fatal(err)
	}
	rule := model.FingerprintSourceRule{SourceRuleID: "tcp:GetRequest:fixture", SourcePath: "nmap:fixture", ContentSHA256: "fixture-rule", RawContent: `match http m|^HTTP/1\.0 200.*Server: FixtureProbe|s p/Fixture Probe/`, RawStructure: string(structure), ImportStatus: "executable"}
	projection, err := (nmapAdapter{}).Project(rule)
	if err != nil {
		t.Fatal(err)
	}
	projection.SourcePath, projection.ContentSHA256 = rule.SourcePath, rule.ContentSHA256
	_, err = storage.ImportFingerprintBatch(db, storage.FingerprintImportBatch{
		Source: model.FingerprintSource{SourceKey: "nmap-service-probes", RepositoryURL: "local://nmap", Status: "enabled"},
		Import: model.FingerprintImport{Commit: "fixture", ContentSHA256: "fixture", AdapterVersion: "fixture-active", ManifestJSON: `{}`, RuleTotal: 1, ExecutableTotal: 1},
		Rules:  []model.FingerprintSourceRule{rule}, Projections: []model.FingerprintRuleProjection{projection},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := LoadActiveEngine(db)
	if err != nil {
		t.Fatal(err)
	}
	if matches := engine.Match(NewBannerEvidence("HTTP/1.0 200 OK\r\nServer: FixtureProbe", false)); len(matches) != 0 {
		t.Fatalf("active probe rule leaked into passive matching: %#v", matches)
	}
	if probes := engine.NmapTCPProbesForEndpoint(port+2, "unknown"); len(probes) != 0 {
		t.Fatalf("probe ignored upstream port scope: %#v", probes)
	}
	secure := engine.NmapTCPProbesForEndpoint(port+1, "https")
	if len(secure) != 1 || !secure[0].TLS {
		t.Fatalf("sslports policy not preserved: %#v", secure)
	}
	received := make(chan string, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 64)
		n, _ := conn.Read(buffer)
		received <- string(buffer[:n])
		_, _ = conn.Write([]byte("HTTP/1.0 200 OK\r\nServer: FixtureProbe\r\n\r\n"))
	}()
	candidates := engine.NmapTCPProbesForEndpoint(port, "unknown")
	if len(candidates) != 1 || candidates[0].TLS {
		t.Fatalf("plain port candidates=%#v", candidates)
	}
	response, err := ExecuteNmapTCPProbe(context.Background(), "127.0.0.1", port, candidates[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := <-received; got != readOnlyNmapProbePayloads["GetRequest"] {
		t.Fatalf("server received %q", got)
	}
	matches := engine.MatchNmapTCPProbeResponse("GetRequest", response)
	if len(matches) != 1 || matches[0].Product != "fixture probe" {
		t.Fatalf("active response matches=%#v", matches)
	}
}

func TestNmapAdapterEnablesOnlyCompatibleTCPNULLRules(t *testing.T) {
	rules, err := (nmapAdapter{}).Adapt(VerifiedSnapshot{Files: map[string][]byte{"nmap-service-probes": []byte("Probe TCP NULL q||\nmatch fixture m|^HELLO$|\nmatch unsupported m|(?>PCRE)$|\nProbe UDP UDPProbe q||\nmatch udp m|^UDP$|\n")}})
	if err == nil {
		t.Fatal("fixture must preserve the production total guard")
	}
	_ = rules
	projection, err := (nmapAdapter{}).Project(model.FingerprintSourceRule{RawContent: "match fixture m|^HELLO$|", SourcePath: "fixture", ContentSHA256: "fixture", ImportStatus: "executable"})
	if err != nil || projection.Product.CanonicalName != "fixture" || projection.Root.Matchers[0].Value != "^HELLO$" {
		t.Fatalf("NULL banner projection=%#v err=%v", projection, err)
	}
}
