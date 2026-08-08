package fingerprint

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCollectWebEvidenceUsesHTTPSForHTTPSService(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/favicon.ico" {
			_, _ = writer.Write([]byte("fixture-icon"))
			return
		}
		writer.Header().Set("Server", "fixture")
		_, _ = writer.Write([]byte("<title>Fixture</title>body"))
	}))
	defer server.Close()
	ip, port := testServerEndpoint(t, server.URL)
	result, err := CollectWebEvidence(context.Background(), ip, port, "https", WebEvidenceOptions{AllowedPorts: map[int]struct{}{port: {}}})
	if err != nil {
		t.Fatalf("collect HTTPS evidence: %v", err)
	}
	if result.Protocol != "https" || result.Evidence.Title != "Fixture" || !strings.Contains(result.Evidence.Body, "body") || result.Evidence.FaviconMMH3 == "" {
		t.Fatalf("evidence = %#v", result)
	}
	if result.Evidence.FaviconMD5 != "5b58975659258dbb70043bead67726f1" || result.Evidence.FaviconMMH3 != "806439077" || result.Evidence.FaviconSHA256 != "bee7e9b52d709d5c75396349f67f3d9e08843e918026e1c210ea90f9029b037b" {
		t.Fatalf("unexpected favicon hashes: %#v", result.Evidence)
	}
	if !strings.Contains(result.Summary, "favicon_sha256="+result.Evidence.FaviconSHA256) || strings.Contains(result.Summary, result.Evidence.FaviconMMH3) {
		t.Fatalf("unsafe favicon summary: %q", result.Summary)
	}
}

func TestCollectWebEvidenceUsesOneTotalBudgetIncludingFavicon(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/favicon.ico" {
			<-request.Context().Done()
			return
		}
		_, _ = writer.Write([]byte("<title>ready</title>"))
	}))
	defer server.Close()
	ip, port := testServerEndpoint(t, server.URL)
	started := time.Now()
	result, err := CollectWebEvidence(context.Background(), ip, port, "http", WebEvidenceOptions{AllowedPorts: map[int]struct{}{port: {}}, Timeout: 120 * time.Millisecond})
	if err != nil {
		t.Fatalf("main evidence should survive favicon timeout: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 350*time.Millisecond {
		t.Fatalf("collection reset total budget: %s", elapsed)
	}
	if result.Evidence.BodyCapturedLength == 0 || result.Evidence.BodyCapturedSHA256 == "" {
		t.Fatalf("captured evidence contract missing: %#v", result.Evidence)
	}
}

func TestFaviconMMH3KnownVector(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R'}
	if got := faviconMMH3(png); got != "628805695" {
		t.Fatalf("favicon MMH3 = %q, want 628805695", got)
	}
}

func TestCollectWebEvidenceRejectsCrossHostRedirect(t *testing.T) {
	foreign := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("foreign"))
	}))
	defer foreign.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, foreign.URL, http.StatusFound)
	}))
	defer server.Close()
	ip, port := testServerEndpoint(t, server.URL)
	result, err := CollectWebEvidence(context.Background(), ip, port, "http", WebEvidenceOptions{AllowedPorts: map[int]struct{}{port: {}}})
	if err != nil {
		t.Fatalf("collect redirect response: %v", err)
	}
	if strings.Contains(result.Evidence.Body, "foreign") || !strings.Contains(result.Summary, "status=302") {
		t.Fatalf("cross-host redirect was followed: %#v", result)
	}
}

func TestCollectWebEvidenceRejectsCrossPortRedirect(t *testing.T) {
	foreign := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("foreign-port"))
	}))
	defer foreign.Close()
	foreignIP, foreignPort := testServerEndpoint(t, foreign.URL)
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, foreign.URL, http.StatusFound)
	}))
	defer origin.Close()
	ip, port := testServerEndpoint(t, origin.URL)
	if ip != foreignIP {
		t.Fatalf("test servers must share an IP: %s != %s", ip, foreignIP)
	}
	result, err := CollectWebEvidence(context.Background(), ip, port, "http", WebEvidenceOptions{AllowedPorts: map[int]struct{}{port: {}, foreignPort: {}}})
	if err != nil {
		t.Fatalf("collect redirect response: %v", err)
	}
	if strings.Contains(result.Evidence.Body, "foreign-port") || !strings.Contains(result.Summary, "status=302") {
		t.Fatalf("cross-port redirect was followed: %#v", result)
	}
}

func TestRedirectDefaultPortUsesTargetScheme(t *testing.T) {
	httpURL, _ := url.Parse("http://127.0.0.1/")
	httpsURL, _ := url.Parse("https://127.0.0.1/")
	if !sameAuthorizedEndpoint(httpURL, "127.0.0.1", 80, map[int]struct{}{80: {}}) {
		t.Fatal("HTTP default port should resolve to 80")
	}
	if !sameAuthorizedEndpoint(httpsURL, "127.0.0.1", 443, map[int]struct{}{443: {}}) {
		t.Fatal("HTTPS default port should resolve to 443")
	}
	if sameAuthorizedEndpoint(httpsURL, "127.0.0.1", 8080, map[int]struct{}{8080: {}, 443: {}}) {
		t.Fatal("redirect from 8080 to implicit HTTPS 443 must be rejected")
	}
}

func TestCollectWebEvidenceRejectsOversizedResponseHeadersAtTransport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Oversized", strings.Repeat("a", maxHTTPHeaderBytes+4096))
		_, _ = writer.Write([]byte("must not be accepted"))
	}))
	defer server.Close()
	ip, port := testServerEndpoint(t, server.URL)
	if _, err := CollectWebEvidence(context.Background(), ip, port, "http", WebEvidenceOptions{AllowedPorts: map[int]struct{}{port: {}}}); err == nil {
		t.Fatal("transport must reject a response header above the network limit")
	}
}

func TestCollectWebEvidenceDoesNotProbeNonWebService(t *testing.T) {
	if _, err := CollectWebEvidence(context.Background(), "127.0.0.1", 6379, "redis", WebEvidenceOptions{}); err != ErrNotWebService {
		t.Fatalf("error = %v, want ErrNotWebService", err)
	}
}

func testServerEndpoint(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("split server endpoint: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	return host, port
}
