package fingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCollectHTTPEvidenceExtractsBoundedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-Zeta", "last")
		response.Header().Set("X-Alpha", "first")
		response.Header().Set("Server", "acme-gateway")
		_, _ = response.Write([]byte("<html><head><title>  Yscan   CAASM </title></head><body>fingerprint-body-that-is-long-enough-to-truncate</body></html>"))
	}))
	defer server.Close()

	options := DefaultHTTPEvidenceOptions()
	options.MaxBodyBytes = 96
	options.MaxBodySummaryBytes = 24
	evidence, err := CollectHTTPEvidence(context.Background(), server.URL, options)
	if err != nil {
		t.Fatalf("collect evidence: %v", err)
	}
	if evidence.StatusCode != http.StatusOK || evidence.FinalURL != server.URL {
		t.Fatalf("response metadata = %#v", evidence)
	}
	if evidence.Headers.Get("Server") != "acme-gateway" || evidence.Title != "Yscan CAASM" {
		t.Fatalf("headers or title = %#v", evidence)
	}
	if !evidence.BodyTruncated || !evidence.SummaryTruncated || len(evidence.BodySummary) > options.MaxBodySummaryBytes {
		t.Fatalf("body bounds = %#v", evidence)
	}
	if !strings.Contains(evidence.HeaderText, "X-Alpha: first\n") || strings.Index(evidence.HeaderText, "X-Alpha") > strings.Index(evidence.HeaderText, "X-Zeta") {
		t.Fatalf("header text is not stable and complete: %q", evidence.HeaderText)
	}
}

func TestCollectHTTPEvidenceStopsAtRedirectLimit(t *testing.T) {
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests[request.URL.Path]++
		switch request.URL.Path {
		case "/start":
			http.Redirect(response, request, "/first", http.StatusFound)
		case "/first":
			http.Redirect(response, request, "/second", http.StatusFound)
		default:
			response.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	options := DefaultHTTPEvidenceOptions()
	options.MaxRedirects = 1
	evidence, err := CollectHTTPEvidence(context.Background(), server.URL+"/start", options)
	if err != nil {
		t.Fatalf("collect redirected evidence: %v", err)
	}
	if evidence.StatusCode != http.StatusFound || evidence.FinalURL != server.URL+"/first" || evidence.RedirectsFollowed != 1 {
		t.Fatalf("redirect result = %#v", evidence)
	}
	if requests["/start"] != 1 || requests["/first"] != 1 || requests["/second"] != 0 {
		t.Fatalf("redirect limit was not enforced: %#v", requests)
	}
}

func TestCollectHTTPEvidenceHonorsTimeoutAndRejectsInvalidTargets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()

	options := DefaultHTTPEvidenceOptions()
	options.Timeout = 20 * time.Millisecond
	if _, err := CollectHTTPEvidence(context.Background(), server.URL, options); err == nil {
		t.Fatal("timeout must fail collection")
	}
	if _, err := CollectHTTPEvidence(context.Background(), "ftp://example.test", DefaultHTTPEvidenceOptions()); err == nil {
		t.Fatal("non-HTTP target must be rejected")
	}
}
