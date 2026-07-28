package fingerprint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var faviconPNG = []byte{
	0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n',
	0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R',
}

func TestCollectFaviconEvidenceProducesReproducibleHashes(t *testing.T) {
	requestedPath := ""
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requestedPath = request.URL.Path
		response.Header().Set("Content-Type", "image/png")
		_, _ = response.Write(faviconPNG)
	}))
	defer server.Close()

	first, err := CollectFaviconEvidence(context.Background(), server.URL+"/console", DefaultHTTPEvidenceOptions())
	if err != nil {
		t.Fatalf("collect favicon: %v", err)
	}
	second, err := CollectFaviconEvidence(context.Background(), server.URL, DefaultHTTPEvidenceOptions())
	if err != nil {
		t.Fatalf("collect favicon again: %v", err)
	}
	if requestedPath != "/favicon.ico" || first != second || first.Status != FaviconAvailable {
		t.Fatalf("favicon evidence is not stable: first=%#v second=%#v path=%q", first, second, requestedPath)
	}
	if first.MD5 != "7cddabe5df64daaa6924a5613dd2150a" || first.MMH3 != "628805695" || first.SHA256 != "02a3e298f1533f62558c58e4c70edcab9af5a50d62d925fd5390942020fb0fb8" {
		t.Fatalf("unexpected favicon hash vector: %#v", first)
	}
}

func TestCollectFaviconEvidenceSafelyDegrades(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		options func(HTTPEvidenceOptions) HTTPEvidenceOptions
		want    FaviconStatus
	}{
		{
			name: "not found",
			handler: func(response http.ResponseWriter, request *http.Request) {
				response.WriteHeader(http.StatusNotFound)
			},
			options: func(options HTTPEvidenceOptions) HTTPEvidenceOptions { return options },
			want:    FaviconNotFound,
		},
		{
			name: "non image body",
			handler: func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", "text/html")
				_, _ = response.Write([]byte("<html>not an icon</html>"))
			},
			options: func(options HTTPEvidenceOptions) HTTPEvidenceOptions { return options },
			want:    FaviconNotImage,
		},
		{
			name: "timeout",
			handler: func(response http.ResponseWriter, request *http.Request) {
				select {
				case <-request.Context().Done():
				case <-time.After(time.Second):
				}
			},
			options: func(options HTTPEvidenceOptions) HTTPEvidenceOptions {
				options.Timeout = 20 * time.Millisecond
				return options
			},
			want: FaviconTimeout,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(test.handler))
			defer server.Close()
			evidence, err := CollectFaviconEvidence(context.Background(), server.URL, test.options(DefaultHTTPEvidenceOptions()))
			if err != nil {
				t.Fatalf("collect favicon: %v", err)
			}
			if evidence.Status != test.want || evidence.MD5 != "" || evidence.MMH3 != "" || evidence.SHA256 != "" {
				t.Fatalf("favicon degradation = %#v, want status %q", evidence, test.want)
			}
		})
	}
}
