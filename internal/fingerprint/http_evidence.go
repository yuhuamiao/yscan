package fingerprint

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

const (
	defaultHTTPTimeout           = 5 * time.Second
	defaultMaxHTTPBodyBytes      = int64(1 << 20)
	defaultMaxHTTPBodySummary    = 64 * 1024
	defaultMaxHTTPRedirects      = 3
	defaultMaxHTTPResponseHeader = int64(64 * 1024)
)

// HTTPEvidenceOptions constrains one HTTP evidence request. Zero values use
// the safe defaults returned by DefaultHTTPEvidenceOptions.
type HTTPEvidenceOptions struct {
	Timeout             time.Duration
	MaxBodyBytes        int64
	MaxBodySummaryBytes int
	MaxRedirects        int
	MaxHeaderBytes      int64
}

// DefaultHTTPEvidenceOptions returns the bounded defaults used by local
// fingerprint evidence collection.
func DefaultHTTPEvidenceOptions() HTTPEvidenceOptions {
	return HTTPEvidenceOptions{
		Timeout:             defaultHTTPTimeout,
		MaxBodyBytes:        defaultMaxHTTPBodyBytes,
		MaxBodySummaryBytes: defaultMaxHTTPBodySummary,
		MaxRedirects:        defaultMaxHTTPRedirects,
		MaxHeaderBytes:      defaultMaxHTTPResponseHeader,
	}
}

// HTTPEvidence is the bounded HTTP response data required by later matching
// tasks. BodySummary is a prefix of the captured response body, never an
// unbounded response copy. HeaderText has stable alphabetical header ordering
// for whole-header rules while Headers supports named-header rules.
type HTTPEvidence struct {
	URL               string      `json:"url"`
	FinalURL          string      `json:"final_url"`
	StatusCode        int         `json:"status_code"`
	Headers           http.Header `json:"headers"`
	HeaderText        string      `json:"header_text"`
	Title             string      `json:"title,omitempty"`
	BodySummary       string      `json:"body_summary"`
	BodyTruncated     bool        `json:"body_truncated"`
	SummaryTruncated  bool        `json:"summary_truncated"`
	RedirectsFollowed int         `json:"redirects_followed"`
}

// CollectHTTPEvidence fetches an HTTP or HTTPS URL with explicit timeout,
// response-size and redirect limits. HTTP status codes, including 4xx and 5xx,
// are valid evidence responses; transport and read failures return an error.
func CollectHTTPEvidence(ctx context.Context, target string, options HTTPEvidenceOptions) (HTTPEvidence, error) {
	parsedTarget, err := validateHTTPTarget(target)
	if err != nil {
		return HTTPEvidence{}, err
	}
	options, err = normalizeHTTPEvidenceOptions(options)
	if err != nil {
		return HTTPEvidence{}, err
	}

	redirectsFollowed := 0
	client := &http.Client{
		Timeout:   options.Timeout,
		Transport: httpTransportWithHeaderLimit(options.MaxHeaderBytes),
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) > options.MaxRedirects {
				return http.ErrUseLastResponse
			}
			redirectsFollowed = len(via)
			return nil
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedTarget.String(), nil)
	if err != nil {
		return HTTPEvidence{}, fmt.Errorf("create HTTP evidence request: %w", err)
	}
	request.Header.Set("User-Agent", "yscan-caasm/1.0")

	response, err := client.Do(request)
	if err != nil {
		return HTTPEvidence{}, fmt.Errorf("collect HTTP evidence from %s: %w", parsedTarget.Redacted(), err)
	}
	defer response.Body.Close()

	body, bodyTruncated, err := readBoundedHTTPBody(response.Body, options.MaxBodyBytes)
	if err != nil {
		return HTTPEvidence{}, fmt.Errorf("read HTTP evidence response from %s: %w", parsedTarget.Redacted(), err)
	}
	summary, summaryTruncated := summarizeHTTPBody(body, options.MaxBodySummaryBytes)
	return HTTPEvidence{
		URL:               parsedTarget.String(),
		FinalURL:          response.Request.URL.String(),
		StatusCode:        response.StatusCode,
		Headers:           response.Header.Clone(),
		HeaderText:        canonicalHTTPHeaders(response.Header),
		Title:             extractHTTPTitle(body),
		BodySummary:       summary,
		BodyTruncated:     bodyTruncated,
		SummaryTruncated:  summaryTruncated,
		RedirectsFollowed: redirectsFollowed,
	}, nil
}

func validateHTTPTarget(target string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(target))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("HTTP evidence target must be an absolute http or https URL")
	}
	return parsed, nil
}

func normalizeHTTPEvidenceOptions(options HTTPEvidenceOptions) (HTTPEvidenceOptions, error) {
	defaults := DefaultHTTPEvidenceOptions()
	if options.Timeout == 0 {
		options.Timeout = defaults.Timeout
	}
	if options.MaxBodyBytes == 0 {
		options.MaxBodyBytes = defaults.MaxBodyBytes
	}
	if options.MaxBodySummaryBytes == 0 {
		options.MaxBodySummaryBytes = defaults.MaxBodySummaryBytes
	}
	if options.MaxRedirects == 0 {
		options.MaxRedirects = defaults.MaxRedirects
	}
	if options.MaxHeaderBytes == 0 {
		options.MaxHeaderBytes = defaults.MaxHeaderBytes
	}
	if options.Timeout <= 0 || options.MaxBodyBytes <= 0 || options.MaxBodySummaryBytes <= 0 || options.MaxRedirects < 0 || options.MaxHeaderBytes <= 0 {
		return HTTPEvidenceOptions{}, errors.New("HTTP evidence limits must be positive")
	}
	if options.MaxBodyBytes == int64(^uint64(0)>>1) {
		return HTTPEvidenceOptions{}, errors.New("HTTP evidence max body bytes is too large")
	}
	return options, nil
}

func httpTransportWithHeaderLimit(maxHeaderBytes int64) http.RoundTripper {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = maxHeaderBytes
	return transport
}

func readBoundedHTTPBody(body io.Reader, maxBytes int64) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxBytes {
		return data[:maxBytes], true, nil
	}
	return data, false, nil
}

func summarizeHTTPBody(body []byte, maxBytes int) (string, bool) {
	truncated := len(body) > maxBytes
	if truncated {
		body = body[:maxBytes]
	}
	return strings.ToValidUTF8(string(body), "\uFFFD"), truncated
}

func canonicalHTTPHeaders(headers http.Header) string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var builder strings.Builder
	for _, key := range keys {
		values := append([]string(nil), headers.Values(key)...)
		sort.Strings(values)
		for _, value := range values {
			fmt.Fprintf(&builder, "%s: %s\n", key, value)
		}
	}
	return builder.String()
}

func extractHTTPTitle(body []byte) string {
	document, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	return strings.Join(strings.Fields(document.Find("title").First().Text()), " ")
}
