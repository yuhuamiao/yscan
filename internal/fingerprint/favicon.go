package fingerprint

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// FaviconStatus describes a non-fatal favicon collection outcome. Only
// FaviconAvailable contains hashes; all other values leave a scan running.
type FaviconStatus string

const (
	FaviconAvailable    FaviconStatus = "available"
	FaviconNotFound     FaviconStatus = "not_found"
	FaviconHTTPError    FaviconStatus = "http_error"
	FaviconTimeout      FaviconStatus = "timeout"
	FaviconUnavailable  FaviconStatus = "unavailable"
	FaviconNotImage     FaviconStatus = "not_image"
	FaviconBodyTooLarge FaviconStatus = "body_too_large"
)

// FaviconEvidence contains reproducible hashes for one bounded favicon
// response. MMH3 follows the newline-wrapped Base64 convention used by
// ProjectDiscovery httpx and common favicon intelligence datasets.
type FaviconEvidence struct {
	URL         string        `json:"url"`
	FinalURL    string        `json:"final_url,omitempty"`
	StatusCode  int           `json:"status_code,omitempty"`
	ContentType string        `json:"content_type,omitempty"`
	Status      FaviconStatus `json:"status"`
	MD5         string        `json:"md5,omitempty"`
	MMH3        string        `json:"mmh3,omitempty"`
	SHA256      string        `json:"sha256,omitempty"`
}

// CollectFaviconEvidence fetches the standard /favicon.ico endpoint for an
// HTTP(S) target. Network and response failures become non-fatal evidence
// states so callers can continue a host scan; invalid targets and invalid
// collection limits still return errors.
func CollectFaviconEvidence(ctx context.Context, target string, options HTTPEvidenceOptions) (FaviconEvidence, error) {
	faviconURL, err := resolveFaviconURL(target)
	if err != nil {
		return FaviconEvidence{}, err
	}
	options, err = normalizeHTTPEvidenceOptions(options)
	if err != nil {
		return FaviconEvidence{}, err
	}
	if ctx == nil {
		return FaviconEvidence{}, errors.New("favicon collection context is required")
	}

	response, err := collectFaviconResponse(ctx, faviconURL, options)
	if err != nil {
		return FaviconEvidence{URL: faviconURL.String(), Status: faviconFailureStatus(ctx, err)}, nil
	}
	evidence := FaviconEvidence{
		URL:         faviconURL.String(),
		FinalURL:    response.finalURL,
		StatusCode:  response.statusCode,
		ContentType: mediaType(response.headers.Get("Content-Type")),
	}
	if evidence.StatusCode == http.StatusNotFound {
		evidence.Status = FaviconNotFound
		return evidence, nil
	}
	if evidence.StatusCode < http.StatusOK || evidence.StatusCode >= http.StatusMultipleChoices {
		evidence.Status = FaviconHTTPError
		return evidence, nil
	}
	if response.bodyTruncated {
		evidence.Status = FaviconBodyTooLarge
		return evidence, nil
	}
	if !isFaviconImage(response.body) {
		evidence.Status = FaviconNotImage
		return evidence, nil
	}

	evidence.Status = FaviconAvailable
	md5Sum := md5.Sum(response.body)
	sha256Sum := sha256.Sum256(response.body)
	evidence.MD5 = hex.EncodeToString(md5Sum[:])
	evidence.SHA256 = hex.EncodeToString(sha256Sum[:])
	evidence.MMH3 = faviconMMH3(response.body)
	return evidence, nil
}

func resolveFaviconURL(target string) (*url.URL, error) {
	parsed, err := validateHTTPTarget(target)
	if err != nil {
		return nil, err
	}
	return &url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: "/favicon.ico"}, nil
}

func collectFaviconResponse(ctx context.Context, target *url.URL, options HTTPEvidenceOptions) (faviconHTTPResponse, error) {
	client := &http.Client{
		Timeout:   options.Timeout,
		Transport: httpTransportWithHeaderLimit(options.MaxHeaderBytes),
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) > options.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return faviconHTTPResponse{}, fmt.Errorf("create favicon request: %w", err)
	}
	request.Header.Set("User-Agent", "yscan-caasm/1.0")
	response, err := client.Do(request)
	if err != nil {
		return faviconHTTPResponse{}, err
	}
	defer response.Body.Close()
	body, bodyTruncated, err := readBoundedHTTPBody(response.Body, options.MaxBodyBytes)
	if err != nil {
		return faviconHTTPResponse{}, err
	}
	return faviconHTTPResponse{
		finalURL:      response.Request.URL.String(),
		statusCode:    response.StatusCode,
		headers:       response.Header.Clone(),
		body:          body,
		bodyTruncated: bodyTruncated,
	}, nil
}

type faviconHTTPResponse struct {
	finalURL      string
	statusCode    int
	headers       http.Header
	body          []byte
	bodyTruncated bool
}

func faviconFailureStatus(ctx context.Context, err error) FaviconStatus {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return FaviconTimeout
	}
	return FaviconUnavailable
}

func mediaType(value string) string {
	parsed, _, err := mime.ParseMediaType(value)
	if err == nil {
		return strings.ToLower(parsed)
	}
	return strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
}

func isFaviconImage(data []byte) bool {
	return strings.HasPrefix(http.DetectContentType(data), "image/")
}

func faviconMMH3(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var builder strings.Builder
	builder.Grow(len(encoded) + len(encoded)/76 + 1)
	for len(encoded) > 76 {
		builder.WriteString(encoded[:76])
		builder.WriteByte('\n')
		encoded = encoded[76:]
	}
	builder.WriteString(encoded)
	builder.WriteByte('\n')
	return strconv.FormatInt(int64(int32(murmur3Sum32([]byte(builder.String())))), 10)
}

// murmur3Sum32 is the little-endian MurmurHash3 x86-32 algorithm with seed
// zero. It deliberately avoids unsafe pointer arithmetic so -race/checkptr
// remains supported on current Go releases.
func murmur3Sum32(data []byte) uint32 {
	const (
		c1 = uint32(0xcc9e2d51)
		c2 = uint32(0x1b873593)
	)

	hash := uint32(0)
	length := len(data)
	for len(data) >= 4 {
		block := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
		block *= c1
		block = block<<15 | block>>17
		block *= c2
		hash ^= block
		hash = hash<<13 | hash>>19
		hash = hash*5 + 0xe6546b64
		data = data[4:]
	}

	var tail uint32
	switch len(data) {
	case 3:
		tail ^= uint32(data[2]) << 16
		fallthrough
	case 2:
		tail ^= uint32(data[1]) << 8
		fallthrough
	case 1:
		tail ^= uint32(data[0])
		tail *= c1
		tail = tail<<15 | tail>>17
		tail *= c2
		hash ^= tail
	}

	hash ^= uint32(length)
	hash ^= hash >> 16
	hash *= 0x85ebca6b
	hash ^= hash >> 13
	hash *= 0xc2b2ae35
	hash ^= hash >> 16
	return hash
}
