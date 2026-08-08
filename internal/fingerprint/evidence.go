package fingerprint

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PuerkitoBio/goquery"
)

const (
	maxHTTPHeaderBytes = 32 << 10
	maxHTTPBodyBytes   = 64 << 10
)

var ErrNotWebService = errors.New("service is not eligible for web evidence collection")

// NewBannerEvidence defines the same captured-value contract as HTTP evidence:
// length and SHA-256 describe only the retained bytes and Truncated means at
// least one additional byte was observed beyond the hard limit.
func NewBannerEvidence(banner string, truncated bool) Evidence {
	sum := sha256.Sum256([]byte(banner))
	return Evidence{
		Protocol: "tcp", Banner: banner, Body: banner,
		BannerTruncated: truncated, BannerCapturedLength: len(banner),
		BannerCapturedSHA256: hex.EncodeToString(sum[:]),
	}
}

// WebEvidenceOptions makes the network boundary explicit. AllowedPorts is the
// port policy for the current run, not a rule supplied destination list.
type WebEvidenceOptions struct {
	AllowedPorts map[int]struct{}
	Timeout      time.Duration
}

// CollectedEvidence is in-memory matching input plus a safe persistence
// summary. Raw headers and body never leave the current scan process.
type CollectedEvidence struct {
	Evidence Evidence
	Protocol string
	Summary  string
}

// CollectWebEvidence performs the fixed read-only web sequence for an already
// discovered endpoint. HTTP/HTTPS services receive one request; unknown gets
// HTTPS first and plain HTTP only when HTTPS did not return a response.
func CollectWebEvidence(ctx context.Context, ip string, port int, service string, options WebEvidenceOptions) (CollectedEvidence, error) {
	if net.ParseIP(ip) == nil || port < 1 || port > 65535 {
		return CollectedEvidence{}, errors.New("invalid web evidence endpoint")
	}
	if options.Timeout <= 0 {
		options.Timeout = 4 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	if len(options.AllowedPorts) == 0 {
		options.AllowedPorts = map[int]struct{}{port: {}}
	}
	service = strings.ToLower(strings.TrimSpace(service))
	switch service {
	case "https":
		return collectHTTP(ctx, "https", ip, port, options)
	case "http":
		return collectHTTP(ctx, "http", ip, port, options)
	case "unknown", "none_unknown", "", "http-unknown":
		result, err := collectHTTP(ctx, "https", ip, port, options)
		if err == nil {
			return result, nil
		}
		return collectHTTP(ctx, "http", ip, port, options)
	default:
		return CollectedEvidence{}, ErrNotWebService
	}
}

func collectHTTP(ctx context.Context, scheme, ip string, port int, options WebEvidenceOptions) (CollectedEvidence, error) {
	dialer := &net.Dialer{Timeout: options.Timeout}
	transport := &http.Transport{
		DialContext:            dialer.DialContext,
		TLSHandshakeTimeout:    options.Timeout,
		MaxResponseHeaderBytes: maxHTTPHeaderBytes,
		TLSClientConfig:        &tls.Config{InsecureSkipVerify: true}, // internal endpoints commonly use private certificates.
	}
	client := &http.Client{Transport: transport}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > 1 || !sameAuthorizedEndpoint(request.URL, ip, port, options.AllowedPorts) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	endpoint := (&url.URL{Scheme: scheme, Host: net.JoinHostPort(ip, strconv.Itoa(port)), Path: "/"}).String()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return CollectedEvidence{}, err
	}
	request.Header.Set("User-Agent", "CAASM-fingerprint/2")
	response, err := client.Do(request)
	if err != nil {
		return CollectedEvidence{}, err
	}
	defer response.Body.Close()

	headers, headerLength, headerTruncated, headerHash := cappedHeaders(response.Header)
	body, bodyLength, bodyTruncated, bodyHash, binary, err := cappedBody(response.Body)
	if err != nil {
		return CollectedEvidence{}, err
	}
	if binary || !utf8.Valid(body) {
		body = nil
	}
	bodyText := string(body)
	evidence := Evidence{
		Headers: headers, Meta: htmlMetadata(bodyText), Cookies: responseCookies(response), Body: bodyText, Title: htmlTitle(bodyText), URL: response.Request.URL.String(), StatusCode: response.StatusCode,
		HeaderTruncated: headerTruncated, BodyTruncated: bodyTruncated,
		HeaderCapturedLength: headerLength, HeaderCapturedSHA256: headerHash,
		BodyCapturedLength: bodyLength, BodyCapturedSHA256: bodyHash,
	}
	faviconHashes, faviconErr := collectFavicon(ctx, client, response.Request.URL)
	if faviconErr == nil {
		evidence.FaviconMD5 = faviconHashes.MD5
		evidence.FaviconMMH3 = faviconHashes.MMH3
		evidence.FaviconSHA256 = faviconHashes.SHA256
		evidence.FaviconHash = strings.Join(faviconHashes.values(), "\n")
	}
	protocol := strings.ToLower(response.Request.URL.Scheme)
	summary := fmt.Sprintf("http status=%d protocol=%s headers=%d%s header_sha256=%s body=%d%s body_sha256=%s", response.StatusCode, protocol, headerLength, truncationSuffix(headerTruncated), headerHash, bodyLength, truncationSuffix(bodyTruncated), bodyHash)
	if faviconHashes.SHA256 != "" {
		summary += " favicon_sha256=" + faviconHashes.SHA256
	}
	return CollectedEvidence{Evidence: evidence, Protocol: protocol, Summary: summary}, nil
}

func responseCookies(response *http.Response) map[string]string {
	values := make(map[string]string)
	if response == nil {
		return values
	}
	for _, cookie := range response.Cookies() {
		name := strings.ToLower(strings.TrimSpace(cookie.Name))
		if name == "" {
			continue
		}
		if existing := values[name]; existing != "" {
			values[name] = existing + "\n" + cookie.Value
		} else {
			values[name] = cookie.Value
		}
	}
	return values
}

type faviconHashes struct {
	MD5    string
	MMH3   string
	SHA256 string
}

func (hashes faviconHashes) values() []string {
	return []string{hashes.MD5, hashes.MMH3, hashes.SHA256}
}

func collectFavicon(ctx context.Context, client *http.Client, base *url.URL) (faviconHashes, error) {
	if base == nil {
		return faviconHashes{}, errors.New("missing response URL")
	}
	faviconURL := base.ResolveReference(&url.URL{Path: "/favicon.ico"})
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, faviconURL.String(), nil)
	if err != nil {
		return faviconHashes{}, err
	}
	request.Header.Set("User-Agent", "CAASM-fingerprint/2")
	response, err := client.Do(request)
	if err != nil {
		return faviconHashes{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return faviconHashes{}, fmt.Errorf("favicon status %d", response.StatusCode)
	}
	data, _, _, hash, _, err := cappedBody(response.Body)
	if err != nil {
		return faviconHashes{}, err
	}
	legacy := md5.Sum(data)
	// Raw hashes remain in memory. Persistence keeps only the SHA-256 summary.
	return faviconHashes{MD5: hex.EncodeToString(legacy[:]), MMH3: faviconMMH3(data), SHA256: hash}, nil
}

// faviconMMH3 follows the newline-wrapped Base64 convention used by Shodan,
// httpx, EHole, and FingerprintHub favicon intelligence.
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

func sameAuthorizedEndpoint(target *url.URL, ip string, initialPort int, allowed map[int]struct{}) bool {
	host := target.Hostname()
	if host != ip {
		return false
	}
	port := 0
	if text := target.Port(); text != "" {
		parsed, err := strconv.Atoi(text)
		if err != nil || parsed < 1 || parsed > 65535 {
			return false
		}
		port = parsed
	} else {
		switch strings.ToLower(target.Scheme) {
		case "http":
			port = 80
		case "https":
			port = 443
		default:
			return false
		}
	}
	if port != initialPort {
		return false
	}
	_, ok := allowed[port]
	return ok
}

func cappedHeaders(headers http.Header) (map[string]string, int, bool, string) {
	result := make(map[string]string, len(headers))
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var captured strings.Builder
	length := 0
	truncated := false
	for _, key := range keys {
		values := headers[key]
		value := strings.Join(values, ", ")
		line := key + ": " + value + "\r\n"
		lineLength := len(line)
		if length+lineLength > maxHTTPHeaderBytes {
			truncated = true
			continue
		}
		length += lineLength
		captured.WriteString(line)
		result[key] = value
	}
	hash := sha256.Sum256([]byte(captured.String()))
	return result, length, truncated, hex.EncodeToString(hash[:])
}

func cappedBody(body io.Reader) ([]byte, int, bool, string, bool, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxHTTPBodyBytes+1))
	if err != nil {
		return nil, 0, false, "", false, err
	}
	truncated := len(data) > maxHTTPBodyBytes
	if truncated {
		data = data[:maxHTTPBodyBytes]
	}
	hash := sha256.Sum256(data)
	binary := !utf8.Valid(data)
	return data, len(data), truncated, hex.EncodeToString(hash[:]), binary, nil
}

func htmlTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	start = strings.Index(lower[start:], ">") + start + 1
	if start <= 0 {
		return ""
	}
	end := strings.Index(strings.ToLower(body[start:]), "</title>")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}

func htmlMetadata(body string) map[string]string {
	metadata := make(map[string]string)
	document, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		return metadata
	}
	document.Find("meta").Each(func(_ int, selection *goquery.Selection) {
		key, exists := selection.Attr("name")
		if !exists {
			key, exists = selection.Attr("property")
		}
		content, contentExists := selection.Attr("content")
		key = strings.ToLower(strings.TrimSpace(key))
		if !exists || !contentExists || key == "" {
			return
		}
		if previous := metadata[key]; previous != "" {
			metadata[key] = previous + "\n" + content
		} else {
			metadata[key] = content
		}
	})
	return metadata
}

func truncationSuffix(truncated bool) string {
	if truncated {
		return " truncated"
	}
	return ""
}
