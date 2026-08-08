package fingerprint

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxNmapProbeWrite = 4 << 10
	maxNmapProbeRead  = 16 << 10
)

// NmapTCPProbe is a read-only, bounded projection of one upstream TCP Probe.
// Raw source rules remain in SQLite; this value is never accepted from a scan target.
type NmapTCPProbe struct {
	Name     string
	Payload  []byte
	Timeout  time.Duration
	Ports    []int
	SSLPorts []int
	Rarity   int
	Fallback []string
	Order    int
	TLS      bool
	Matches  []NmapProbeMatch
}

type nmapProbeProjection struct {
	Mode       string   `json:"mode"`
	Name       string   `json:"name"`
	Payload    []byte   `json:"payload,omitempty"`
	Ports      []int    `json:"ports,omitempty"`
	SSLPorts   []int    `json:"ssl_ports,omitempty"`
	Rarity     int      `json:"rarity,omitempty"`
	Fallback   []string `json:"fallback,omitempty"`
	TimeoutMS  int      `json:"timeout_ms,omitempty"`
	Order      int      `json:"order,omitempty"`
	SideEffect string   `json:"side_effect,omitempty"`
}

var readOnlyNmapProbePayloads = map[string]string{
	"GenericLines":           "\r\n\r\n",
	"GetRequest":             "GET / HTTP/1.0\r\n\r\n",
	"HTTPOptions":            "OPTIONS / HTTP/1.0\r\n\r\n",
	"RTSPRequest":            "OPTIONS / RTSP/1.0\r\n\r\n",
	"Hello":                  "EHLO\r\n",
	"Help":                   "HELP\r\n",
	"NessusTPv12":            "< NTP/1.2 >\n",
	"NessusTPv11":            "< NTP/1.1 >\n",
	"NessusTPv10":            "< NTP/1.0 >\n",
	"Memcache":               "stats\r\n",
	"SqueezeCenter_CLI":      "serverstatus\r\n",
	"teamspeak-tcpquery-ver": "ver\r\n",
	"docker":                 "GET /version HTTP/1.1\r\n\r\n",
	"VersionRequest":         "VERSION",
	"LSCP":                   "GET SERVER INFO\r\n",
	"rotctl":                 "get_info\n",
}

type NmapProbeMatch struct {
	Service string
	Soft    bool
	Pattern string
	Flags   string
	Product string
	Version string
	CPE     string
}

func ParseNmapTCPProbes(raw []byte) ([]NmapTCPProbe, error) {
	lines := strings.Split(string(raw), "\n")
	probes := make([]NmapTCPProbe, 0)
	var current *NmapTCPProbe
	order := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Probe TCP ") {
			if current != nil {
				probes = append(probes, *current)
			}
			name, payload, ok := parseNmapProbeHeader(line)
			if !ok {
				return nil, errors.New("invalid Nmap TCP probe header")
			}
			current = &NmapTCPProbe{Name: name, Payload: payload, Timeout: 4 * time.Second, Rarity: 9, Order: order}
			order++
			continue
		}
		if strings.HasPrefix(line, "Probe ") {
			if current != nil {
				probes = append(probes, *current)
				current = nil
			}
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(line, "totalwaitms ") {
			if value, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "totalwaitms "))); err == nil && value > 0 {
				current.Timeout = minDuration(time.Duration(value)*time.Millisecond, 4*time.Second)
			}
			continue
		}
		if strings.HasPrefix(line, "ports ") || strings.HasPrefix(line, "sslports ") {
			ports, err := parseNmapPortList(strings.TrimSpace(line[strings.IndexByte(line, ' ')+1:]))
			if err != nil {
				return nil, err
			}
			if strings.HasPrefix(line, "sslports ") {
				current.SSLPorts = ports
			} else {
				current.Ports = ports
			}
			continue
		}
		if strings.HasPrefix(line, "rarity ") {
			if value, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "rarity "))); err == nil && value >= 1 && value <= 9 {
				current.Rarity = value
			}
			continue
		}
		if strings.HasPrefix(line, "fallback ") {
			current.Fallback = splitNmapFallback(strings.TrimSpace(strings.TrimPrefix(line, "fallback ")))
			continue
		}
		if match, ok := parseNmapMatch(line); ok {
			current.Matches = append(current.Matches, match)
		}
	}
	if current != nil {
		probes = append(probes, *current)
	}
	return probes, nil
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func parseNmapPortList(value string) ([]int, error) {
	seen := make(map[int]struct{})
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		bounds := strings.SplitN(part, "-", 2)
		start, err := strconv.Atoi(bounds[0])
		if err != nil || start < 1 || start > 65535 {
			return nil, errors.New("invalid Nmap probe port list")
		}
		end := start
		if len(bounds) == 2 {
			end, err = strconv.Atoi(bounds[1])
			if err != nil || end < start || end > 65535 {
				return nil, errors.New("invalid Nmap probe port range")
			}
		}
		for port := start; port <= end; port++ {
			seen[port] = struct{}{}
		}
	}
	ports := make([]int, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

func splitNmapFallback(value string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result
}

func isReadOnlyNmapProbe(probe NmapTCPProbe) bool {
	expected, allowed := readOnlyNmapProbePayloads[probe.Name]
	return allowed && string(probe.Payload) == expected && len(probe.Payload) <= maxNmapProbeWrite && (len(probe.Ports) > 0 || len(probe.SSLPorts) > 0)
}

func nmapProbeProjectionFor(probe NmapTCPProbe, mode string) nmapProbeProjection {
	return nmapProbeProjection{
		Mode: mode, Name: probe.Name, Payload: append([]byte(nil), probe.Payload...), Ports: append([]int(nil), probe.Ports...),
		SSLPorts: append([]int(nil), probe.SSLPorts...), Rarity: probe.Rarity, Fallback: append([]string(nil), probe.Fallback...),
		TimeoutMS: int(minDuration(probe.Timeout, 4*time.Second) / time.Millisecond), Order: probe.Order, SideEffect: "read_only",
	}
}

func (projection nmapProbeProjection) runtimeProbe(port int, service string) (NmapTCPProbe, bool) {
	plain := containsNmapPort(projection.Ports, port)
	secure := containsNmapPort(projection.SSLPorts, port)
	if !plain && !secure {
		return NmapTCPProbe{}, false
	}
	useTLS := secure && (!plain || strings.EqualFold(service, "https") || strings.EqualFold(service, "tls"))
	return NmapTCPProbe{
		Name: projection.Name, Payload: append([]byte(nil), projection.Payload...), Timeout: time.Duration(projection.TimeoutMS) * time.Millisecond,
		Ports: append([]int(nil), projection.Ports...), SSLPorts: append([]int(nil), projection.SSLPorts...), Rarity: projection.Rarity,
		Fallback: append([]string(nil), projection.Fallback...), Order: projection.Order, TLS: useTLS,
	}, true
}

func containsNmapPort(ports []int, port int) bool {
	index := sort.SearchInts(ports, port)
	return index < len(ports) && ports[index] == port
}

func parseNmapProbeHeader(line string) (string, []byte, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return "", nil, false
	}
	encoded := strings.TrimPrefix(line[strings.Index(line, fields[2])+len(fields[2]):], " ")
	if !strings.HasPrefix(encoded, "q|") {
		return "", nil, false
	}
	payload := strings.TrimSuffix(strings.TrimPrefix(encoded, "q|"), "|")
	decoded, err := decodeNmapProbePayload(payload)
	if err != nil || len(decoded) > maxNmapProbeWrite {
		return "", nil, false
	}
	return fields[2], decoded, true
}

func decodeNmapProbePayload(value string) ([]byte, error) {
	result := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			result = append(result, value[index])
			continue
		}
		index++
		if index >= len(value) {
			return nil, errors.New("truncated Nmap probe payload escape")
		}
		switch value[index] {
		case 'a':
			result = append(result, '\a')
		case 'b':
			result = append(result, '\b')
		case 'f':
			result = append(result, '\f')
		case 'n':
			result = append(result, '\n')
		case 'r':
			result = append(result, '\r')
		case 't':
			result = append(result, '\t')
		case 'v':
			result = append(result, '\v')
		case 'x':
			if index+2 >= len(value) {
				return nil, errors.New("truncated Nmap hexadecimal payload escape")
			}
			decoded, err := strconv.ParseUint(value[index+1:index+3], 16, 8)
			if err != nil {
				return nil, errors.New("invalid Nmap hexadecimal payload escape")
			}
			result = append(result, byte(decoded))
			index += 2
		case '0', '1', '2', '3', '4', '5', '6', '7':
			end := index + 1
			for end < len(value) && end < index+3 && value[end] >= '0' && value[end] <= '7' {
				end++
			}
			decoded, err := strconv.ParseUint(value[index:end], 8, 8)
			if err != nil {
				return nil, errors.New("invalid Nmap octal payload escape")
			}
			result = append(result, byte(decoded))
			index = end - 1
		case '\\', '|', '"':
			result = append(result, value[index])
		default:
			return nil, errors.New("unsupported Nmap probe payload escape")
		}
	}
	return result, nil
}

func parseNmapMatch(line string) (NmapProbeMatch, bool) {
	soft := strings.HasPrefix(line, "softmatch ")
	if !soft && !strings.HasPrefix(line, "match ") {
		return NmapProbeMatch{}, false
	}
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return NmapProbeMatch{}, false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, fields[0]+" "+fields[1]))
	if !strings.HasPrefix(rest, "m|") {
		return NmapProbeMatch{}, false
	}
	pattern, suffix, ok := nmapDelimited(rest[2:])
	if !ok {
		return NmapProbeMatch{}, false
	}
	flags, suffix := nmapRegexFlags(suffix)
	return NmapProbeMatch{
		Service: fields[1],
		Soft:    soft,
		Pattern: pattern,
		Flags:   flags,
		Product: nmapMetadataValue(suffix, "p"),
		Version: nmapMetadataValue(suffix, "v"),
		CPE:     nmapMetadataValue(suffix, "cpe:"),
	}, true
}

func nmapRegexFlags(suffix string) (string, string) {
	index := 0
	for index < len(suffix) && (suffix[index] == 'i' || suffix[index] == 's') {
		index++
	}
	return suffix[:index], strings.TrimSpace(suffix[index:])
}

func nmapGoPattern(pattern, flags string) (string, bool) {
	seen := map[rune]bool{}
	for _, flag := range flags {
		if flag != 'i' && flag != 's' {
			return "", false
		}
		seen[flag] = true
	}
	prefix := ""
	if seen['i'] {
		prefix += "i"
	}
	if seen['s'] {
		prefix += "s"
	}
	if prefix != "" {
		pattern = "(?" + prefix + ")" + pattern
	}
	return pattern, true
}

func nmapDelimited(input string) (string, string, bool) {
	escaped := false
	for index, runeValue := range input {
		if escaped {
			escaped = false
			continue
		}
		if runeValue == '\\' {
			escaped = true
			continue
		}
		if runeValue == '|' {
			return input[:index], input[index+1:], true
		}
	}
	return "", "", false
}

func nmapMetadataValue(suffix, key string) string {
	prefix := key + "/"
	start := -1
	for offset := 0; offset < len(suffix); {
		index := strings.Index(suffix[offset:], prefix)
		if index < 0 {
			return ""
		}
		index += offset
		if index == 0 || suffix[index-1] == ' ' || suffix[index-1] == '\t' {
			start = index + len(prefix)
			break
		}
		offset = index + len(prefix)
	}
	if start < 0 {
		return ""
	}
	escaped := false
	for index := start; index < len(suffix); index++ {
		if escaped {
			escaped = false
			continue
		}
		if suffix[index] == '\\' {
			escaped = true
			continue
		}
		if suffix[index] == '/' {
			value := strings.ReplaceAll(suffix[start:index], `\/`, `/`)
			if key == "cpe:" {
				return "cpe:/" + value
			}
			return value
		}
	}
	return ""
}

func ExecuteNmapTCPProbe(ctx context.Context, ip string, port int, probe NmapTCPProbe) ([]byte, error) {
	if net.ParseIP(ip) == nil || port < 1 || port > 65535 || len(probe.Payload) > maxNmapProbeWrite {
		return nil, errors.New("invalid Nmap TCP probe endpoint")
	}
	if probe.Timeout <= 0 || probe.Timeout > 4*time.Second {
		probe.Timeout = 4 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, probe.Timeout)
	defer cancel()
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	var conn net.Conn
	var err error
	if probe.TLS {
		conn, err = (&tls.Dialer{NetDialer: &net.Dialer{}, Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}}).DialContext(ctx, "tcp", address)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if len(probe.Payload) > 0 {
		if _, err := conn.Write(probe.Payload); err != nil {
			return nil, err
		}
	}
	deadline := time.Now().Add(probe.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetReadDeadline(deadline)
	response, err := io.ReadAll(io.LimitReader(conn, maxNmapProbeRead))
	if len(response) == 0 && err != nil {
		return nil, err
	}
	return response, nil
}

func MatchNmapTCPProbe(response []byte, matches []NmapProbeMatch) []NmapProbeMatch {
	found := make([]NmapProbeMatch, 0)
	for _, match := range matches {
		pattern, ok := nmapGoPattern(match.Pattern, match.Flags)
		if !ok {
			continue
		}
		if re, err := regexp.Compile(pattern); err == nil && re.Match(response) {
			found = append(found, match)
		}
	}
	return found
}
