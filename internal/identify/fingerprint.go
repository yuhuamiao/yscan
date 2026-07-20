package identify

import (
	"strings"

	"golandproject/yscan/internal/assist"
)

type FingerprintMatch struct {
	Product string
	Source  string
}

var matchFingerprint func(string) string

func SetFingerprintMatcher(matcher func(string) string) {
	matchFingerprint = matcher
}

func IdentifyFingerprint(banner string, port int) FingerprintMatch {
	if strings.TrimSpace(banner) == "" {
		return FingerprintMatch{}
	}

	if strings.Contains(banner, "HTTP/") {
		if server := assist.ExtractHeader(banner, "Server"); server != "" && matchFingerprint != nil {
			if product := normalizeFingerprintName(matchFingerprint(server)); product != "" {
				return FingerprintMatch{
					Product: product,
					Source:  "http_server_header",
				}
			}
		}
	}

	if matchFingerprint != nil {
		if product := normalizeFingerprintName(matchFingerprint(banner)); product != "" {
			return FingerprintMatch{
				Product: product,
				Source:  "banner_pattern",
			}
		}
	}

	if product := fallbackFingerprint(banner, port); product != "" {
		return FingerprintMatch{
			Product: product,
			Source:  "builtin_fallback",
		}
	}

	return FingerprintMatch{}
}

func normalizeFingerprintName(product string) string {
	product = strings.TrimSpace(strings.ToLower(product))
	if product == "" || product == "unknown" || product == "none_unknown" {
		return ""
	}
	return product
}

func fallbackFingerprint(banner string, port int) string {
	lower := strings.ToLower(banner)

	switch {
	case strings.Contains(lower, "nginx"):
		return "nginx"
	case strings.Contains(lower, "apache"):
		return "apache"
	case strings.Contains(lower, "microsoft-iis"):
		return "iis"
	case strings.Contains(lower, "openssh"):
		return "openssh"
	case strings.Contains(lower, "pure-ftpd"):
		return "pure-ftpd"
	case strings.Contains(lower, "redis_version"):
		return "redis"
	case strings.Contains(lower, "elasticsearch"):
		return "elasticsearch"
	case strings.Contains(lower, "jetty"):
		return "jetty"
	}

	switch port {
	case 6379:
		return "redis"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 27017:
		return "mongodb"
	}

	return ""
}
