package domain

import (
	"context"
	"net"
	"strings"
	"time"
)

const (
	DNSModeHybrid   = "hybrid"
	DNSModeInternal = "internal"
	DNSModeExternal = "external"
)

type ResolvePolicy struct {
	Mode      string
	DenyCIDRs []string
}

type ipFilter struct {
	deny []*net.IPNet
}

func NormalizeResolvePolicy(policy ResolvePolicy) ResolvePolicy {
	mode := strings.ToLower(strings.TrimSpace(policy.Mode))
	switch mode {
	case DNSModeInternal, DNSModeExternal, DNSModeHybrid:
	default:
		mode = DNSModeHybrid
	}

	if len(policy.DenyCIDRs) == 0 && mode == DNSModeExternal {
		policy.DenyCIDRs = defaultExternalDenyCIDRs()
	}

	return ResolvePolicy{
		Mode:      mode,
		DenyCIDRs: uniqueStrings(policy.DenyCIDRs),
	}
}

func ResolveSubdomainIPsWithPolicy(ctx context.Context, name string, policy ResolvePolicy) []net.IP {
	policy = NormalizeResolvePolicy(policy)
	filter := newIPFilter(policy.DenyCIDRs)

	seen := make(map[string]struct{})
	var out []net.IP

	for _, r := range resolverChain {
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		ips, err := r.LookupIP(lookupCtx, "ip4", name)
		cancel()

		if err != nil || len(ips) == 0 {
			lookupCtx2, cancel2 := context.WithTimeout(ctx, 2*time.Second)
			ips, err = r.LookupIP(lookupCtx2, "ip", name)
			cancel2()
			if err != nil || len(ips) == 0 {
				continue
			}
		}

		for _, ip := range ips {
			if ip == nil {
				continue
			}
			if filter.Blocks(ip) {
				continue
			}
			key := ip.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, ip)
		}
	}

	return out
}

func ResolveSubdomainIPs(ctx context.Context, name string) []net.IP {
	return ResolveSubdomainIPsWithPolicy(ctx, name, ResolvePolicy{Mode: DNSModeHybrid})
}

func resolveCNAME(ctx context.Context, name string) string {
	queryName := normalizeDNSName(name)
	for _, r := range resolverChain {
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		cname, err := r.LookupCNAME(lookupCtx, queryName)
		cancel()
		if err != nil {
			continue
		}

		normalized := normalizeDNSName(cname)
		if normalized == "" || normalized == queryName {
			continue
		}
		return normalized
	}
	return ""
}

func dnsResolver(server string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", server)
		},
	}
}

var resolverChain = []*net.Resolver{
	dnsResolver("223.5.5.5:53"),
	dnsResolver("119.29.29.29:53"),
	dnsResolver("1.1.1.1:53"),
	net.DefaultResolver,
}

func resolveA(ctx context.Context, name string) []net.IP {
	return ResolveSubdomainIPsWithPolicy(ctx, name, ResolvePolicy{Mode: DNSModeHybrid})
}

func newIPFilter(cidrs []string) ipFilter {
	filter := ipFilter{}
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil || network == nil {
			continue
		}
		filter.deny = append(filter.deny, network)
	}
	return filter
}

func (f ipFilter) Blocks(ip net.IP) bool {
	for _, network := range f.deny {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func defaultExternalDenyCIDRs() []string {
	return []string{
		"10.0.0.0/8",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"100.64.0.0/10",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeDNSName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	name = strings.TrimSuffix(name, ".")
	return name
}
