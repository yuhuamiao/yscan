package domain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type wildcardProfile struct {
	ipSignatures map[string]struct{}
	cnameTargets map[string]struct{}
}

type wildcardSample struct {
	ipSignature string
	cnameTarget string
}

func detectWildcardProfile(ctx context.Context, domain string, samples int) wildcardProfile {
	if samples <= 0 {
		samples = 3
	}

	resultsCh := make(chan wildcardSample, samples)
	var wg sync.WaitGroup

	for i := 0; i < samples; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			hostname := randomWildcardHostname(domain)
			ipCtx, cancelIP := context.WithTimeout(ctx, 4*time.Second)
			ips := resolveA(ipCtx, hostname)
			cancelIP()

			cnameCtx, cancelCNAME := context.WithTimeout(ctx, 3*time.Second)
			cname := resolveCNAME(cnameCtx, hostname)
			cancelCNAME()

			resultsCh <- wildcardSample{
				ipSignature: normalizedIPSignature(ips),
				cnameTarget: normalizeDNSName(cname),
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	ipCounts := make(map[string]int)
	cnameCounts := make(map[string]int)
	for sample := range resultsCh {
		if sample.ipSignature != "" {
			ipCounts[sample.ipSignature]++
		}
		if sample.cnameTarget != "" {
			cnameCounts[sample.cnameTarget]++
		}
	}

	profile := wildcardProfile{
		ipSignatures: make(map[string]struct{}),
		cnameTargets: make(map[string]struct{}),
	}

	if signature, ok := consistentWildcardMarker(ipCounts); ok {
		profile.ipSignatures[signature] = struct{}{}
	}
	if target, ok := consistentWildcardMarker(cnameCounts); ok {
		profile.cnameTargets[target] = struct{}{}
	}

	return profile
}

func (p wildcardProfile) empty() bool {
	return len(p.ipSignatures) == 0 && len(p.cnameTargets) == 0
}

func (p wildcardProfile) matchesIPs(ips []net.IP) bool {
	if len(p.ipSignatures) == 0 {
		return false
	}
	signature := normalizedIPSignature(ips)
	if signature == "" {
		return false
	}
	_, ok := p.ipSignatures[signature]
	return ok
}

func (p wildcardProfile) matchesCNAME(target string) bool {
	if len(p.cnameTargets) == 0 {
		return false
	}
	target = normalizeDNSName(target)
	if target == "" {
		return false
	}
	_, ok := p.cnameTargets[target]
	return ok
}

func consistentWildcardMarker(counts map[string]int) (string, bool) {
	if len(counts) != 1 {
		return "", false
	}

	for value, count := range counts {
		if value == "" || count < 2 {
			return "", false
		}
		return value, true
	}

	return "", false
}

func normalizedIPSignature(ips []net.IP) string {
	if len(ips) == 0 {
		return ""
	}

	seen := make(map[string]struct{}, len(ips))
	values := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		values = append(values, key)
	}

	if len(values) == 0 {
		return ""
	}

	sort.Strings(values)
	return strings.Join(values, ",")
}

func randomWildcardHostname(domain string) string {
	token := randomHex(8)
	if token == "" {
		token = hex.EncodeToString([]byte(time.Now().Format("150405.000000000")))
	}
	return "yscan-wild-" + token + "." + strings.TrimSpace(strings.ToLower(domain))
}

func randomHex(size int) string {
	if size <= 0 {
		size = 8
	}

	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}
