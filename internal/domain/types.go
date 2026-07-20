package domain

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"
)

type CollectResult struct {
	Subdomain string
	IPs       []net.IP
	FirstSeen time.Time
	Sources   []string
}

func isValidSubdomain(name, baseDomain string) bool {
	name = strings.TrimSuffix(name, ".")
	baseDomain = strings.TrimSuffix(baseDomain, ".")
	return name == baseDomain || strings.HasSuffix(name, "."+baseDomain)
}

func mergeIPs(existing []net.IP, incoming []net.IP) []net.IP {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	merged := make([]net.IP, 0, len(existing)+len(incoming))

	for _, ip := range existing {
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, ip)
	}

	for _, ip := range incoming {
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, ip)
	}

	return merged
}

func mergeSources(existing []string, incoming []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	merged := make([]string, 0, len(existing)+len(incoming))

	for _, src := range existing {
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}
		if _, ok := seen[src]; ok {
			continue
		}
		seen[src] = struct{}{}
		merged = append(merged, src)
	}

	for _, src := range incoming {
		src = strings.TrimSpace(src)
		if src == "" {
			continue
		}
		if _, ok := seen[src]; ok {
			continue
		}
		seen[src] = struct{}{}
		merged = append(merged, src)
	}

	sort.Strings(merged)
	return merged
}

func errorsIsContextDone(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}
