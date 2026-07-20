package pipeline

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"golandproject/yscan/internal/assist"
)

type SubnetDiscoveryOptions struct {
	Workers  int
	MaxHosts int
}

func DiscoverAliveHosts(ctx context.Context, cidr string, opts SubnetDiscoveryOptions) ([]string, error) {
	targets, err := ExpandIPv4CIDR(cidr, opts.MaxHosts)
	if err != nil {
		return nil, err
	}

	return ProbeAliveHosts(ctx, targets, opts.Workers)
}

// ProbeAliveHosts probes a list of IPv4 addresses concurrently and returns the
// responsive addresses in ascending order.
func ProbeAliveHosts(ctx context.Context, targets []string, workers int) ([]string, error) {
	return probeAliveHosts(ctx, targets, workers, probeAliveHost)
}

type hostProbe func(context.Context, string) bool

func probeAliveHosts(ctx context.Context, targets []string, workers int, probe hostProbe) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if probe == nil {
		return nil, fmt.Errorf("host probe is required")
	}

	targets = normalizeIPv4Targets(targets)
	if len(targets) == 0 {
		return nil, nil
	}

	if workers <= 0 {
		workers = 128
	}
	if workers > 512 {
		workers = 512
	}

	jobs := make(chan string)
	results := make(chan string, len(targets))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip, ok := <-jobs:
					if !ok {
						return
					}
					if !probe(ctx, ip) {
						continue
					}
					select {
					case results <- ip:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range targets {
			select {
			case jobs <- ip:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	seen := make(map[string]struct{}, len(targets))
	alive := make([]string, 0, len(targets))
	for ip := range results {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		alive = append(alive, ip)
	}

	sort.Slice(alive, func(i, j int) bool {
		return compareIPv4(alive[i], alive[j]) < 0
	})
	if err := ctx.Err(); err != nil {
		return alive, err
	}
	return alive, nil
}

func probeAliveHost(ctx context.Context, ip string) bool {
	if assist.IsHostAliveTCPContext(ctx, ip) {
		return true
	}
	return assist.IsHostAliveContext(ctx, ip)
}

// ExpandIPv4CIDR expands an IPv4 CIDR to scannable host addresses. Network and
// broadcast addresses are excluded except for /31 and /32 ranges.
func ExpandIPv4CIDR(cidr string, maxHosts int) ([]string, error) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return nil, fmt.Errorf("empty cidr")
	}

	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr %s: %w", cidr, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only ipv4 cidr is supported for subnet scan")
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only ipv4 cidr is supported for subnet scan")
	}

	if maxHosts <= 0 {
		maxHosts = 4096
	}

	hostBits := uint(bits - ones)
	var total uint64 = 1
	total <<= hostBits

	var start, end uint32
	base := binary.BigEndian.Uint32(network.IP.To4())
	switch {
	case total == 1:
		start, end = base, base
	case total == 2:
		start, end = base, base+1
	default:
		start, end = base+1, base+uint32(total)-2
	}

	hostCount := uint64(end-start) + 1
	if hostCount > uint64(maxHosts) {
		return nil, fmt.Errorf("cidr %s expands to %d hosts, over max %d", cidr, hostCount, maxHosts)
	}

	out := make([]string, 0, hostCount)
	for current := start; current <= end; current++ {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, current)
		out = append(out, net.IP(buf).String())
		if current == end {
			break
		}
	}
	return out, nil
}

func normalizeIPv4Targets(targets []string) []string {
	seen := make(map[string]struct{}, len(targets))
	normalized := make([]string, 0, len(targets))
	for _, target := range targets {
		ip := net.ParseIP(strings.TrimSpace(target)).To4()
		if ip == nil {
			continue
		}
		value := ip.String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func compareIPv4(left, right string) int {
	l := net.ParseIP(strings.TrimSpace(left)).To4()
	r := net.ParseIP(strings.TrimSpace(right)).To4()
	if l == nil || r == nil {
		return strings.Compare(left, right)
	}

	lu := binary.BigEndian.Uint32(l)
	ru := binary.BigEndian.Uint32(r)
	switch {
	case lu < ru:
		return -1
	case lu > ru:
		return 1
	default:
		return 0
	}
}
