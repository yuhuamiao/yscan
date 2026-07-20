package pipeline

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golandproject/yscan/internal/domain"
	"golandproject/yscan/internal/storage"
)

type DomainCollectionOptions struct {
	ResolvePolicy  domain.ResolvePolicy
	CollectTimeout time.Duration
	VerifyWorkers  int
	BruteWorkers   int
}

func CollectSubdomains(db *sql.DB, domainName string, opts DomainCollectionOptions) []string {
	domainName = strings.TrimSpace(strings.ToLower(domainName))
	if domainName == "" {
		log.Print("域名不能为空")
		return nil
	}

	opts = normalizeDomainCollectionOptions(opts)
	ctx, cancel := context.WithTimeout(context.Background(), opts.CollectTimeout)
	defer cancel()

	results := collectFromSources(ctx, db, domainName, opts)
	resolvedResults := verifySubdomainsActive(ctx, aggregateSubdomains(results), opts.VerifyWorkers, opts.ResolvePolicy)

	uniqueIPs := make(map[string]bool)
	var ipsToScan []string

	for _, res := range resolvedResults {
		if len(res.IPs) == 0 && !strings.HasPrefix(res.Subdomain, "*.") {
			if err := storage.MarkDomainInactive(db, res.Subdomain); err != nil {
				log.Printf("标记失活子域失败 %s: %v", res.Subdomain, err)
			}
			fmt.Printf("[INACTIVE] %s\n", res.Subdomain)
			continue
		}

		fmt.Printf("[%s] %s (IPs: %v)\n", formatFirstSeen(res.FirstSeen), res.Subdomain, res.IPs)

		domainID, err := storage.SaveDomainInfo(
			db,
			domainName,
			res.Subdomain,
			strings.HasPrefix(res.Subdomain, "*."),
			"",
			strings.Join(res.Sources, ","),
			res.FirstSeen,
		)
		if err != nil {
			log.Printf("保存子域名失败 %s: %v", res.Subdomain, err)
			continue
		}

		var ipv4s []string
		for _, ip := range res.IPs {
			if ip == nil || ip.To4() == nil {
				continue
			}
			ipv4s = append(ipv4s, ip.String())
		}

		if err := storage.SyncDomainIPs(db, domainID, res.Subdomain, ipv4s, nil); err != nil {
			log.Printf("同步子域 IP 失败 %s: %v", res.Subdomain, err)
		}

		for _, ipStr := range ipv4s {
			if !uniqueIPs[ipStr] {
				uniqueIPs[ipStr] = true
				ipsToScan = append(ipsToScan, ipStr)
			}
		}
	}

	return ipsToScan
}

func normalizeDomainCollectionOptions(opts DomainCollectionOptions) DomainCollectionOptions {
	if opts.CollectTimeout <= 0 {
		opts.CollectTimeout = 90 * time.Second
	}
	if opts.VerifyWorkers <= 0 {
		opts.VerifyWorkers = 64
	}
	if opts.BruteWorkers <= 0 {
		opts.BruteWorkers = 48
	}
	opts.ResolvePolicy = domain.NormalizeResolvePolicy(opts.ResolvePolicy)
	return opts
}

func collectFromSources(ctx context.Context, db *sql.DB, domainName string, opts DomainCollectionOptions) []domain.CollectResult {
	var results []domain.CollectResult

	if crtResults, err := (&domain.CRTshCollector{}).Collect(domainName, 30*time.Second); err == nil {
		results = append(results, applyResolvePolicyToResults(crtResults, opts.ResolvePolicy)...)
	} else {
		log.Printf("crt.sh 收集错误: %v", err)
	}

	if searchResults, err := domain.NewSearchEngineCollector().Collect(domainName, 30*time.Second); err == nil {
		fmt.Printf("[DEBUG] 搜索引擎结果数量: %d\n", len(searchResults))
		results = append(results, applyResolvePolicyToResults(searchResults, opts.ResolvePolicy)...)
	} else {
		log.Printf("搜索引擎收集错误: %v", err)
	}

	if bruteResults, err := domain.BruteforceSubdomains(ctx, domainName, nil, opts.BruteWorkers); err == nil {
		fmt.Printf("[DEBUG] DNS 字典爆破结果数量: %d\n", len(bruteResults))
		results = append(results, applyResolvePolicyToResults(bruteResults, opts.ResolvePolicy)...)
	} else {
		log.Printf("DNS 字典爆破错误: %v", err)
	}

	if knownResults, err := revalidateKnownSubdomains(ctx, db, domainName, opts.ResolvePolicy); err == nil {
		fmt.Printf("[DEBUG] 历史子域复检结果数量: %d\n", len(knownResults))
		results = append(results, knownResults...)
	} else {
		log.Printf("历史子域复检错误: %v", err)
	}

	return results
}

func revalidateKnownSubdomains(ctx context.Context, db *sql.DB, domainName string, policy domain.ResolvePolicy) ([]domain.CollectResult, error) {
	known, err := storage.ListKnownSubdomains(db, domainName)
	if err != nil {
		return nil, err
	}
	if len(known) == 0 {
		return nil, nil
	}

	results := make([]domain.CollectResult, 0, len(known))
	for _, subdomainName := range known {
		if strings.TrimSpace(subdomainName) == "" {
			continue
		}
		results = append(results, domain.CollectResult{
			Subdomain: subdomainName,
			FirstSeen: time.Now(),
			Sources:   []string{"stateful_recheck"},
		})
	}

	return verifySubdomainsActive(ctx, aggregateSubdomains(results), 32, policy), nil
}

func verifySubdomainsActive(ctx context.Context, aggregated map[string]*domain.CollectResult, workers int, policy domain.ResolvePolicy) []domain.CollectResult {
	if len(aggregated) == 0 {
		return nil
	}
	if workers <= 0 {
		workers = 16
	}

	type job struct {
		key string
	}

	keys := make([]string, 0, len(aggregated))
	for key := range aggregated {
		keys = append(keys, key)
	}

	jobs := make(chan job, len(keys))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					return
				}

				res := aggregated[item.key]
				if res == nil || strings.HasPrefix(res.Subdomain, "*.") {
					continue
				}

				needLookup := len(res.IPs) == 0
				if !needLookup {
					needLookup = true
					for _, ip := range res.IPs {
						if ip != nil {
							needLookup = false
							break
						}
					}
				}
				if !needLookup {
					continue
				}

				lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				ips := resolveIPs(lookupCtx, res.Subdomain, policy)
				cancel()
				res.IPs = ips
			}
		}()
	}

	for _, key := range keys {
		if ctx.Err() != nil {
			break
		}
		jobs <- job{key: key}
	}
	close(jobs)
	wg.Wait()

	results := make([]domain.CollectResult, 0, len(keys))
	for _, key := range keys {
		if res := aggregated[key]; res != nil {
			results = append(results, *res)
		}
	}

	return results
}

func aggregateSubdomains(results []domain.CollectResult) map[string]*domain.CollectResult {
	res := make(map[string]*domain.CollectResult)

	for _, r := range results {
		key := r.Subdomain
		agg, ok := res[key]
		if !ok {
			copyResult := r
			res[key] = &copyResult
			continue
		}

		if agg.FirstSeen.IsZero() || (!r.FirstSeen.IsZero() && r.FirstSeen.Before(agg.FirstSeen)) {
			agg.FirstSeen = r.FirstSeen
		}

		agg.IPs = mergeIPs(agg.IPs, r.IPs)
		agg.Sources = mergeStrings(agg.Sources, r.Sources)
	}
	return res
}

func applyResolvePolicyToResults(results []domain.CollectResult, policy domain.ResolvePolicy) []domain.CollectResult {
	policy = domain.NormalizeResolvePolicy(policy)
	filtered := make([]domain.CollectResult, 0, len(results))
	for _, result := range results {
		result.IPs = filterIPsByPolicy(result.IPs, policy)
		filtered = append(filtered, result)
	}
	return filtered
}

func filterIPsByPolicy(ips []net.IP, policy domain.ResolvePolicy) []net.IP {
	filter := newRuntimeIPFilter(policy.DenyCIDRs)
	var out []net.IP
	for _, ip := range ips {
		if ip == nil || filter.Blocks(ip) {
			continue
		}
		out = append(out, ip)
	}
	return out
}

func resolveIPs(ctx context.Context, hostname string, policy domain.ResolvePolicy) []net.IP {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("DNS 校验异常 %s: %v", hostname, r)
		}
	}()

	if strings.TrimSpace(hostname) == "" || strings.HasPrefix(hostname, "*.") {
		return nil
	}
	return domain.ResolveSubdomainIPsWithPolicy(ctx, hostname, policy)
}

func formatFirstSeen(t time.Time) string {
	if t.IsZero() {
		return time.Now().Format("2006-01-02")
	}
	return t.Format("2006-01-02")
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

func mergeStrings(existing []string, incoming []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	merged := make([]string, 0, len(existing)+len(incoming))
	for _, value := range existing {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		merged = append(merged, value)
	}
	for _, value := range incoming {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		merged = append(merged, value)
	}
	return merged
}

type runtimeIPFilter struct {
	deny []*net.IPNet
}

func newRuntimeIPFilter(cidrs []string) runtimeIPFilter {
	filter := runtimeIPFilter{}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil || network == nil {
			continue
		}
		filter.deny = append(filter.deny, network)
	}
	return filter
}

func (f runtimeIPFilter) Blocks(ip net.IP) bool {
	for _, network := range f.deny {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
