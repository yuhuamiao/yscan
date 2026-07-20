package domain

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

var defaultSubdomainWordlist = []string{
	"www", "api", "dev", "test", "uat", "staging", "stage", "prod",
	"admin", "portal", "login", "sso", "vpn", "gw", "mail", "mx",
	"ns1", "ns2", "dns", "cdn", "img", "static", "assets", "files",
	"download", "upload", "git", "gitlab", "github", "jenkins", "ci",
	"nexus", "registry", "docker", "harbor", "k8s", "kubernetes",
	"grafana", "prometheus", "kibana", "es", "elk", "rabbitmq",
	"redis", "mysql", "pgsql", "oracle", "sql", "db", "mongo",
	"mq", "ftp", "ssh", "rdp", "oa", "erp", "crm", "hr", "cms",
	"wiki", "confluence", "jira", "shop", "pay", "m", "mobile",
	"app", "open", "auth", "cas", "ldap", "idp", "bastion", "jump",
	"intra", "internal", "office", "ops", "monitor", "backup",
}

func BruteforceSubdomains(ctx context.Context, domain string, words []string, workers int) ([]CollectResult, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	if len(words) == 0 {
		words = defaultSubdomainWordlist
	}
	if workers <= 0 {
		workers = 32
	}

	wildcard := detectWildcardProfile(ctx, domain, 3)
	if !wildcard.empty() {
		log.Printf("[dns_bruteforce] wildcard dns detected for %s, ip_signatures=%d, cname_targets=%d", domain, len(wildcard.ipSignatures), len(wildcard.cnameTargets))
	}

	type job struct {
		word string
	}

	jobs := make(chan job, len(words))
	resultsCh := make(chan CollectResult, len(words))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}

				word := strings.TrimSpace(strings.ToLower(j.word))
				if word == "" {
					continue
				}

				subdomain := word + "." + domain
				lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				ips := resolveA(lookupCtx, subdomain)
				cancel()
				if len(ips) == 0 {
					continue
				}
				if wildcard.matchesIPs(ips) {
					continue
				}
				if len(wildcard.cnameTargets) > 0 {
					cnameCtx, cancelCNAME := context.WithTimeout(ctx, 2*time.Second)
					cnameTarget := resolveCNAME(cnameCtx, subdomain)
					cancelCNAME()
					if wildcard.matchesCNAME(cnameTarget) {
						continue
					}
				}

				resultsCh <- CollectResult{
					Subdomain: subdomain,
					IPs:       ips,
					FirstSeen: time.Now(),
					Sources:   []string{"dns_bruteforce"},
				}
			}
		}()
	}

	for _, word := range words {
		if ctx.Err() != nil {
			break
		}
		jobs <- job{word: word}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	seen := make(map[string]CollectResult)
	for res := range resultsCh {
		existing, ok := seen[res.Subdomain]
		if !ok {
			seen[res.Subdomain] = res
			continue
		}
		existing.IPs = mergeIPs(existing.IPs, res.IPs)
		existing.Sources = mergeSources(existing.Sources, res.Sources)
		if existing.FirstSeen.IsZero() || (!res.FirstSeen.IsZero() && res.FirstSeen.Before(existing.FirstSeen)) {
			existing.FirstSeen = res.FirstSeen
		}
		seen[res.Subdomain] = existing
	}

	results := make([]CollectResult, 0, len(seen))
	for _, res := range seen {
		results = append(results, res)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Subdomain < results[j].Subdomain
	})

	if ctx.Err() != nil && !errorsIsContextDone(ctx.Err()) {
		return results, ctx.Err()
	}
	return results, nil
}
