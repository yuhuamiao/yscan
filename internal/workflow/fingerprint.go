package workflow

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golandproject/yscan/internal/fingerprint"
	"golandproject/yscan/internal/model"
)

// collectRunFingerprintMatches keeps collection separate from port discovery:
// a port is discovered first, then only its eligible service is queried.
func collectRunFingerprintMatches(ctx context.Context, db *sql.DB, run model.ScanTaskRun, ip string, results []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error) {
	if len(results) == 0 {
		return results, nil, nil
	}
	engine, err := fingerprint.LoadRunEngineCached(db, run.ID)
	if err != nil {
		return nil, nil, err
	}
	return collectRunFingerprintMatchesWithEngine(ctx, engine, ip, results)
}

func newRunFingerprintCollector(db *sql.DB, run model.ScanTaskRun) (func(context.Context, *sql.DB, model.ScanTaskRun, string, []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error), error) {
	return newRunFingerprintCollectorWithLoader(db, run, fingerprint.LoadRunEngineCached), nil
}

func newRunFingerprintCollectorWithLoader(db *sql.DB, run model.ScanTaskRun, loader func(*sql.DB, int64) (*fingerprint.Engine, error)) func(context.Context, *sql.DB, model.ScanTaskRun, string, []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error) {
	var once sync.Once
	var engine *fingerprint.Engine
	var loadErr error
	return func(ctx context.Context, _ *sql.DB, _ model.ScanTaskRun, ip string, results []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error) {
		if len(results) == 0 {
			return results, nil, nil
		}
		once.Do(func() { engine, loadErr = loader(db, run.ID) })
		if loadErr != nil {
			return results, nil, loadErr
		}
		return collectRunFingerprintMatchesWithEngine(ctx, engine, ip, results)
	}
}

func collectRunFingerprintMatchesWithEngine(ctx context.Context, engine *fingerprint.Engine, ip string, results []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error) {
	allowedPorts := make(map[int]struct{}, len(results))
	for _, result := range results {
		if port, ok := scanResultPort(ip, result); ok {
			allowedPorts[port] = struct{}{}
		}
	}
	persisted := make([]model.FingerprintRunMatch, 0)
	for index := range results {
		if err := ctx.Err(); err != nil {
			return results, persisted, err
		}
		// V2 product conclusions are exclusively derived from this run's frozen engine.
		results[index].Product = ""
		results[index].FingerprintSource = ""
		port, ok := scanResultPort(ip, results[index])
		if !ok {
			continue
		}
		tcpEvidence := fingerprint.NewBannerEvidence(results[index].Banner, results[index].BannerTruncated)
		results[index].ProtocolEvidence = append(results[index].ProtocolEvidence, protocolEvidenceFromBanner(tcpEvidence))
		tcpSummary := bannerEvidenceSummary(tcpEvidence)
		matchSets := []endpointEvidenceMatches{{protocol: "tcp", summary: tcpSummary, matches: engine.Match(tcpEvidence)}}
		collected, collectErr := fingerprint.CollectWebEvidence(ctx, ip, port, webEvidenceService(results[index].Service), fingerprint.WebEvidenceOptions{AllowedPorts: allowedPorts})
		if collectErr == nil {
			webEvidence := collected.Evidence
			webEvidence.Protocol = collected.Protocol
			matchSets = append(matchSets, endpointEvidenceMatches{protocol: collected.Protocol, summary: collected.Summary, matches: engine.Match(webEvidence)})
			results[index].Service = collectedWebService(results[index].Service, collected.Protocol)
			results[index].ProtocolEvidence = append(results[index].ProtocolEvidence, protocolEvidenceFromWeb(collected))
		} else if !errors.Is(collectErr, fingerprint.ErrNotWebService) {
			// A failed HTTP request never discards an already collected banner.
			matchSets[0].summary += " web_evidence_unavailable"
		}
		probeSets, probeEvidence, probeErr := collectNmapProbeMatches(ctx, engine, ip, port, results[index].Service)
		matchSets = append(matchSets, probeSets...)
		results[index].ProtocolEvidence = append(results[index].ProtocolEvidence, probeEvidence...)
		hardProducts := make(map[string]hardProductCandidate)
		for _, set := range matchSets {
			for _, match := range set.matches {
				persisted = append(persisted, model.FingerprintRunMatch{
					FingerprintImportID:     match.FingerprintImportID,
					FingerprintSourceRuleID: match.FingerprintSourceRuleID,
					SourceKey:               match.SourceKey,
					SourceRuleID:            match.SourceRuleID,
					IP:                      ip,
					Port:                    port,
					Protocol:                set.protocol,
					Product:                 match.Product,
					SourceProduct:           match.SourceProduct,
					ProductRole:             match.ProductRole,
					ExclusiveGroup:          match.ExclusiveGroup,
					Version:                 match.Version,
					CPE:                     match.CPE,
					Tags:                    match.Tags,
					Soft:                    match.Soft,
					EvidenceSummary:         set.summary,
					Evidence:                append([]model.FingerprintMatchEvidence(nil), match.MatcherHits...),
				})
				if !match.Soft {
					product := strings.ToLower(strings.TrimSpace(match.Product))
					if product != "" {
						candidate := hardProducts[product]
						candidate.role = match.ProductRole
						candidate.exclusiveGroup = match.ExclusiveGroup
						if candidate.source == "" {
							candidate.source = match.SourceKey
						} else if candidate.source != match.SourceKey {
							candidate.source = "multiple"
						}
						hardProducts[product] = candidate
					}
				}
			}
		}
		results[index].Product, results[index].FingerprintSource = resolvedHardProduct(hardProducts)
		if endpointServiceUnknown(results[index].Service) {
			if candidate, exists := hardProducts[results[index].Product]; exists && candidate.role == "network_service" {
				results[index].Service = results[index].Product
			}
		}
		if probeErr != nil {
			return results, persisted, probeErr
		}
		if err := ctx.Err(); err != nil {
			return results, persisted, err
		}
	}
	return results, persisted, nil
}

func endpointServiceUnknown(service string) bool {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "", "unknown", "none_unknown", "tcp", "tcp-unknown":
		return true
	default:
		return false
	}
}

const (
	maxNmapProbesPerEndpoint = 3
	nmapProbeEndpointBudget  = 4 * time.Second
	nmapProbeReadBudget      = 3 * time.Second
)

func collectNmapProbeMatches(ctx context.Context, engine *fingerprint.Engine, ip string, port int, service string) ([]endpointEvidenceMatches, []model.ScanTaskRunProtocolEvidence, error) {
	probes := engine.NmapTCPProbesForEndpoint(port, service)
	if len(probes) == 0 {
		return nil, nil, nil
	}
	probeContext, cancel := context.WithTimeout(ctx, nmapProbeEndpointBudget)
	defer cancel()
	selected := probes[:minInt(len(probes), maxNmapProbesPerEndpoint)]
	for index := range selected {
		if selected[index].Timeout <= 0 || selected[index].Timeout > nmapProbeReadBudget {
			selected[index].Timeout = nmapProbeReadBudget
		}
	}
	completed := make(chan nmapProbeResult, len(selected))
	for index, probe := range selected {
		go func(index int, probe fingerprint.NmapTCPProbe) {
			response, err := fingerprint.ExecuteNmapTCPProbe(probeContext, ip, port, probe)
			if err != nil {
				outcome := nmapProbeFailureOutcome(err)
				completed <- nmapProbeResult{index: index, evidence: protocolEvidenceFromProbeFailure(probe.Name, outcome)}
				return
			}
			evidence := fingerprint.NewBannerEvidence(string(response), len(response) >= 16<<10)
			completed <- nmapProbeResult{index: index, ok: len(response) > 0, set: endpointEvidenceMatches{
				protocol: "tcp",
				summary:  "tcp probe=" + probe.Name + " " + bannerEvidenceSummary(evidence),
				matches:  engine.MatchNmapTCPProbeResponse(probe.Name, response),
			}, evidence: protocolEvidenceFromProbe(probe.Name, evidence)}
		}(index, probe)
	}
	results := make([]nmapProbeResult, 0, len(selected))
	for range selected {
		select {
		case result := <-completed:
			results = append(results, result)
		case <-probeContext.Done():
			if err := ctx.Err(); err != nil {
				results = appendMissingProbeResults(results, selected, model.ProtocolProbeOutcomeCanceled)
				sets, evidence := probeResultsInOrder(results)
				return sets, evidence, err
			}
			results = appendMissingProbeResults(results, selected, model.ProtocolProbeOutcomeBudgetTimeout)
			sets, evidence := probeResultsInOrder(results)
			return sets, evidence, nil
		}
	}
	sets, evidence := probeResultsInOrder(results)
	return sets, evidence, nil
}

type nmapProbeResult struct {
	index    int
	set      endpointEvidenceMatches
	evidence model.ScanTaskRunProtocolEvidence
	ok       bool
}

func probeResultsInOrder(results []nmapProbeResult) ([]endpointEvidenceMatches, []model.ScanTaskRunProtocolEvidence) {
	sort.Slice(results, func(i, j int) bool { return results[i].index < results[j].index })
	sets := make([]endpointEvidenceMatches, 0, len(results))
	evidence := make([]model.ScanTaskRunProtocolEvidence, 0, len(results))
	for _, result := range results {
		if result.ok {
			sets = append(sets, result.set)
		}
		evidence = append(evidence, result.evidence)
	}
	return sets, evidence
}

func appendMissingProbeResults(results []nmapProbeResult, probes []fingerprint.NmapTCPProbe, outcome string) []nmapProbeResult {
	completed := make(map[int]struct{}, len(results))
	for _, result := range results {
		completed[result.index] = struct{}{}
	}
	for index, probe := range probes {
		if _, ok := completed[index]; ok {
			continue
		}
		results = append(results, nmapProbeResult{index: index, evidence: protocolEvidenceFromProbeFailure(probe.Name, outcome)})
	}
	return results
}

func nmapProbeFailureOutcome(err error) string {
	if errors.Is(err, context.Canceled) {
		return model.ProtocolProbeOutcomeCanceled
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		switch strings.ToLower(netErr.Op) {
		case "dial":
			if netErr.Timeout() {
				return model.ProtocolProbeOutcomeConnectTimeout
			}
			return model.ProtocolProbeOutcomeConnectFailed
		case "write":
			return model.ProtocolProbeOutcomeWriteFailed
		case "read":
			if netErr.Timeout() {
				return model.ProtocolProbeOutcomeReadTimeout
			}
			return model.ProtocolProbeOutcomeReadFailed
		}
		if netErr.Timeout() {
			return model.ProtocolProbeOutcomeReadTimeout
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.ProtocolProbeOutcomeReadTimeout
	}
	return model.ProtocolProbeOutcomeReadFailed
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

type hardProductCandidate struct {
	role           string
	exclusiveGroup string
	source         string
}

func resolvedHardProduct(products map[string]hardProductCandidate) (string, string) {
	primary := make(map[string]hardProductCandidate)
	for product, candidate := range products {
		if candidate.role == "web_server" || candidate.role == "network_service" {
			primary[product] = candidate
		}
	}
	if len(primary) != 1 {
		return "", ""
	}
	for product, candidate := range primary {
		source := candidate.source
		if source == "multiple" {
			source = ""
		}
		return product, source
	}
	return "", ""
}

func protocolEvidenceFromBanner(evidence fingerprint.Evidence) model.ScanTaskRunProtocolEvidence {
	observation := model.ScanTaskRunProtocolEvidence{
		EvidenceType: model.ProtocolEvidencePassiveBanner,
		Protocol:     "tcp",
		Responded:    evidence.BannerCapturedLength > 0,
	}
	if observation.Responded {
		observation.BannerCapturedLength = evidence.BannerCapturedLength
		observation.BannerSHA256 = evidence.BannerCapturedSHA256
		observation.BannerTruncated = evidence.BannerTruncated
	}
	return observation
}

func protocolEvidenceFromProbe(name string, evidence fingerprint.Evidence) model.ScanTaskRunProtocolEvidence {
	outcome := model.ProtocolProbeOutcomeNoResponse
	if evidence.BannerCapturedLength > 0 {
		outcome = model.ProtocolProbeOutcomeResponded
	}
	observation := model.ScanTaskRunProtocolEvidence{
		EvidenceType: model.ProtocolEvidenceActiveProbe,
		ProbeName:    safeProtocolLabel(name, 128),
		Protocol:     "tcp",
		Responded:    evidence.BannerCapturedLength > 0,
		Outcome:      outcome,
		Diagnostic:   outcome,
	}
	if observation.Responded {
		observation.BannerCapturedLength = evidence.BannerCapturedLength
		observation.BannerSHA256 = evidence.BannerCapturedSHA256
		observation.BannerTruncated = evidence.BannerTruncated
	}
	return observation
}

func protocolEvidenceFromProbeFailure(name, outcome string) model.ScanTaskRunProtocolEvidence {
	return model.ScanTaskRunProtocolEvidence{
		EvidenceType: model.ProtocolEvidenceActiveProbe,
		ProbeName:    safeProtocolLabel(name, 128),
		Protocol:     "tcp",
		Outcome:      outcome,
		Diagnostic:   outcome,
	}
}

func protocolEvidenceFromWeb(collected fingerprint.CollectedEvidence) model.ScanTaskRunProtocolEvidence {
	evidence := collected.Evidence
	return model.ScanTaskRunProtocolEvidence{
		EvidenceType:         model.ProtocolEvidenceWeb,
		Protocol:             collected.Protocol,
		Responded:            true,
		StatusCode:           evidence.StatusCode,
		Server:               safeProtocolLabel(headerValue(evidence.Headers, "server"), 256),
		Title:                safeProtocolLabel(evidence.Title, 256),
		HeaderCapturedLength: evidence.HeaderCapturedLength,
		HeaderSHA256:         evidence.HeaderCapturedSHA256,
		HeaderTruncated:      evidence.HeaderTruncated,
		BodyCapturedLength:   evidence.BodyCapturedLength,
		BodySHA256:           evidence.BodyCapturedSHA256,
		BodyTruncated:        evidence.BodyTruncated,
	}
}

func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func safeProtocolLabel(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(value))
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) > limit {
		value = string(runes[:limit])
	}
	return value
}

func collectedWebService(current, protocol string) string {
	current = strings.ToLower(strings.TrimSpace(current))
	if current == "" || current == "unknown" || current == "none_unknown" || current == "http-unknown" {
		return protocol
	}
	return current
}

func webEvidenceService(service string) string {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "nginx", "apache", "iis", "lighttpd", "caddy", "jetty":
		return "http"
	default:
		return service
	}
}

func scanResultPort(ip string, result model.ScanResult) (int, bool) {
	if !result.Open {
		return 0, false
	}
	host, portText, err := net.SplitHostPort(result.Address)
	if err != nil || host != ip {
		return 0, false
	}
	port, err := strconv.Atoi(portText)
	return port, err == nil && port >= 1 && port <= 65535
}

type endpointEvidenceMatches struct {
	protocol string
	summary  string
	matches  []fingerprint.Match
}

func bannerEvidenceSummary(evidence fingerprint.Evidence) string {
	if strings.TrimSpace(evidence.Banner) == "" {
		return "tcp banner=unavailable"
	}
	return "tcp banner_bytes=" + strconv.Itoa(evidence.BannerCapturedLength) +
		" banner_sha256=" + evidence.BannerCapturedSHA256 + truncationSummary(evidence.BannerTruncated)
}

func truncationSummary(truncated bool) string {
	if truncated {
		return " truncated"
	}
	return ""
}
