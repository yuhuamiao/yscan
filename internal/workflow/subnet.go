package workflow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"golandproject/yscan/internal/diff"
	"golandproject/yscan/internal/fingerprint"
	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/pipeline"
	"golandproject/yscan/internal/planner"
	"golandproject/yscan/internal/scan"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/vuln"
)

var ErrCanceled = errors.New("subnet task canceled")

type SubnetRunOptions struct {
	DB                    *sql.DB
	TaskID                int64
	CIDR                  string
	Network               string
	TemplatesPath         string
	EnableVulnerabilities bool
	DiscoveryOptions      pipeline.SubnetDiscoveryOptions
	CheckCanceled         func() (bool, error)
	UpdateProgress        func(int) error
}

// SubnetTaskRunOptions configures the v2 execution path. Its target and scan
// settings are read from the immutable ScanTaskRun instead of a legacy Task.
type SubnetTaskRunOptions struct {
	DB               *sql.DB
	Run              model.ScanTaskRun
	Network          string
	DiscoveryOptions pipeline.SubnetDiscoveryOptions
	CheckCanceled    func() (bool, error)
	UpdateProgress   func(int) error
}

// SubnetTaskRunExecutor adapts the subnet workflow to schedule.Executor
// without making the workflow package depend on the schedule package.
type SubnetTaskRunExecutor struct {
	Options SubnetTaskRunOptions
}

func NewSubnetTaskRunExecutor(options SubnetTaskRunOptions) SubnetTaskRunExecutor {
	return SubnetTaskRunExecutor{Options: options}
}

func (executor SubnetTaskRunExecutor) Execute(ctx context.Context, run model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
	options := executor.Options
	options.Run = run
	return RunSubnetTaskRun(ctx, options)
}

type subnetDependencies struct {
	discover            func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error)
	scanHost            func(context.Context, string, string) ([]model.ScanResult, error)
	runNuclei           func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error)
	runNucleiPaths      func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error)
	collectFingerprints func(context.Context, *sql.DB, string, []model.ScanResult) ([]model.AssetFingerprint, error)
	saveFindings        func(*sql.DB, int64, []model.NucleiFinding) error
}

// RunSubnet executes discovery, quick profiling, optional vulnerability
// validation, and persists a task-level change summary.
func RunSubnet(ctx context.Context, options SubnetRunOptions) (model.TaskChangeSummary, error) {
	return runSubnet(ctx, options, subnetDependencies{
		discover:            pipeline.DiscoverAliveHosts,
		scanHost:            scan.RunQuick,
		runNuclei:           vuln.RunNucleiForOpenPortsWithTags,
		runNucleiPaths:      vuln.RunNucleiForOpenPortsWithTemplatePaths,
		collectFingerprints: collectRunFingerprints,
		saveFindings:        storage.SaveNucleiFindings,
	})
}

// RunSubnetTaskRun scans one v2 subnet run and returns only the immutable
// observations for that run. Inventory updates remain current-state data;
// they are deliberately not used as the run Diff baseline.
func RunSubnetTaskRun(ctx context.Context, options SubnetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
	return runSubnetTaskRun(ctx, options, subnetDependencies{
		discover:            pipeline.DiscoverAliveHosts,
		scanHost:            scan.RunQuick,
		runNuclei:           vuln.RunNucleiForOpenPortsWithTags,
		runNucleiPaths:      vuln.RunNucleiForOpenPortsWithTemplatePaths,
		collectFingerprints: collectRunFingerprints,
	})
}

func runSubnetTaskRun(ctx context.Context, options SubnetTaskRunOptions, dependencies subnetDependencies) (model.ScanTaskRunSnapshot, error) {
	if options.DB == nil {
		return model.ScanTaskRunSnapshot{}, errors.New("subnet task run database is required")
	}
	if options.Run.ID <= 0 || options.Run.ScanTaskID <= 0 || options.Run.ScanType != model.ScanTypeSubnet {
		return model.ScanTaskRunSnapshot{}, errors.New("invalid subnet scan task run")
	}
	cidr := strings.TrimSpace(options.Run.Target)
	if !pipeline.IsIPv4CIDR(cidr) {
		return model.ScanTaskRunSnapshot{}, fmt.Errorf("invalid IPv4 CIDR: %s", cidr)
	}
	if strings.TrimSpace(options.Network) == "" {
		options.Network = "tcp"
	}
	if dependencies.runNucleiPaths == nil {
		dependencies.runNucleiPaths = vuln.RunNucleiForOpenPortsWithTemplatePaths
	}
	if dependencies.collectFingerprints == nil {
		dependencies.collectFingerprints = collectRunFingerprints
	}
	if dependencies.discover == nil || dependencies.scanHost == nil || dependencies.runNuclei == nil {
		return model.ScanTaskRunSnapshot{}, errors.New("subnet task run dependencies are required")
	}
	if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if err := updateProgress(options.UpdateProgress, 10); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}

	aliveHosts, err := dependencies.discover(ctx, cidr, options.DiscoveryOptions)
	if err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	scope := "subnet:" + cidr
	if err := storage.SyncHostInventory(options.DB, scope, aliveHosts); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}

	snapshot := model.ScanTaskRunSnapshot{
		RunID:           options.Run.ID,
		Hosts:           snapshotHosts(aliveHosts),
		Ports:           make([]model.ScanTaskRunPort, 0),
		Vulnerabilities: make([]model.ScanTaskRunVulnerability, 0),
	}
	if len(aliveHosts) == 0 {
		if err := storage.DeactivateScopePortsForInactiveHosts(options.DB, scope); err != nil {
			return model.ScanTaskRunSnapshot{}, err
		}
		if err := updateProgress(options.UpdateProgress, 100); err != nil {
			return model.ScanTaskRunSnapshot{}, err
		}
		return snapshot, nil
	}

	for index, ip := range aliveHosts {
		if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
			return model.ScanTaskRunSnapshot{}, err
		}
		openPorts, err := dependencies.scanHost(ctx, ip, options.Network)
		if err != nil {
			return model.ScanTaskRunSnapshot{}, err
		}
		if err := storage.SyncOpenPorts(options.DB, ip, openPorts); err != nil {
			return model.ScanTaskRunSnapshot{}, err
		}
		if err := storage.SyncScopeOpenPorts(options.DB, scope, ip, openPorts); err != nil {
			return model.ScanTaskRunSnapshot{}, err
		}
		// Fingerprint collection is best-effort; a failed probe must not fail the scan.
		currentFingerprints, _ := dependencies.collectFingerprints(ctx, options.DB, ip, openPorts)
		snapshot.Ports = append(snapshot.Ports, snapshotPorts(ip, openPorts)...)

		if options.Run.Config.VulnerabilityOn {
			findings, candidates, err := runPlannedValidation(ctx, ip, openPorts, currentFingerprints, options.Run.Config.NucleiTemplates, dependencies.runNuclei, dependencies.runNucleiPaths)
			if err != nil {
				return model.ScanTaskRunSnapshot{}, err
			}
			snapshot.TemplateCandidates = append(snapshot.TemplateCandidates, candidates...)
			snapshot.Vulnerabilities = append(snapshot.Vulnerabilities, snapshotVulnerabilities(findings)...)
		}
		progress := 20 + int(float64(index+1)/float64(len(aliveHosts))*80)
		if err := updateProgress(options.UpdateProgress, progress); err != nil {
			return model.ScanTaskRunSnapshot{}, err
		}
	}
	if err := storage.DeactivateScopePortsForInactiveHosts(options.DB, scope); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	snapshot.Ports = uniqueSnapshotPorts(snapshot.Ports)
	snapshot.Vulnerabilities = uniqueSnapshotVulnerabilities(snapshot.Vulnerabilities)
	snapshot.TemplateCandidates = uniqueTemplateCandidates(snapshot.TemplateCandidates)
	return snapshot, nil
}

func collectRunFingerprints(ctx context.Context, db *sql.DB, ip string, ports []model.ScanResult) ([]model.AssetFingerprint, error) {
	return collectRunFingerprintsWith(ctx, db, ip, ports, fingerprint.CollectHTTPEvidence)
}

type httpEvidenceCollector func(context.Context, string, fingerprint.HTTPEvidenceOptions) (fingerprint.HTTPEvidence, error)

func collectRunFingerprintsWith(ctx context.Context, db *sql.DB, ip string, ports []model.ScanResult, collectHTTP httpEvidenceCollector) ([]model.AssetFingerprint, error) {
	compilation, err := fingerprint.LoadReviewedRules("data/fingerprints")
	if err != nil {
		return nil, err
	}
	return collectRunFingerprintsWithRules(ctx, db, ip, ports, compilation.Rules, collectHTTP)
}

func collectRunFingerprintsWithRules(ctx context.Context, db *sql.DB, ip string, ports []model.ScanResult, rules []fingerprint.Rule, collectHTTP httpEvidenceCollector) ([]model.AssetFingerprint, error) {
	current := make([]model.AssetFingerprint, 0)
	for _, port := range ports {
		if !port.Open {
			continue
		}
		_, portText, err := net.SplitHostPort(port.Address)
		if err != nil {
			continue
		}
		var number int
		if _, err := fmt.Sscanf(portText, "%d", &number); err != nil {
			continue
		}
		// Banner is independently useful TCP evidence. A failed optional web
		// probe must never erase it.
		evidence := fingerprint.ServiceEvidence{Protocol: fingerprint.ProtocolTCP, Banner: port.Banner}
		if shouldCollectHTTPEvidence(number, port.Service) {
			protocol := fingerprintProtocol(number, port.Service)
			if protocol != fingerprint.ProtocolHTTPS {
				protocol = fingerprint.ProtocolHTTP
			}
			httpEvidence, err := collectHTTP(ctx, fmt.Sprintf("%s://%s:%d", protocol, ip, number), fingerprint.DefaultHTTPEvidenceOptions())
			if err == nil {
				fav, _ := fingerprint.CollectFaviconEvidence(ctx, httpEvidence.FinalURL, fingerprint.DefaultHTTPEvidenceOptions())
				evidence = fingerprint.ServiceEvidence{Protocol: protocol, Headers: httpEvidence.Headers, HeaderText: httpEvidence.HeaderText, Body: httpEvidence.BodySummary, Favicon: fav}
			}
		}
		matches, err := fingerprint.MatchRules(rules, evidence)
		if err != nil {
			continue
		}
		records := make([]model.AssetFingerprint, 0, len(matches))
		for _, match := range matches {
			if record, err := match.ToAssetFingerprint(ip, number); err == nil {
				records = append(records, record)
			}
		}
		if err := storage.UpsertAssetFingerprints(db, records); err != nil {
			return nil, err
		}
		current = append(current, records...)
	}
	return current, nil
}

// Unknown services receive one bounded HTTP GET probe so a web product on a
// non-standard port can be fingerprinted. Probe failure is deliberately
// non-blocking and the TCP banner path remains available.
func shouldCollectHTTPEvidence(port int, service string) bool {
	service = strings.ToLower(strings.TrimSpace(service))
	return port == 80 || port == 443 || strings.Contains(service, "http") || service == "" || service == "unknown"
}

func fingerprintProtocol(port int, service string) fingerprint.Protocol {
	service = strings.ToLower(strings.TrimSpace(service))
	if port == 443 || strings.Contains(service, "https") {
		return fingerprint.ProtocolHTTPS
	}
	if port == 80 || strings.Contains(service, "http") {
		return fingerprint.ProtocolHTTP
	}
	return fingerprint.ProtocolTCP
}

func runPlannedValidation(ctx context.Context, ip string, ports []model.ScanResult, currentFingerprints []model.AssetFingerprint, templates string, runFallback func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error), runPaths func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error)) ([]model.NucleiFinding, []model.ScanTaskRunTemplateCandidate, error) {
	var root string
	var index planner.TemplateIndex
	var err error
	indexLoaded := false
	findings := make([]model.NucleiFinding, 0)
	candidates := make([]model.ScanTaskRunTemplateCandidate, 0)
	for _, port := range ports {
		if !port.Open {
			continue
		}
		number, protocol, ok := fingerprintPort(port)
		if !ok {
			continue
		}
		fingerprints := currentPortFingerprints(currentFingerprints, ip, number, protocol)
		if len(fingerprints) > 0 && !indexLoaded {
			root, err = vuln.ResolveNucleiTemplatesPath(templates)
			if err != nil {
				return nil, nil, err
			}
			index, err = planner.BuildNucleiTemplateIndex(root)
			if err != nil {
				return nil, nil, err
			}
			indexLoaded = true
		}
		if indexLoaded {
			planned := planner.PlanFingerprintCandidates(fingerprints, index, planner.DefaultTemplateSafetyPolicy(), planner.DefaultFingerprintConfidenceThreshold)
			if len(planned) > 0 {
				paths := make([]string, 0, len(planned))
				for _, item := range planned {
					paths = append(paths, item.Path)
					candidates = append(candidates, model.ScanTaskRunTemplateCandidate{TemplateID: item.TemplateID, Path: item.Path, Source: item.Source, Reason: item.FingerprintSource + ":" + item.FingerprintRule + " product=" + item.Product})
				}
				matched, err := runPaths(ctx, ip, []model.ScanResult{port}, root, paths)
				if err != nil {
					return nil, nil, err
				}
				findings = append(findings, matched...)
				continue
			}
		}
		groups := planner.TemplateGroupsForScanResults([]model.ScanResult{port})
		if len(groups) == 0 {
			continue
		}
		matched, err := runFallback(ctx, ip, []model.ScanResult{port}, templates, groups)
		if err != nil {
			return nil, nil, err
		}
		findings = append(findings, matched...)
		candidates = append(candidates, serviceFallbackCandidates(groups)...)
	}
	return findings, candidates, nil
}

func currentPortFingerprints(records []model.AssetFingerprint, ip string, port int, protocol string) []model.AssetFingerprint {
	result := make([]model.AssetFingerprint, 0)
	for _, record := range records {
		if record.IP != ip || record.Port != port || (protocol != "" && record.Protocol != protocol) {
			continue
		}
		result = append(result, record)
	}
	return result
}

func fingerprintPort(port model.ScanResult) (int, string, bool) {
	_, portText, err := net.SplitHostPort(port.Address)
	if err != nil {
		return 0, "", false
	}
	var number int
	if _, err := fmt.Sscanf(portText, "%d", &number); err != nil || number <= 0 {
		return 0, "", false
	}
	service := strings.ToLower(strings.TrimSpace(port.Service))
	if service == "" || service == "unknown" {
		return number, "", true
	}
	return number, string(fingerprintProtocol(number, service)), true
}

func serviceFallbackCandidates(groups []string) []model.ScanTaskRunTemplateCandidate {
	result := make([]model.ScanTaskRunTemplateCandidate, 0, len(groups))
	for _, group := range groups {
		result = append(result, model.ScanTaskRunTemplateCandidate{TemplateID: "tag:" + group, Path: "service-tag", Source: "service_tag", Reason: "v1 service label fallback"})
	}
	return result
}

func uniqueTemplateCandidates(input []model.ScanTaskRunTemplateCandidate) []model.ScanTaskRunTemplateCandidate {
	seen := map[string]model.ScanTaskRunTemplateCandidate{}
	for _, item := range input {
		seen[item.TemplateID+"\x00"+item.Path] = item
	}
	result := make([]model.ScanTaskRunTemplateCandidate, 0, len(seen))
	for _, item := range seen {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TemplateID < result[j].TemplateID })
	return result
}

func runSubnet(ctx context.Context, options SubnetRunOptions, dependencies subnetDependencies) (model.TaskChangeSummary, error) {
	if options.DB == nil {
		return model.TaskChangeSummary{}, errors.New("subnet task database is required")
	}
	if options.TaskID <= 0 {
		return model.TaskChangeSummary{}, fmt.Errorf("invalid task ID: %d", options.TaskID)
	}
	options.CIDR = strings.TrimSpace(options.CIDR)
	if !pipeline.IsIPv4CIDR(options.CIDR) {
		return model.TaskChangeSummary{}, fmt.Errorf("invalid IPv4 CIDR: %s", options.CIDR)
	}
	if strings.TrimSpace(options.Network) == "" {
		options.Network = "tcp"
	}
	if dependencies.discover == nil || dependencies.scanHost == nil || dependencies.runNuclei == nil || dependencies.saveFindings == nil {
		return model.TaskChangeSummary{}, errors.New("subnet task dependencies are required")
	}
	if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
		return model.TaskChangeSummary{}, err
	}
	if err := updateProgress(options.UpdateProgress, 10); err != nil {
		return model.TaskChangeSummary{}, err
	}

	scope := "subnet:" + options.CIDR
	beforeHosts, err := storage.ListHostScopeMemberships(options.DB, storage.HostScopeMembershipQuery{Scope: scope})
	if err != nil {
		return model.TaskChangeSummary{}, err
	}
	beforePorts, err := storage.ListScopeActivePorts(options.DB, scope)
	if err != nil {
		return model.TaskChangeSummary{}, err
	}

	aliveHosts, err := dependencies.discover(ctx, options.CIDR, options.DiscoveryOptions)
	if err != nil {
		return model.TaskChangeSummary{}, err
	}
	if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
		return model.TaskChangeSummary{}, err
	}
	if err := storage.SyncHostInventory(options.DB, scope, aliveHosts); err != nil {
		return model.TaskChangeSummary{}, err
	}
	afterHosts, err := storage.ListHostScopeMemberships(options.DB, storage.HostScopeMembershipQuery{Scope: scope})
	if err != nil {
		return model.TaskChangeSummary{}, err
	}

	summary := model.TaskChangeSummary{
		TaskID:      options.TaskID,
		Target:      options.CIDR,
		HostChanges: diff.CompareScopeMembers(beforeHosts, afterHosts),
		PortChanges: model.PortChanges{Opened: []model.PortChange{}, Closed: []model.PortChange{}},
	}
	if len(aliveHosts) == 0 {
		if err := storage.DeactivateScopePortsForInactiveHosts(options.DB, scope); err != nil {
			return model.TaskChangeSummary{}, err
		}
		afterPorts, err := storage.ListScopeActivePorts(options.DB, scope)
		if err != nil {
			return model.TaskChangeSummary{}, err
		}
		summary.PortChanges = diff.ComparePorts(beforePorts, afterPorts)
		if err := storage.SaveTaskChangeSummary(options.DB, summary); err != nil {
			return model.TaskChangeSummary{}, err
		}
		if err := updateProgress(options.UpdateProgress, 100); err != nil {
			return model.TaskChangeSummary{}, err
		}
		return summary, nil
	}

	for index, ip := range aliveHosts {
		if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
			return model.TaskChangeSummary{}, err
		}

		openPorts, err := dependencies.scanHost(ctx, ip, options.Network)
		if err != nil {
			return model.TaskChangeSummary{}, err
		}
		if err := storage.SyncOpenPorts(options.DB, ip, openPorts); err != nil {
			return model.TaskChangeSummary{}, err
		}
		if err := storage.SyncScopeOpenPorts(options.DB, scope, ip, openPorts); err != nil {
			return model.TaskChangeSummary{}, err
		}

		if groups := planner.TemplateGroupsForScanResults(openPorts); options.EnableVulnerabilities && len(groups) > 0 {
			findings, err := dependencies.runNuclei(ctx, ip, openPorts, options.TemplatesPath, groups)
			if err != nil {
				return model.TaskChangeSummary{}, err
			}
			if err := dependencies.saveFindings(options.DB, options.TaskID, findings); err != nil {
				return model.TaskChangeSummary{}, err
			}
		}

		progress := 20 + int(float64(index+1)/float64(len(aliveHosts))*80)
		if err := updateProgress(options.UpdateProgress, progress); err != nil {
			return model.TaskChangeSummary{}, err
		}
	}

	if err := storage.DeactivateScopePortsForInactiveHosts(options.DB, scope); err != nil {
		return model.TaskChangeSummary{}, err
	}
	afterPorts, err := storage.ListScopeActivePorts(options.DB, scope)
	if err != nil {
		return model.TaskChangeSummary{}, err
	}
	summary.PortChanges = diff.ComparePorts(beforePorts, afterPorts)
	if err := storage.SaveTaskChangeSummary(options.DB, summary); err != nil {
		return model.TaskChangeSummary{}, err
	}
	return summary, nil
}

func checkCanceled(ctx context.Context, check func() (bool, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if check == nil {
		return nil
	}
	canceled, err := check()
	if err != nil {
		return err
	}
	if canceled {
		return ErrCanceled
	}
	return nil
}

func updateProgress(update func(int) error, progress int) error {
	if update == nil {
		return nil
	}
	return update(progress)
}

func portsFromResults(ip string, results []model.ScanResult) []int {
	ports := make([]int, 0, len(results))
	seen := make(map[int]struct{}, len(results))
	for _, result := range results {
		if !result.Open {
			continue
		}
		host, portText, err := net.SplitHostPort(result.Address)
		if err != nil || host != ip {
			continue
		}
		var port int
		if _, err := fmt.Sscanf(portText, "%d", &port); err != nil || port < 1 || port > 65535 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func snapshotHosts(ips []string) []model.ScanTaskRunHost {
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if net.ParseIP(strings.TrimSpace(ip)) != nil {
			seen[ip] = struct{}{}
		}
	}
	hosts := make([]model.ScanTaskRunHost, 0, len(seen))
	for ip := range seen {
		hosts = append(hosts, model.ScanTaskRunHost{IP: ip, IsActive: true})
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].IP < hosts[j].IP })
	return hosts
}

func snapshotPorts(ip string, results []model.ScanResult) []model.ScanTaskRunPort {
	ports := make([]model.ScanTaskRunPort, 0, len(results))
	for _, result := range results {
		if !result.Open {
			continue
		}
		host, portText, err := net.SplitHostPort(result.Address)
		if err != nil || host != ip {
			continue
		}
		var port int
		if _, err := fmt.Sscanf(portText, "%d", &port); err != nil || port < 1 || port > 65535 {
			continue
		}
		serviceType := strings.TrimSpace(result.Service)
		if serviceType == "" {
			serviceType = "unknown"
		}
		ports = append(ports, model.ScanTaskRunPort{
			IP:          ip,
			Port:        port,
			ServiceType: serviceType,
			Product:     strings.TrimSpace(result.Product),
			Banner:      result.Banner,
		})
	}
	return ports
}

func uniqueSnapshotPorts(ports []model.ScanTaskRunPort) []model.ScanTaskRunPort {
	byKey := make(map[string]model.ScanTaskRunPort, len(ports))
	for _, port := range ports {
		key := fmt.Sprintf("%s:%d", port.IP, port.Port)
		if _, found := byKey[key]; !found {
			byKey[key] = port
		}
	}
	unique := make([]model.ScanTaskRunPort, 0, len(byKey))
	for _, port := range byKey {
		unique = append(unique, port)
	}
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].IP == unique[j].IP {
			return unique[i].Port < unique[j].Port
		}
		return unique[i].IP < unique[j].IP
	})
	return unique
}

func snapshotVulnerabilities(findings []model.NucleiFinding) []model.ScanTaskRunVulnerability {
	vulnerabilities := make([]model.ScanTaskRunVulnerability, 0, len(findings))
	for _, finding := range findings {
		target := firstNonEmptySnapshot(finding.Target, finding.MatchedAt, finding.Host, finding.TargetIP)
		if target == "" {
			continue
		}
		key := fmt.Sprintf("%s|%s|%s|%d", finding.TemplateID, target, finding.TargetIP, finding.TargetPort)
		vulnerabilities = append(vulnerabilities, model.ScanTaskRunVulnerability{
			FindingKey: key,
			TemplateID: strings.TrimSpace(finding.TemplateID),
			Name:       strings.TrimSpace(finding.Name),
			Severity:   strings.TrimSpace(finding.Severity),
			Target:     target,
			TargetIP:   strings.TrimSpace(finding.TargetIP),
			TargetPort: finding.TargetPort,
			MatchedAt:  strings.TrimSpace(finding.MatchedAt),
			Evidence:   finding.Evidence,
		})
	}
	return vulnerabilities
}

func uniqueSnapshotVulnerabilities(findings []model.ScanTaskRunVulnerability) []model.ScanTaskRunVulnerability {
	byKey := make(map[string]model.ScanTaskRunVulnerability, len(findings))
	for _, finding := range findings {
		if _, found := byKey[finding.FindingKey]; !found {
			byKey[finding.FindingKey] = finding
		}
	}
	unique := make([]model.ScanTaskRunVulnerability, 0, len(byKey))
	for _, finding := range byKey {
		unique = append(unique, finding)
	}
	sort.Slice(unique, func(i, j int) bool { return unique[i].FindingKey < unique[j].FindingKey })
	return unique
}

func firstNonEmptySnapshot(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
