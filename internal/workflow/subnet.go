package workflow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"golandproject/yscan/internal/diff"
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
	scanSelected        func(context.Context, string, string, []int) ([]model.ScanResult, error)
	collectFingerprints func(context.Context, *sql.DB, model.ScanTaskRun, string, []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error)
	runNuclei           func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error)
	executeNuclei       func(context.Context, string, []model.ScanResult, string, []string) vuln.NucleiExecutionResult
	saveFindings        func(*sql.DB, int64, []model.NucleiFinding) error
}

// RunSubnet executes discovery, quick profiling, optional vulnerability
// validation, and persists a task-level change summary.
func RunSubnet(ctx context.Context, options SubnetRunOptions) (model.TaskChangeSummary, error) {
	return runSubnet(ctx, options, subnetDependencies{
		discover:     pipeline.DiscoverAliveHosts,
		scanHost:     scan.RunQuick,
		runNuclei:    vuln.RunNucleiForOpenPortsWithTags,
		saveFindings: storage.SaveNucleiFindings,
	})
}

// RunSubnetTaskRun scans one v2 subnet run and returns only the immutable
// observations for that run. Inventory updates remain current-state data;
// they are deliberately not used as the run Diff baseline.
func RunSubnetTaskRun(ctx context.Context, options SubnetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
	if options.DB == nil {
		return model.ScanTaskRunSnapshot{}, errors.New("subnet task run database is required")
	}
	if options.Run.ID <= 0 || options.Run.ScanTaskID <= 0 || options.Run.ScanType != model.ScanTypeSubnet {
		return model.ScanTaskRunSnapshot{}, errors.New("invalid subnet scan task run")
	}
	collector, err := newRunFingerprintCollector(options.DB, options.Run)
	if err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	return runSubnetTaskRun(ctx, options, subnetDependencies{
		discover:            pipeline.DiscoverAliveHosts,
		scanHost:            scan.RunQuickDiscovery,
		scanSelected:        scan.RunSelectedDiscovery,
		collectFingerprints: collector,
		runNuclei:           vuln.RunNucleiForOpenPortsWithTags,
		executeNuclei:       vuln.ExecuteNucleiForOpenPortsWithTags,
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
	if dependencies.discover == nil || dependencies.scanHost == nil || (dependencies.runNuclei == nil && dependencies.executeNuclei == nil) {
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
	snapshot := model.ScanTaskRunSnapshot{
		RunID:              options.Run.ID,
		Hosts:              snapshotHosts(aliveHosts),
		Ports:              make([]model.ScanTaskRunPort, 0),
		ProtocolEvidence:   make([]model.ScanTaskRunProtocolEvidence, 0),
		Vulnerabilities:    make([]model.ScanTaskRunVulnerability, 0),
		FingerprintMatches: make([]model.FingerprintRunMatch, 0),
		Validation:         initialRunValidation(options.Run.Config.VulnerabilityOn),
	}
	var validation *runValidationTracker
	if options.Run.Config.VulnerabilityOn {
		validation = newRunValidationTracker()
	}
	if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
		return snapshot, err
	}
	scope := "subnet:" + cidr
	if err := storage.SyncHostInventory(options.DB, scope, aliveHosts); err != nil {
		return snapshot, err
	}
	configuredPorts, err := scan.ParsePortSpec(options.Run.Config.PortSpec)
	if err != nil {
		return snapshot, fmt.Errorf("invalid run port_spec: %w", err)
	}
	coveragePorts := scan.InternalBaselinePorts()
	if len(configuredPorts) > 0 {
		coveragePorts = configuredPorts
	}
	portCoverage := storage.SelectedPortScanCoverage(coveragePorts)
	if len(aliveHosts) == 0 {
		if err := storage.DeactivateScopePortsForInactiveHosts(options.DB, scope); err != nil {
			return snapshot, err
		}
		if err := updateProgress(options.UpdateProgress, 100); err != nil {
			return snapshot, err
		}
		if validation != nil {
			validation.finish(&snapshot, nil)
		}
		return snapshot, nil
	}

	for index, ip := range aliveHosts {
		if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
			return snapshot, err
		}
		var openPorts []model.ScanResult
		if len(configuredPorts) > 0 {
			if dependencies.scanSelected == nil {
				return snapshot, errors.New("selected port scan dependency is required")
			}
			openPorts, err = dependencies.scanSelected(ctx, ip, options.Network, configuredPorts)
		} else {
			openPorts, err = dependencies.scanHost(ctx, ip, options.Network)
		}
		if err != nil {
			snapshot.Ports = uniqueSnapshotPorts(append(snapshot.Ports, snapshotPorts(ip, openPorts)...))
			snapshot.ProtocolEvidence = uniqueProtocolEvidence(append(snapshot.ProtocolEvidence, snapshotProtocolEvidence(ip, openPorts)...))
			return snapshot, err
		}
		if dependencies.collectFingerprints != nil {
			var matches []model.FingerprintRunMatch
			openPorts, matches, err = dependencies.collectFingerprints(ctx, options.DB, options.Run, ip, openPorts)
			snapshot.Ports = append(snapshot.Ports, snapshotPorts(ip, openPorts)...)
			snapshot.ProtocolEvidence = append(snapshot.ProtocolEvidence, snapshotProtocolEvidence(ip, openPorts)...)
			snapshot.FingerprintMatches = append(snapshot.FingerprintMatches, matches...)
			if err != nil {
				return snapshot, err
			}
		}
		if err := storage.SyncOpenPorts(options.DB, ip, openPorts, portCoverage); err != nil {
			return snapshot, err
		}
		if err := storage.SyncScopeOpenPorts(options.DB, scope, ip, openPorts, portCoverage); err != nil {
			return snapshot, err
		}
		if dependencies.collectFingerprints == nil {
			snapshot.Ports = append(snapshot.Ports, snapshotPorts(ip, openPorts)...)
			snapshot.ProtocolEvidence = append(snapshot.ProtocolEvidence, snapshotProtocolEvidence(ip, openPorts)...)
		}

		if options.Run.Config.VulnerabilityOn {
			mappingResult := runFingerprintMappingValidation(ctx, options.DB, options.Run, ip, openPorts, snapshot.FingerprintMatches, options.Run.Config.NucleiTemplates)
			validation.observe(mappingResult)
			snapshot.TemplateCandidates = uniqueTemplateCandidates(append(snapshot.TemplateCandidates, mappingResult.candidates...))
			snapshot.Vulnerabilities = uniqueSnapshotVulnerabilities(append(snapshot.Vulnerabilities, snapshotVulnerabilities(mappingResult.findings)...))
			if mappingResult.err != nil && !errors.Is(mappingResult.err, vuln.ErrNoTemplates) {
				validation.finish(&snapshot, mappingResult.err)
				return snapshot, mappingResult.err
			}
			fallbackResult := runServiceTagValidation(ctx, ip, portsWithoutFingerprintMappings(openPorts, mappingResult.candidates), options.Run.Config.NucleiTemplates, nucleiExecutionDependency(dependencies.executeNuclei, dependencies.runNuclei))
			validation.observe(fallbackResult)
			allCandidates := append(mappingResult.candidates, fallbackResult.candidates...)
			allFindings := append(mappingResult.findings, fallbackResult.findings...)
			snapshot.TemplateCandidates = uniqueTemplateCandidates(append(snapshot.TemplateCandidates, allCandidates...))
			snapshot.Vulnerabilities = uniqueSnapshotVulnerabilities(append(snapshot.Vulnerabilities, snapshotVulnerabilities(allFindings)...))
			if fallbackResult.err != nil && !errors.Is(fallbackResult.err, vuln.ErrNoTemplates) {
				validation.finish(&snapshot, fallbackResult.err)
				return snapshot, fallbackResult.err
			}
		}
		progress := 20 + int(float64(index+1)/float64(len(aliveHosts))*80)
		if err := updateProgress(options.UpdateProgress, progress); err != nil {
			return snapshot, err
		}
	}
	if err := storage.DeactivateScopePortsForInactiveHosts(options.DB, scope); err != nil {
		return snapshot, err
	}
	snapshot.Ports = uniqueSnapshotPorts(snapshot.Ports)
	snapshot.ProtocolEvidence = uniqueProtocolEvidence(snapshot.ProtocolEvidence)
	snapshot.Vulnerabilities = uniqueSnapshotVulnerabilities(snapshot.Vulnerabilities)
	snapshot.TemplateCandidates = uniqueTemplateCandidates(snapshot.TemplateCandidates)
	if validation != nil {
		validation.finish(&snapshot, nil)
	}
	return snapshot, nil
}

// runFingerprintMappingValidation executes only approved, content-pinned
// templates justified by this run's endpoint conclusions. It deliberately
// does not read historical fingerprint results.
type validationExecutionResult struct {
	findings          []model.NucleiFinding
	candidates        []model.ScanTaskRunTemplateCandidate
	executedEndpoints map[string]struct{}
	err               error
}

func (result *validationExecutionResult) markExecuted(candidates []model.ScanTaskRunTemplateCandidate) {
	if result.executedEndpoints == nil {
		result.executedEndpoints = make(map[string]struct{})
	}
	for _, candidate := range candidates {
		if endpoint := validationEndpointKey(candidate); endpoint != "" {
			result.executedEndpoints[endpoint] = struct{}{}
		}
	}
}

func runFingerprintMappingValidation(ctx context.Context, db *sql.DB, run model.ScanTaskRun, ip string, ports []model.ScanResult, matches []model.FingerprintRunMatch, templatesRoot string) validationExecutionResult {
	result := validationExecutionResult{}
	noTemplates := false
	for _, portResult := range ports {
		if !portResult.Open {
			continue
		}
		_, portText, err := net.SplitHostPort(portResult.Address)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			continue
		}
		for _, protocol := range []string{"https", "http", "tcp"} {
			mappings, err := storage.ListApprovedTemplateMappingsForMatches(db, run.ID, ip, port, protocol, matches)
			if err != nil {
				result.err = err
				return result
			}
			if len(mappings) == 0 {
				continue
			}
			resolved, err := planner.ResolveReviewedTemplateCandidates(templatesRoot, mappings)
			if err != nil {
				result.err = err
				return result
			}
			paths := make([]string, 0, len(resolved))
			invocationCandidates := make([]model.ScanTaskRunTemplateCandidate, 0, len(resolved))
			for _, candidate := range resolved {
				paths = append(paths, candidate.AbsolutePath)
				invocationCandidates = append(invocationCandidates, model.ScanTaskRunTemplateCandidate{TemplateID: candidate.Mapping.TemplateID, Path: candidate.Mapping.TemplatePath, Source: "fingerprint_mapping", Reason: fmt.Sprintf("approved fingerprint mapping %s", candidate.Mapping.ProductKey), TemplateSHA256: candidate.Mapping.TemplateSHA256, TemplateSetRevision: candidate.Mapping.TemplateSetRevision, MappingImportID: candidate.Mapping.TemplateMappingImportID, IP: ip, Port: port, Protocol: protocol})
			}
			result.candidates = append(result.candidates, invocationCandidates...)
			if len(paths) > 0 {
				execution := vuln.ExecuteNucleiForOpenPortsWithTemplatePaths(ctx, ip, []model.ScanResult{portResult}, paths)
				result.findings = append(result.findings, execution.Findings...)
				if execution.Executed {
					result.markExecuted(invocationCandidates)
				}
				err := execution.Err
				if err == nil {
					continue
				}
				if errors.Is(err, vuln.ErrNoTemplates) {
					noTemplates = true
					continue
				}
				if err != nil {
					result.err = err
					return result
				}
			}
		}
	}
	if noTemplates {
		result.err = vuln.ErrNoTemplates
	}
	return result
}

func portsWithoutFingerprintMappings(ports []model.ScanResult, candidates []model.ScanTaskRunTemplateCandidate) []model.ScanResult {
	covered := make(map[string]struct{})
	for _, candidate := range candidates {
		if candidate.Source != "fingerprint_mapping" {
			continue
		}
		if candidate.IP != "" && candidate.Port > 0 && candidate.Protocol != "" {
			covered[fmt.Sprintf("%s:%d:%s", candidate.IP, candidate.Port, candidate.Protocol)] = struct{}{}
		}
	}
	result := make([]model.ScanResult, 0, len(ports))
	for _, port := range ports {
		host, value, err := net.SplitHostPort(port.Address)
		if err == nil {
			portNumber, _ := strconv.Atoi(value)
			if _, ok := covered[fmt.Sprintf("%s:%d:%s", host, portNumber, candidateProtocolForService(port.Service))]; ok {
				continue
			}
		}
		result = append(result, port)
	}
	return result
}

func runServiceTagValidation(ctx context.Context, ip string, ports []model.ScanResult, templates string, runNuclei func(context.Context, string, []model.ScanResult, string, []string) vuln.NucleiExecutionResult) validationExecutionResult {
	result := validationExecutionResult{}
	noTemplates := false
	for _, port := range ports {
		if !port.Open {
			continue
		}
		groups := planner.TemplateGroupsForScanResults([]model.ScanResult{port})
		if len(groups) == 0 {
			continue
		}
		_, portText, _ := net.SplitHostPort(port.Address)
		portNumber, _ := strconv.Atoi(portText)
		invocationCandidates := serviceFallbackCandidates(ip, portNumber, candidateProtocolForService(port.Service), groups)
		result.candidates = append(result.candidates, invocationCandidates...)
		execution := runNuclei(ctx, ip, []model.ScanResult{port}, templates, groups)
		result.findings = append(result.findings, execution.Findings...)
		if execution.Executed {
			result.markExecuted(invocationCandidates)
		}
		err := execution.Err
		if err == nil {
			continue
		}
		if errors.Is(err, vuln.ErrNoTemplates) {
			noTemplates = true
			continue
		}
		if err != nil {
			result.err = err
			return result
		}
	}
	if noTemplates {
		result.err = vuln.ErrNoTemplates
	}
	return result
}

func nucleiExecutionDependency(
	execute func(context.Context, string, []model.ScanResult, string, []string) vuln.NucleiExecutionResult,
	legacy func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error),
) func(context.Context, string, []model.ScanResult, string, []string) vuln.NucleiExecutionResult {
	if execute != nil {
		return execute
	}
	return func(ctx context.Context, ip string, ports []model.ScanResult, templates string, tags []string) vuln.NucleiExecutionResult {
		findings, err := legacy(ctx, ip, ports, templates, tags)
		return vuln.NucleiExecutionResult{Findings: findings, Started: true, Executed: err == nil || len(findings) > 0, Err: err}
	}
}

type runValidationTracker struct {
	startedAt  time.Time
	candidates map[string]struct{}
	templates  map[string]struct{}
	executed   map[string]struct{}
}

func initialRunValidation(enabled bool) model.ScanTaskRunValidation {
	status := model.ScanTaskRunValidationDisabled
	if enabled {
		status = model.ScanTaskRunValidationNotStarted
	}
	return model.ScanTaskRunValidation{Status: status}
}

func newRunValidationTracker() *runValidationTracker {
	return &runValidationTracker{
		startedAt: time.Now().UTC(), candidates: make(map[string]struct{}),
		templates: make(map[string]struct{}), executed: make(map[string]struct{}),
	}
}

func (tracker *runValidationTracker) observe(result validationExecutionResult) {
	if tracker == nil {
		return
	}
	for _, candidate := range result.candidates {
		endpoint := validationEndpointKey(candidate)
		if endpoint != "" {
			tracker.candidates[endpoint] = struct{}{}
		}
		tracker.templates[candidate.TemplateID+"\x00"+candidate.Path] = struct{}{}
	}
	for endpoint := range result.executedEndpoints {
		tracker.executed[endpoint] = struct{}{}
	}
}

func (tracker *runValidationTracker) finish(snapshot *model.ScanTaskRunSnapshot, executionErr error) {
	if tracker == nil || snapshot == nil {
		return
	}
	validation := model.ScanTaskRunValidation{
		Status:                 model.ScanTaskRunValidationNoCandidates,
		CandidateEndpointCount: len(tracker.candidates),
		ExecutedEndpointCount:  len(tracker.executed),
		TemplateCount:          len(tracker.templates),
		FindingCount:           len(snapshot.Vulnerabilities),
		StartedAt:              tracker.startedAt.Format(time.RFC3339Nano),
		FinishedAt:             time.Now().UTC().Format(time.RFC3339Nano),
	}
	if executionErr != nil && !errors.Is(executionErr, vuln.ErrNoTemplates) {
		validation.Status = model.ScanTaskRunValidationFailed
		validation.Error = safeValidationError(executionErr)
	} else if len(tracker.executed) > 0 {
		validation.Status = model.ScanTaskRunValidationSuccess
	}
	snapshot.Validation = validation
}

func validationEndpointKey(candidate model.ScanTaskRunTemplateCandidate) string {
	if net.ParseIP(candidate.IP) == nil || candidate.Port < 1 || candidate.Protocol == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d/%s", candidate.IP, candidate.Port, strings.ToLower(candidate.Protocol))
}

func safeValidationError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.Join(strings.Fields(err.Error()), " ")
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func serviceFallbackCandidates(ip string, port int, protocol string, groups []string) []model.ScanTaskRunTemplateCandidate {
	result := make([]model.ScanTaskRunTemplateCandidate, 0, len(groups))
	for _, group := range groups {
		result = append(result, model.ScanTaskRunTemplateCandidate{TemplateID: "tag:" + group, Path: "service-tag", Source: "service_tag", Reason: "v1 service label fallback", IP: ip, Port: port, Protocol: protocol})
	}
	return result
}

func uniqueTemplateCandidates(input []model.ScanTaskRunTemplateCandidate) []model.ScanTaskRunTemplateCandidate {
	seen := map[string]model.ScanTaskRunTemplateCandidate{}
	for _, item := range input {
		seen[fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s", item.TemplateID, item.Path, item.IP, item.Port, item.Protocol)] = item
	}
	result := make([]model.ScanTaskRunTemplateCandidate, 0, len(seen))
	for _, item := range seen {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TemplateID < result[j].TemplateID })
	return result
}

func candidateProtocolForService(service string) string {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "http", "http-unknown":
		return "http"
	case "https":
		return "https"
	default:
		return "tcp"
	}
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
	portCoverage := storage.SelectedPortScanCoverage(scan.InternalBaselinePorts())
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
		if err := storage.SyncOpenPorts(options.DB, ip, openPorts, portCoverage); err != nil {
			return model.TaskChangeSummary{}, err
		}
		if err := storage.SyncScopeOpenPorts(options.DB, scope, ip, openPorts, portCoverage); err != nil {
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
		})
	}
	return ports
}

func snapshotProtocolEvidence(ip string, results []model.ScanResult) []model.ScanTaskRunProtocolEvidence {
	observations := make([]model.ScanTaskRunProtocolEvidence, 0)
	for _, result := range results {
		port, ok := scanResultPort(ip, result)
		if !ok {
			continue
		}
		for _, observation := range result.ProtocolEvidence {
			observation.IP = ip
			observation.Port = port
			observation.Protocol = strings.ToLower(strings.TrimSpace(observation.Protocol))
			observation.EvidenceType = strings.ToLower(strings.TrimSpace(observation.EvidenceType))
			observation.ProbeName = strings.TrimSpace(observation.ProbeName)
			if observation.EvidenceType == "" {
				if observation.Protocol == "http" || observation.Protocol == "https" {
					observation.EvidenceType = model.ProtocolEvidenceWeb
				} else {
					observation.EvidenceType = model.ProtocolEvidencePassiveBanner
				}
			}
			if observation.Protocol != "" {
				observations = append(observations, observation)
			}
		}
	}
	return observations
}

func uniqueProtocolEvidence(observations []model.ScanTaskRunProtocolEvidence) []model.ScanTaskRunProtocolEvidence {
	byKey := make(map[string]model.ScanTaskRunProtocolEvidence, len(observations))
	for _, observation := range observations {
		key := fmt.Sprintf("%s:%d/%s/%s/%s", observation.IP, observation.Port, observation.EvidenceType, observation.Protocol, observation.ProbeName)
		if existing, found := byKey[key]; !found || (!existing.Responded && observation.Responded) {
			byKey[key] = observation
		}
	}
	result := make([]model.ScanTaskRunProtocolEvidence, 0, len(byKey))
	for _, observation := range byKey {
		result = append(result, observation)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].IP != result[j].IP {
			return result[i].IP < result[j].IP
		}
		if result[i].Port != result[j].Port {
			return result[i].Port < result[j].Port
		}
		if result[i].EvidenceType != result[j].EvidenceType {
			return result[i].EvidenceType < result[j].EvidenceType
		}
		if result[i].Protocol != result[j].Protocol {
			return result[i].Protocol < result[j].Protocol
		}
		return result[i].ProbeName < result[j].ProbeName
	})
	return result
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
			FindingKey:  key,
			TemplateID:  strings.TrimSpace(finding.TemplateID),
			Name:        strings.TrimSpace(finding.Name),
			Severity:    strings.TrimSpace(finding.Severity),
			Target:      target,
			TargetIP:    strings.TrimSpace(finding.TargetIP),
			TargetPort:  finding.TargetPort,
			MatchedAt:   strings.TrimSpace(finding.MatchedAt),
			Description: safeProtocolLabel(finding.Description, 1024),
			Evidence:    finding.Evidence,
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
