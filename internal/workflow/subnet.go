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
	discover             func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error)
	scanHost             func(context.Context, string, string) ([]model.ScanResult, error)
	scanSelected         func(context.Context, string, string, []int) ([]model.ScanResult, error)
	collectFingerprints  func(context.Context, *sql.DB, model.ScanTaskRun, string, []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error)
	runNuclei            func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error)
	executeNuclei        func(context.Context, string, []model.ScanResult, string, []string) vuln.NucleiExecutionResult
	loadTemplateIndex    func(string) (string, *planner.NucleiTemplateIndex, error)
	executeTemplatePaths func(context.Context, string, []model.ScanResult, []string) vuln.NucleiExecutionResult
	saveFindings         func(*sql.DB, int64, []model.NucleiFinding) error
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
		discover:             pipeline.DiscoverAliveHosts,
		scanHost:             scan.RunQuickDiscovery,
		scanSelected:         scan.RunSelectedDiscovery,
		collectFingerprints:  collector,
		runNuclei:            vuln.RunNucleiForOpenPortsWithTags,
		executeNuclei:        vuln.ExecuteNucleiForOpenPortsWithTags,
		loadTemplateIndex:    loadNucleiTemplateIndex,
		executeTemplatePaths: vuln.ExecuteNucleiForOpenPortsWithTemplatePaths,
	})
}

func loadNucleiTemplateIndex(configuredPath string) (string, *planner.NucleiTemplateIndex, error) {
	root, err := vuln.ResolveNucleiTemplatesPath(configuredPath)
	if err != nil {
		return "", nil, err
	}
	index, err := planner.BuildNucleiTemplateIndex(root)
	if err != nil {
		return "", nil, err
	}
	return root, index, nil
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
	if dependencies.discover == nil || dependencies.scanHost == nil || (dependencies.runNuclei == nil && dependencies.executeNuclei == nil && dependencies.executeTemplatePaths == nil) {
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
	templateRoot := options.Run.Config.NucleiTemplates
	var templateIndex *planner.NucleiTemplateIndex
	templateIndexLoaded := false
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
		if err := storage.SyncOpenAndScopePorts(options.DB, scope, ip, openPorts, portCoverage); err != nil {
			return snapshot, err
		}
		if dependencies.collectFingerprints == nil {
			snapshot.Ports = append(snapshot.Ports, snapshotPorts(ip, openPorts)...)
			snapshot.ProtocolEvidence = append(snapshot.ProtocolEvidence, snapshotProtocolEvidence(ip, openPorts)...)
		}

		if options.Run.Config.VulnerabilityOn {
			validation.register(ip, openPorts, snapshot.FingerprintMatches)
			if dependencies.loadTemplateIndex != nil && !templateIndexLoaded {
				templateRoot, templateIndex, err = dependencies.loadTemplateIndex(options.Run.Config.NucleiTemplates)
				templateIndexLoaded = true
				if err != nil {
					validation.failAll(err)
					validation.finish(&snapshot, err)
					return snapshot, err
				}
			}
			mappingResult := runFingerprintMappingValidation(ctx, options.DB, options.Run, ip, openPorts, snapshot.FingerprintMatches, templateRoot, templateIndex, dependencies.executeTemplatePaths)
			validation.observe(mappingResult)
			snapshot.TemplateCandidates = uniqueTemplateCandidates(append(snapshot.TemplateCandidates, mappingResult.candidates...))
			snapshot.Vulnerabilities = uniqueSnapshotVulnerabilities(append(snapshot.Vulnerabilities, snapshotVulnerabilities(mappingResult.findings)...))
			if mappingResult.err != nil && !errors.Is(mappingResult.err, vuln.ErrNoTemplates) {
				validation.finish(&snapshot, mappingResult.err)
				return snapshot, mappingResult.err
			}
			fallbackResult := runServiceTagValidation(ctx, ip, portsWithoutFingerprintMappings(openPorts, mappingResult.candidates, snapshot.FingerprintMatches), templateIndex, dependencies.executeTemplatePaths)
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
	findings           []model.NucleiFinding
	candidates         []model.ScanTaskRunTemplateCandidate
	executedEndpoints  map[string]struct{}
	executedTemplates  map[string]struct{}
	identifiedProducts map[string]struct{}
	mappedProducts     map[string]struct{}
	endpointErrors     map[string]error
	attemptedEndpoints map[string]struct{}
	policyFiltered     map[string]struct{}
	err                error
}

func (result *validationExecutionResult) markExecuted(candidates []model.ScanTaskRunTemplateCandidate) {
	if result.executedEndpoints == nil {
		result.executedEndpoints = make(map[string]struct{})
	}
	if result.executedTemplates == nil {
		result.executedTemplates = make(map[string]struct{})
	}
	for _, candidate := range candidates {
		if endpoint := validationEndpointKey(candidate); endpoint != "" {
			result.executedEndpoints[endpoint] = struct{}{}
		}
		result.executedTemplates[candidate.TemplateID+"\x00"+candidate.Path] = struct{}{}
	}
}

func (result *validationExecutionResult) observeExecution(candidates []model.ScanTaskRunTemplateCandidate, execution vuln.NucleiExecutionResult) {
	if result.attemptedEndpoints == nil {
		result.attemptedEndpoints = make(map[string]struct{})
	}
	if result.endpointErrors == nil {
		result.endpointErrors = make(map[string]error)
	}
	endpoints := make(map[string]struct{})
	for _, candidate := range candidates {
		if endpoint := validationEndpointKey(candidate); endpoint != "" {
			endpoints[endpoint] = struct{}{}
		}
	}
	for endpoint := range endpoints {
		result.attemptedEndpoints[endpoint] = struct{}{}
		if execution.Err != nil {
			result.endpointErrors[endpoint] = execution.Err
		}
	}
	if execution.Executed {
		result.markExecuted(candidates)
	}
}

func runFingerprintMappingValidation(ctx context.Context, db *sql.DB, run model.ScanTaskRun, ip string, ports []model.ScanResult, matches []model.FingerprintRunMatch, templatesRoot string, templateIndex *planner.NucleiTemplateIndex, executeTemplatePaths func(context.Context, string, []model.ScanResult, []string) vuln.NucleiExecutionResult) validationExecutionResult {
	result := validationExecutionResult{identifiedProducts: make(map[string]struct{}), mappedProducts: make(map[string]struct{})}
	if executeTemplatePaths == nil {
		executeTemplatePaths = vuln.ExecuteNucleiForOpenPortsWithTemplatePaths
	}
	portResults := make(map[int]model.ScanResult)
	for _, portResult := range ports {
		if !portResult.Open {
			continue
		}
		_, portText, err := net.SplitHostPort(portResult.Address)
		port, parseErr := strconv.Atoi(portText)
		if err == nil && parseErr == nil {
			portResults[port] = portResult
		}
	}
	endpointProducts := make(map[string]model.FingerprintRunMatch)
	for _, match := range matches {
		if match.Soft || match.IP != ip || match.Product == "" {
			continue
		}
		if _, exists := portResults[match.Port]; !exists {
			continue
		}
		identity := validationProductIdentity(match.IP, match.Port, match.Protocol, match.Product)
		result.identifiedProducts[identity] = struct{}{}
		if current, exists := endpointProducts[identity]; !exists || (current.CPE == "" && match.CPE != "") {
			endpointProducts[identity] = match
		}
	}
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
			invocationCandidates := make([]model.ScanTaskRunTemplateCandidate, 0, len(mappings))
			for _, mapping := range mappings {
				invocationCandidates = append(invocationCandidates, model.ScanTaskRunTemplateCandidate{TemplateID: mapping.TemplateID, Path: mapping.TemplatePath, ProductKey: mapping.ProductKey, Source: "fingerprint_mapping", Reason: fmt.Sprintf("approved fingerprint mapping %s", mapping.ProductKey), TemplateSHA256: mapping.TemplateSHA256, TemplateSetRevision: mapping.TemplateSetRevision, MappingImportID: mapping.TemplateMappingImportID, IP: ip, Port: port, Protocol: protocol})
				result.mappedProducts[validationProductIdentity(ip, port, protocol, mapping.ProductKey)] = struct{}{}
			}
			resolved, err := planner.ResolveReviewedTemplateCandidates(templatesRoot, mappings)
			if err != nil {
				result.candidates = append(result.candidates, invocationCandidates...)
				result.observeExecution(invocationCandidates, vuln.NucleiExecutionResult{Err: err})
				continue
			}
			pinnedTemplates := make([]planner.PinnedNucleiTemplate, 0, len(resolved))
			for _, candidate := range resolved {
				pinnedTemplates = append(pinnedTemplates, candidate.Pinned)
			}
			if len(pinnedTemplates) > 0 {
				execution := executePinnedNucleiTemplates(ctx, ip, []model.ScanResult{portResult}, pinnedTemplates, executeTemplatePaths)
				result.findings = append(result.findings, execution.Findings...)
				if execution.Executed {
					markTemplateCandidatesExecuted(invocationCandidates)
				}
				result.observeExecution(invocationCandidates, execution)
			}
			result.candidates = append(result.candidates, invocationCandidates...)
		}
	}
	if templateIndex != nil {
		type automaticInvocation struct {
			port       model.ScanResult
			templates  []planner.PinnedNucleiTemplate
			candidates []model.ScanTaskRunTemplateCandidate
			seen       map[string]struct{}
		}
		invocations := make(map[string]*automaticInvocation)
		productIdentities := make([]string, 0, len(endpointProducts))
		for identity := range endpointProducts {
			productIdentities = append(productIdentities, identity)
		}
		sort.Strings(productIdentities)
		for _, identity := range productIdentities {
			match := endpointProducts[identity]
			if _, reviewed := result.mappedProducts[identity]; reviewed {
				continue
			}
			selected := templateIndex.Select(match.Product, match.CPE, match.Protocol)
			if len(selected) == 0 {
				if templateIndex.PolicyFiltered(match.Product, match.CPE, match.Protocol) {
					if result.policyFiltered == nil {
						result.policyFiltered = make(map[string]struct{})
					}
					result.policyFiltered[validationEndpointIdentity(match.IP, match.Port, match.Protocol)] = struct{}{}
				}
				continue
			}
			result.mappedProducts[identity] = struct{}{}
			invocationKey := fmt.Sprintf("%d/%s", match.Port, strings.ToLower(match.Protocol))
			invocation := invocations[invocationKey]
			if invocation == nil {
				invocation = &automaticInvocation{port: portResults[match.Port], seen: make(map[string]struct{})}
				invocations[invocationKey] = invocation
			}
			for _, entry := range selected {
				entryKey := entry.TemplateID + "\x00" + entry.Path
				if _, duplicate := invocation.seen[entryKey]; !duplicate {
					invocation.seen[entryKey] = struct{}{}
					invocation.templates = append(invocation.templates, entry.PinnedTemplate())
				}
				invocation.candidates = append(invocation.candidates, model.ScanTaskRunTemplateCandidate{
					TemplateID: entry.TemplateID, Path: entry.Path, ProductKey: match.Product,
					Source: "automatic_template_index", Reason: "normalized product, CPE, or exact product tag",
					TemplateSHA256: entry.SHA256, TemplateSetRevision: templateIndex.Revision,
					IP: ip, Port: match.Port, Protocol: match.Protocol,
				})
			}
		}
		invocationKeys := make([]string, 0, len(invocations))
		for key := range invocations {
			invocationKeys = append(invocationKeys, key)
		}
		sort.Strings(invocationKeys)
		for _, key := range invocationKeys {
			invocation := invocations[key]
			execution := executePinnedNucleiTemplates(ctx, ip, []model.ScanResult{invocation.port}, invocation.templates, executeTemplatePaths)
			result.findings = append(result.findings, execution.Findings...)
			if execution.Executed {
				markTemplateCandidatesExecuted(invocation.candidates)
			}
			result.observeExecution(invocation.candidates, execution)
			result.candidates = append(result.candidates, invocation.candidates...)
		}
	}
	return result
}

func executePinnedNucleiTemplates(ctx context.Context, ip string, ports []model.ScanResult, templates []planner.PinnedNucleiTemplate, execute func(context.Context, string, []model.ScanResult, []string) vuln.NucleiExecutionResult) vuln.NucleiExecutionResult {
	snapshot, err := planner.MaterializePinnedNucleiTemplates(templates)
	if err != nil {
		return vuln.NucleiExecutionResult{Err: err}
	}
	defer snapshot.Close()
	return execute(ctx, ip, ports, snapshot.Paths)
}

func validationProductIdentity(ip string, port int, protocol, product string) string {
	return fmt.Sprintf("%s:%d/%s product=%s", ip, port, strings.ToLower(strings.TrimSpace(protocol)), strings.ToLower(strings.TrimSpace(product)))
}

func validationEndpointIdentity(ip string, port int, protocol string) string {
	return fmt.Sprintf("%s:%d/%s", ip, port, strings.ToLower(strings.TrimSpace(protocol)))
}

func markTemplateCandidatesExecuted(candidates []model.ScanTaskRunTemplateCandidate) {
	for index := range candidates {
		candidates[index].Executed = true
	}
}

func portsWithoutFingerprintMappings(ports []model.ScanResult, candidates []model.ScanTaskRunTemplateCandidate, matches ...[]model.FingerprintRunMatch) []model.ScanResult {
	covered := make(map[string]struct{})
	for _, candidate := range candidates {
		if candidate.Source != "fingerprint_mapping" && candidate.Source != "automatic_template_index" {
			continue
		}
		if candidate.IP != "" && candidate.Port > 0 && candidate.Protocol != "" {
			covered[fmt.Sprintf("%s:%d:%s", candidate.IP, candidate.Port, candidate.Protocol)] = struct{}{}
		}
	}
	identifiedPorts := make(map[string]struct{})
	for _, group := range matches {
		for _, match := range group {
			if !match.Soft && match.Product != "" {
				identifiedPorts[fmt.Sprintf("%s:%d", match.IP, match.Port)] = struct{}{}
			}
		}
	}
	result := make([]model.ScanResult, 0, len(ports))
	for _, port := range ports {
		host, value, err := net.SplitHostPort(port.Address)
		if err == nil {
			portNumber, _ := strconv.Atoi(value)
			if _, ok := identifiedPorts[fmt.Sprintf("%s:%d", host, portNumber)]; ok {
				continue
			}
			if _, ok := covered[fmt.Sprintf("%s:%d:%s", host, portNumber, candidateProtocolForService(port.Service))]; ok {
				continue
			}
		}
		result = append(result, port)
	}
	return result
}

func runServiceTagValidation(ctx context.Context, ip string, ports []model.ScanResult, templateIndex *planner.NucleiTemplateIndex, executeTemplatePaths func(context.Context, string, []model.ScanResult, []string) vuln.NucleiExecutionResult) validationExecutionResult {
	result := validationExecutionResult{}
	if templateIndex == nil {
		return result
	}
	if executeTemplatePaths == nil {
		executeTemplatePaths = vuln.ExecuteNucleiForOpenPortsWithTemplatePaths
	}
	for _, port := range ports {
		if !port.Open {
			continue
		}
		_, portText, _ := net.SplitHostPort(port.Address)
		portNumber, _ := strconv.Atoi(portText)
		protocol := candidateProtocolForService(port.Service)
		selected := templateIndex.Select(port.Service, "", protocol)
		if len(selected) == 0 {
			if templateIndex.PolicyFiltered(port.Service, "", protocol) {
				if result.policyFiltered == nil {
					result.policyFiltered = make(map[string]struct{})
				}
				result.policyFiltered[validationEndpointIdentity(ip, portNumber, protocol)] = struct{}{}
			}
			continue
		}
		pinned := make([]planner.PinnedNucleiTemplate, 0, len(selected))
		invocationCandidates := make([]model.ScanTaskRunTemplateCandidate, 0, len(selected))
		for _, entry := range selected {
			pinned = append(pinned, entry.PinnedTemplate())
			invocationCandidates = append(invocationCandidates, model.ScanTaskRunTemplateCandidate{
				TemplateID: entry.TemplateID, Path: entry.Path, ProductKey: strings.ToLower(strings.TrimSpace(port.Service)),
				Source: "service_tag", Reason: "strict reviewed service product selector",
				TemplateSHA256: entry.SHA256, TemplateSetRevision: templateIndex.Revision,
				IP: ip, Port: portNumber, Protocol: protocol,
			})
		}
		execution := executePinnedNucleiTemplates(ctx, ip, []model.ScanResult{port}, pinned, executeTemplatePaths)
		result.findings = append(result.findings, execution.Findings...)
		if execution.Executed {
			markTemplateCandidatesExecuted(invocationCandidates)
		}
		result.observeExecution(invocationCandidates, execution)
		result.candidates = append(result.candidates, invocationCandidates...)
	}
	return result
}

type runValidationTracker struct {
	startedAt          time.Time
	candidates         map[string]struct{}
	templates          map[string]struct{}
	executed           map[string]struct{}
	executedTemplates  map[string]struct{}
	identifiedProducts map[string]struct{}
	mappedProducts     map[string]struct{}
	endpoints          map[string]*endpointValidationTracker
}

type endpointValidationTracker struct {
	ip, protocol                  string
	port                          int
	identified, mapped            map[string]struct{}
	candidates, executedTemplates map[string]struct{}
	findingKeys                   map[string]struct{}
	attempted, policyFiltered     bool
	err                           error
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
		templates: make(map[string]struct{}), executed: make(map[string]struct{}), executedTemplates: make(map[string]struct{}),
		identifiedProducts: make(map[string]struct{}), mappedProducts: make(map[string]struct{}),
		endpoints: make(map[string]*endpointValidationTracker),
	}
}

func (tracker *runValidationTracker) endpoint(ip string, port int, protocol string) *endpointValidationTracker {
	key := validationEndpointIdentity(ip, port, protocol)
	state := tracker.endpoints[key]
	if state == nil {
		state = &endpointValidationTracker{
			ip: ip, port: port, protocol: strings.ToLower(strings.TrimSpace(protocol)),
			identified: make(map[string]struct{}), mapped: make(map[string]struct{}),
			candidates: make(map[string]struct{}), executedTemplates: make(map[string]struct{}), findingKeys: make(map[string]struct{}),
		}
		tracker.endpoints[key] = state
	}
	return state
}

func (tracker *runValidationTracker) register(ip string, ports []model.ScanResult, matches []model.FingerprintRunMatch) {
	if tracker == nil {
		return
	}
	open := make(map[int]struct{})
	for _, portResult := range ports {
		if !portResult.Open {
			continue
		}
		_, rawPort, err := net.SplitHostPort(portResult.Address)
		port, parseErr := strconv.Atoi(rawPort)
		if err != nil || parseErr != nil {
			continue
		}
		open[port] = struct{}{}
		tracker.endpoint(ip, port, candidateProtocolForService(portResult.Service))
	}
	for _, match := range matches {
		if match.Soft || match.IP != ip || strings.TrimSpace(match.Product) == "" {
			continue
		}
		if _, exists := open[match.Port]; !exists {
			continue
		}
		product := strings.ToLower(strings.TrimSpace(match.Product))
		tracker.endpoint(ip, match.Port, match.Protocol).identified[product] = struct{}{}
		tracker.identifiedProducts[validationProductIdentity(ip, match.Port, match.Protocol, product)] = struct{}{}
	}
}

func (tracker *runValidationTracker) failAll(err error) {
	if tracker == nil || err == nil {
		return
	}
	for _, endpoint := range tracker.endpoints {
		endpoint.attempted = true
		endpoint.err = err
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
			state := tracker.endpoint(candidate.IP, candidate.Port, candidate.Protocol)
			template := candidate.TemplateID + "\x00" + candidate.Path
			state.candidates[template] = struct{}{}
			if product := strings.ToLower(strings.TrimSpace(candidate.ProductKey)); product != "" {
				state.mapped[product] = struct{}{}
				state.identified[product] = struct{}{}
			}
		}
		tracker.templates[candidate.TemplateID+"\x00"+candidate.Path] = struct{}{}
	}
	for endpoint := range result.executedEndpoints {
		tracker.executed[endpoint] = struct{}{}
	}
	for template := range result.executedTemplates {
		tracker.executedTemplates[template] = struct{}{}
	}
	for product := range result.identifiedProducts {
		tracker.identifiedProducts[product] = struct{}{}
	}
	for product := range result.mappedProducts {
		tracker.mappedProducts[product] = struct{}{}
	}
	for endpoint := range result.attemptedEndpoints {
		if state := tracker.endpoints[endpoint]; state != nil {
			state.attempted = true
		}
	}
	for endpoint, executionErr := range result.endpointErrors {
		if state := tracker.endpoints[endpoint]; state != nil {
			state.err = executionErr
		}
	}
	for endpoint := range result.policyFiltered {
		if state := tracker.endpoints[endpoint]; state != nil {
			state.policyFiltered = true
		}
	}
	for _, candidate := range result.candidates {
		if !candidate.Executed {
			continue
		}
		state := tracker.endpoint(candidate.IP, candidate.Port, candidate.Protocol)
		state.executedTemplates[candidate.TemplateID+"\x00"+candidate.Path] = struct{}{}
	}
	for _, finding := range result.findings {
		for _, state := range tracker.endpoints {
			if state.port != finding.TargetPort || (finding.TargetIP != "" && state.ip != finding.TargetIP) || len(state.executedTemplates) == 0 {
				continue
			}
			matchedTemplate := false
			for template := range state.executedTemplates {
				if strings.HasPrefix(template, finding.TemplateID+"\x00") {
					matchedTemplate = true
					break
				}
			}
			if matchedTemplate {
				state.findingKeys[finding.TemplateID+"\x00"+finding.Target] = struct{}{}
			}
		}
	}
}

func (tracker *runValidationTracker) finish(snapshot *model.ScanTaskRunSnapshot, executionErr error) {
	if tracker == nil || snapshot == nil {
		return
	}
	snapshot.EndpointValidations = snapshot.EndpointValidations[:0]
	validation := model.ScanTaskRunValidation{
		Status:                 model.ScanTaskRunValidationNoCandidates,
		IdentifiedProductCount: len(tracker.identifiedProducts),
		MappedProductCount:     len(tracker.mappedProducts),
		CandidateEndpointCount: len(tracker.candidates),
		ExecutedEndpointCount:  len(tracker.executed),
		TemplateCount:          len(tracker.templates),
		ExecutedTemplateCount:  len(tracker.executedTemplates),
		FindingCount:           len(snapshot.Vulnerabilities),
		StartedAt:              tracker.startedAt.Format(time.RFC3339Nano),
		FinishedAt:             time.Now().UTC().Format(time.RFC3339Nano),
	}
	for product := range tracker.identifiedProducts {
		if _, mapped := tracker.mappedProducts[product]; !mapped {
			validation.UnmappedProducts = append(validation.UnmappedProducts, product)
		}
	}
	sort.Strings(validation.UnmappedProducts)
	endpointKeys := make([]string, 0, len(tracker.endpoints))
	for key := range tracker.endpoints {
		endpointKeys = append(endpointKeys, key)
	}
	sort.Strings(endpointKeys)
	finishedAt := time.Now().UTC().Format(time.RFC3339Nano)
	anySuccess, anyFailure := false, false
	for _, key := range endpointKeys {
		state := tracker.endpoints[key]
		endpointResult := model.ScanTaskRunEndpointValidation{
			IP: state.ip, Port: state.port, Protocol: state.protocol, Enabled: true,
			Status: model.ScanTaskRunValidationNoCandidates, IdentifiedProductCount: len(state.identified),
			MappedProductCount: len(state.mapped), CandidateTemplateCount: len(state.candidates),
			ExecutedTemplateCount: len(state.executedTemplates), FindingCount: len(state.findingKeys),
			StartedAt: tracker.startedAt.Format(time.RFC3339Nano), FinishedAt: finishedAt,
		}
		for product := range state.identified {
			if _, mapped := state.mapped[product]; !mapped {
				endpointResult.UnmappedProducts = append(endpointResult.UnmappedProducts, product)
			}
		}
		sort.Strings(endpointResult.UnmappedProducts)
		endpointErr := state.err
		if endpointErr == nil && executionErr != nil {
			endpointErr = executionErr
		}
		if endpointErr != nil {
			endpointResult.Reason = validationErrorReason(endpointErr)
			endpointResult.Error = safeValidationError(endpointErr)
			if errors.Is(endpointErr, vuln.ErrNoTemplates) {
				endpointResult.Status = model.ScanTaskRunValidationNoCandidates
			} else {
				endpointResult.Status = model.ScanTaskRunValidationFailed
				anyFailure = true
			}
		} else if len(state.executedTemplates) > 0 {
			endpointResult.Status = model.ScanTaskRunValidationSuccess
			anySuccess = true
		} else if state.policyFiltered {
			endpointResult.Reason = model.ValidationReasonPolicyFiltered
		} else if len(state.identified) == 0 {
			endpointResult.Reason = model.ValidationReasonUnidentifiedProduct
		} else {
			endpointResult.Reason = model.ValidationReasonMappingMissing
		}
		snapshot.EndpointValidations = append(snapshot.EndpointValidations, endpointResult)
	}
	if anyFailure {
		validation.Status = model.ScanTaskRunValidationFailed
		for _, endpoint := range snapshot.EndpointValidations {
			if endpoint.Status == model.ScanTaskRunValidationFailed {
				validation.Error = endpoint.Error
				break
			}
		}
	} else if anySuccess {
		validation.Status = model.ScanTaskRunValidationSuccess
	}
	snapshot.Validation = validation
}

func initialEndpointValidations(ip string, ports []model.ScanResult, enabled bool) []model.ScanTaskRunEndpointValidation {
	status := model.ScanTaskRunValidationDisabled
	reason := ""
	if enabled {
		status = model.ScanTaskRunValidationNotStarted
		reason = model.ValidationReasonRunFailure
	}
	seen := make(map[string]struct{})
	result := make([]model.ScanTaskRunEndpointValidation, 0)
	for _, portResult := range ports {
		if !portResult.Open {
			continue
		}
		_, rawPort, err := net.SplitHostPort(portResult.Address)
		port, parseErr := strconv.Atoi(rawPort)
		if err != nil || parseErr != nil {
			continue
		}
		protocol := candidateProtocolForService(portResult.Service)
		key := validationEndpointIdentity(ip, port, protocol)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, model.ScanTaskRunEndpointValidation{IP: ip, Port: port, Protocol: protocol, Enabled: enabled, Status: status, Reason: reason, UnmappedProducts: make([]string, 0)})
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Port != result[right].Port {
			return result[left].Port < result[right].Port
		}
		return result[left].Protocol < result[right].Protocol
	})
	return result
}

func validationErrorReason(err error) string {
	switch {
	case errors.Is(err, vuln.ErrNoTemplates), errors.Is(err, vuln.ErrTemplateMissing), errors.Is(err, planner.ErrPinnedTemplateMissing):
		return model.ValidationReasonTemplateMissing
	case errors.Is(err, vuln.ErrNucleiMissing):
		return model.ValidationReasonNucleiMissing
	case errors.Is(err, vuln.ErrTemplateDirectoryMissing):
		return model.ValidationReasonTemplateDirectory
	default:
		return model.ValidationReasonExecutionFailed
	}
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

func uniqueTemplateCandidates(input []model.ScanTaskRunTemplateCandidate) []model.ScanTaskRunTemplateCandidate {
	seen := map[string]model.ScanTaskRunTemplateCandidate{}
	for _, item := range input {
		seen[fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s\x00%s", item.TemplateID, item.Path, item.IP, item.Port, item.Protocol, strings.ToLower(strings.TrimSpace(item.ProductKey)))] = item
	}
	result := make([]model.ScanTaskRunTemplateCandidate, 0, len(seen))
	for _, item := range seen {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		left := fmt.Sprintf("%s\x00%s\x00%s\x00%05d\x00%s\x00%s", result[i].TemplateID, result[i].Path, result[i].IP, result[i].Port, result[i].Protocol, result[i].ProductKey)
		right := fmt.Sprintf("%s\x00%s\x00%s\x00%05d\x00%s\x00%s", result[j].TemplateID, result[j].Path, result[j].IP, result[j].Port, result[j].Protocol, result[j].ProductKey)
		return left < right
	})
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
		if err := storage.SyncOpenAndScopePorts(options.DB, scope, ip, openPorts, portCoverage); err != nil {
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
