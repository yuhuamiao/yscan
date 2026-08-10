package workflow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/planner"
	"golandproject/yscan/internal/scan"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/vuln"
)

// TargetTaskRunOptions configures one v2 IP run. The immutable run supplies
// the target and vulnerability settings; this struct only supplies execution
// dependencies and optional progress/cancellation hooks.
type TargetTaskRunOptions struct {
	DB             *sql.DB
	Run            model.ScanTaskRun
	Network        string
	CheckCanceled  func() (bool, error)
	UpdateProgress func(int) error
}

type TargetTaskRunExecutor struct {
	Options TargetTaskRunOptions
}

func NewTargetTaskRunExecutor(options TargetTaskRunOptions) TargetTaskRunExecutor {
	return TargetTaskRunExecutor{Options: options}
}

func (executor TargetTaskRunExecutor) Execute(ctx context.Context, run model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
	options := executor.Options
	options.Run = run
	return RunTargetTaskRun(ctx, options)
}

type targetDependencies struct {
	scanHost             func(context.Context, string, string) (scan.PortScanOutcome, error)
	scanSelected         func(context.Context, string, string, []int) (scan.PortScanOutcome, error)
	collectFingerprints  func(context.Context, *sql.DB, model.ScanTaskRun, string, []model.ScanResult) ([]model.ScanResult, []model.FingerprintRunMatch, error)
	runNuclei            func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error)
	executeNuclei        func(context.Context, string, []model.ScanResult, string, []string) vuln.NucleiExecutionResult
	loadTemplateIndex    func(string) (string, *planner.NucleiTemplateIndex, error)
	executeTemplatePaths func(context.Context, string, []model.ScanResult, []string) vuln.NucleiExecutionResult
}

// RunTargetTaskRun collects the observations for one IP run without reading
// inventory state as a Diff baseline.
func RunTargetTaskRun(ctx context.Context, options TargetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
	if options.DB == nil {
		return model.ScanTaskRunSnapshot{}, errors.New("target task run database is required")
	}
	if options.Run.ID <= 0 || options.Run.ScanTaskID <= 0 || options.Run.ScanType != model.ScanTypeIP {
		return model.ScanTaskRunSnapshot{}, errors.New("invalid IP scan task run")
	}
	collector, err := newRunFingerprintCollector(options.DB, options.Run)
	if err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	return runTargetTaskRun(ctx, options, targetDependencies{
		scanHost:             scan.RunDiscoveryWithOutcome,
		scanSelected:         scan.RunSelectedDiscoveryWithOutcome,
		collectFingerprints:  collector,
		runNuclei:            vuln.RunNucleiForOpenPortsWithTags,
		executeNuclei:        vuln.ExecuteNucleiForOpenPortsWithTags,
		loadTemplateIndex:    loadNucleiTemplateIndex,
		executeTemplatePaths: vuln.ExecuteNucleiForOpenPortsWithTemplatePaths,
	})
}

func runTargetTaskRun(ctx context.Context, options TargetTaskRunOptions, dependencies targetDependencies) (model.ScanTaskRunSnapshot, error) {
	if options.DB == nil {
		return model.ScanTaskRunSnapshot{}, errors.New("target task run database is required")
	}
	if options.Run.ID <= 0 || options.Run.ScanTaskID <= 0 || options.Run.ScanType != model.ScanTypeIP {
		return model.ScanTaskRunSnapshot{}, errors.New("invalid IP scan task run")
	}
	ip := net.ParseIP(strings.TrimSpace(options.Run.Target)).To4()
	if ip == nil {
		return model.ScanTaskRunSnapshot{}, fmt.Errorf("invalid IPv4 target: %s", options.Run.Target)
	}
	if strings.TrimSpace(options.Network) == "" {
		options.Network = "tcp"
	}
	if dependencies.scanHost == nil || (dependencies.runNuclei == nil && dependencies.executeNuclei == nil && dependencies.executeTemplatePaths == nil) {
		return model.ScanTaskRunSnapshot{}, errors.New("target task run dependencies are required")
	}
	if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if err := updateProgress(options.UpdateProgress, 10); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}

	target := ip.String()
	configuredPorts, err := scan.ParsePortSpec(options.Run.Config.PortSpec)
	if err != nil {
		return model.ScanTaskRunSnapshot{}, fmt.Errorf("invalid run port_spec: %w", err)
	}
	budget := scan.FullPortScanWorstCaseBudget()
	if len(configuredPorts) > 0 {
		budget = scan.SelectedPortScanWorstCaseBudget(len(configuredPorts))
	}
	discoveryCtx, cancelDiscovery := context.WithTimeout(ctx, budget)
	var outcome scan.PortScanOutcome
	if len(configuredPorts) > 0 {
		if dependencies.scanSelected == nil {
			cancelDiscovery()
			return model.ScanTaskRunSnapshot{}, errors.New("selected port scan dependency is required")
		}
		outcome, err = dependencies.scanSelected(discoveryCtx, target, options.Network, configuredPorts)
	} else {
		outcome, err = dependencies.scanHost(discoveryCtx, target, options.Network)
	}
	cancelDiscovery()
	if err != nil {
		return partialTargetSnapshot(options.Run.ID, target, outcome.Results, options.Run.Config.VulnerabilityOn), err
	}
	if !outcome.Complete() {
		return partialTargetSnapshot(options.Run.ID, target, outcome.Results, options.Run.Config.VulnerabilityOn), fmt.Errorf("incomplete port scan: attempted %d of %d ports", outcome.AttemptedPorts, outcome.TotalPorts)
	}
	openPorts := outcome.Results
	if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
		return partialTargetSnapshot(options.Run.ID, target, openPorts, options.Run.Config.VulnerabilityOn), err
	}
	if err := updateProgress(options.UpdateProgress, 55); err != nil {
		return partialTargetSnapshot(options.Run.ID, target, openPorts, options.Run.Config.VulnerabilityOn), err
	}
	fingerprintMatches := make([]model.FingerprintRunMatch, 0)
	if dependencies.collectFingerprints != nil {
		openPorts, fingerprintMatches, err = dependencies.collectFingerprints(ctx, options.DB, options.Run, target, openPorts)
		if err != nil {
			snapshot := partialTargetSnapshot(options.Run.ID, target, openPorts, options.Run.Config.VulnerabilityOn)
			snapshot.FingerprintMatches = fingerprintMatches
			return snapshot, err
		}
	}
	if err := updateProgress(options.UpdateProgress, 75); err != nil {
		snapshot := partialTargetSnapshot(options.Run.ID, target, openPorts, options.Run.Config.VulnerabilityOn)
		snapshot.FingerprintMatches = fingerprintMatches
		return snapshot, err
	}
	active := len(snapshotPorts(target, openPorts)) > 0
	snapshot := partialTargetSnapshot(options.Run.ID, target, openPorts, options.Run.Config.VulnerabilityOn)
	snapshot.FingerprintMatches = fingerprintMatches
	scope := "ip:" + target
	if err := storage.SyncHostInventory(options.DB, scope, activeTargets(target, active)); err != nil {
		return snapshot, err
	}
	coverage := storage.FullPortScanCoverage()
	if len(configuredPorts) > 0 {
		coverage = storage.SelectedPortScanCoverage(configuredPorts)
	}
	if err := storage.SyncOpenPorts(options.DB, target, openPorts, coverage); err != nil {
		return snapshot, err
	}
	if err := storage.SyncScopeOpenPorts(options.DB, scope, target, openPorts, coverage); err != nil {
		return snapshot, err
	}
	if err := storage.DeactivateScopePortsForInactiveHosts(options.DB, scope); err != nil {
		return snapshot, err
	}
	if options.Run.Config.VulnerabilityOn {
		if err := updateProgress(options.UpdateProgress, 85); err != nil {
			return snapshot, err
		}
		validation := newRunValidationTracker()
		validation.register(target, openPorts, fingerprintMatches)
		templateRoot := options.Run.Config.NucleiTemplates
		var templateIndex *planner.NucleiTemplateIndex
		if dependencies.loadTemplateIndex != nil {
			templateRoot, templateIndex, err = dependencies.loadTemplateIndex(options.Run.Config.NucleiTemplates)
			if err != nil {
				validation.failAll(err)
				validation.finish(&snapshot, err)
				return snapshot, err
			}
		}
		mappingResult := runFingerprintMappingValidation(ctx, options.DB, options.Run, target, openPorts, fingerprintMatches, templateRoot, templateIndex, dependencies.executeTemplatePaths)
		validation.observe(mappingResult)
		snapshot.Vulnerabilities = uniqueSnapshotVulnerabilities(snapshotVulnerabilities(mappingResult.findings))
		snapshot.TemplateCandidates = uniqueTemplateCandidates(mappingResult.candidates)
		if mappingResult.err != nil && !errors.Is(mappingResult.err, vuln.ErrNoTemplates) {
			validation.finish(&snapshot, mappingResult.err)
			return snapshot, mappingResult.err
		}
		fallbackResult := runServiceTagValidation(ctx, target, portsWithoutFingerprintMappings(openPorts, mappingResult.candidates, fingerprintMatches), templateIndex, dependencies.executeTemplatePaths)
		validation.observe(fallbackResult)
		allFindings := append(mappingResult.findings, fallbackResult.findings...)
		allCandidates := append(mappingResult.candidates, fallbackResult.candidates...)
		snapshot.Vulnerabilities = uniqueSnapshotVulnerabilities(snapshotVulnerabilities(allFindings))
		snapshot.TemplateCandidates = uniqueTemplateCandidates(allCandidates)
		if fallbackResult.err != nil && !errors.Is(fallbackResult.err, vuln.ErrNoTemplates) {
			validation.finish(&snapshot, fallbackResult.err)
			return snapshot, fallbackResult.err
		}
		validation.finish(&snapshot, nil)
	}
	if err := updateProgress(options.UpdateProgress, 100); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func partialTargetSnapshot(runID int64, ip string, results []model.ScanResult, vulnerabilityOn ...bool) model.ScanTaskRunSnapshot {
	ports := uniqueSnapshotPorts(snapshotPorts(ip, results))
	snapshot := model.ScanTaskRunSnapshot{
		RunID: runID, Ports: ports, ProtocolEvidence: uniqueProtocolEvidence(snapshotProtocolEvidence(ip, results)), Hosts: make([]model.ScanTaskRunHost, 0, 1),
		Vulnerabilities: make([]model.ScanTaskRunVulnerability, 0), FingerprintMatches: make([]model.FingerprintRunMatch, 0),
	}
	snapshot.Validation = initialRunValidation(len(vulnerabilityOn) > 0 && vulnerabilityOn[0])
	enabled := len(vulnerabilityOn) > 0 && vulnerabilityOn[0]
	snapshot.EndpointValidations = initialEndpointValidations(ip, results, enabled)
	if len(ports) > 0 {
		snapshot.Hosts = []model.ScanTaskRunHost{{IP: ip, IsActive: true}}
	}
	return snapshot
}

func activeTargets(ip string, active bool) []string {
	if !active {
		return nil
	}
	return []string{ip}
}
