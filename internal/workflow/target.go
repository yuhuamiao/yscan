package workflow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"

	"golandproject/yscan/internal/model"
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
	scanHost            func(context.Context, string, string) ([]model.ScanResult, error)
	runNuclei           func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error)
	runNucleiPaths      func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error)
	collectFingerprints func(context.Context, *sql.DB, string, []model.ScanResult) ([]model.AssetFingerprint, error)
}

// RunTargetTaskRun collects the observations for one IP run without reading
// inventory state as a Diff baseline.
func RunTargetTaskRun(ctx context.Context, options TargetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
	return runTargetTaskRun(ctx, options, targetDependencies{
		scanHost:            scan.RunQuick,
		runNuclei:           vuln.RunNucleiForOpenPortsWithTags,
		runNucleiPaths:      vuln.RunNucleiForOpenPortsWithTemplatePaths,
		collectFingerprints: collectRunFingerprints,
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
	if dependencies.runNucleiPaths == nil {
		dependencies.runNucleiPaths = vuln.RunNucleiForOpenPortsWithTemplatePaths
	}
	if dependencies.collectFingerprints == nil {
		dependencies.collectFingerprints = collectRunFingerprints
	}
	if dependencies.scanHost == nil || dependencies.runNuclei == nil {
		return model.ScanTaskRunSnapshot{}, errors.New("target task run dependencies are required")
	}
	if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if err := updateProgress(options.UpdateProgress, 10); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}

	target := ip.String()
	openPorts, err := dependencies.scanHost(ctx, target, options.Network)
	if err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	active := len(snapshotPorts(target, openPorts)) > 0
	scope := "ip:" + target
	if err := storage.SyncHostInventory(options.DB, scope, activeTargets(target, active)); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if err := storage.SyncOpenPorts(options.DB, target, openPorts); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if err := storage.SyncScopeOpenPorts(options.DB, scope, target, openPorts); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	if err := storage.DeactivateScopePortsForInactiveHosts(options.DB, scope); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	// Evidence collection is intentionally non-blocking. A failed web probe
	// leaves the existing service-tag validation path available for this port.
	currentFingerprints, _ := dependencies.collectFingerprints(ctx, options.DB, target, openPorts)

	snapshot := model.ScanTaskRunSnapshot{
		RunID:           options.Run.ID,
		Hosts:           make([]model.ScanTaskRunHost, 0, 1),
		Ports:           uniqueSnapshotPorts(snapshotPorts(target, openPorts)),
		Vulnerabilities: make([]model.ScanTaskRunVulnerability, 0),
	}
	if active {
		snapshot.Hosts = append(snapshot.Hosts, model.ScanTaskRunHost{IP: target, IsActive: true})
	}
	if options.Run.Config.VulnerabilityOn {
		findings, candidates, err := runPlannedValidation(ctx, target, openPorts, currentFingerprints, options.Run.Config.NucleiTemplates, dependencies.runNuclei, dependencies.runNucleiPaths)
		if err != nil {
			return model.ScanTaskRunSnapshot{}, err
		}
		snapshot.Vulnerabilities = uniqueSnapshotVulnerabilities(snapshotVulnerabilities(findings))
		snapshot.TemplateCandidates = uniqueTemplateCandidates(candidates)
	}
	if err := updateProgress(options.UpdateProgress, 100); err != nil {
		return model.ScanTaskRunSnapshot{}, err
	}
	return snapshot, nil
}

func activeTargets(ip string, active bool) []string {
	if !active {
		return nil
	}
	return []string{ip}
}
