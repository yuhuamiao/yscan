package diff

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

var (
	ErrScanTaskRunMismatch      = errors.New("scan task runs belong to different scan tasks")
	ErrScanTaskRunNotSuccessful = errors.New("scan task run is not successful")
)

// CompareScanTaskRuns compares two explicit runs from one logical task.
func CompareScanTaskRuns(db *sql.DB, baselineRunID, currentRunID int64) (model.ScanTaskRunChanges, error) {
	if baselineRunID <= 0 || currentRunID <= 0 {
		return model.ScanTaskRunChanges{}, errors.New("baseline and current run IDs are required")
	}
	baselineRun, err := storage.GetScanTaskRun(db, baselineRunID)
	if err != nil {
		return model.ScanTaskRunChanges{}, err
	}
	currentRun, err := storage.GetScanTaskRun(db, currentRunID)
	if err != nil {
		return model.ScanTaskRunChanges{}, err
	}
	if baselineRun.ScanTaskID != currentRun.ScanTaskID {
		return model.ScanTaskRunChanges{}, ErrScanTaskRunMismatch
	}
	if baselineRun.Status != model.ScanTaskRunStatusSuccess || currentRun.Status != model.ScanTaskRunStatusSuccess {
		return model.ScanTaskRunChanges{}, ErrScanTaskRunNotSuccessful
	}
	if baselineRun.ConfigHash != currentRun.ConfigHash {
		return configChangedRunChanges(currentRun.ScanTaskID, baselineRunID, currentRunID), nil
	}

	baseline, err := storage.GetScanTaskRunSnapshot(db, baselineRunID)
	if err != nil {
		return model.ScanTaskRunChanges{}, err
	}
	current, err := storage.GetScanTaskRunSnapshot(db, currentRunID)
	if err != nil {
		return model.ScanTaskRunChanges{}, err
	}
	return compareRunSnapshots(currentRun.ScanTaskID, baselineRunID, currentRunID, baseline, current), nil
}

// CompareRunWithPreviousSuccess compares a run with the latest earlier
// successful run that has an immutable snapshot. The first successful run uses
// an empty baseline so its observed assets are reported as newly discovered.
func CompareRunWithPreviousSuccess(db *sql.DB, currentRunID int64) (model.ScanTaskRunChanges, error) {
	return compareRunWithPreviousSuccess(db, currentRunID, false)
}

// CompareReportingRunWithPreviousSuccess is reserved for report preparation.
// Public API and CLI callers must continue to require an already-successful run.
func CompareReportingRunWithPreviousSuccess(db *sql.DB, currentRunID int64) (model.ScanTaskRunChanges, error) {
	return compareRunWithPreviousSuccess(db, currentRunID, true)
}

func compareRunWithPreviousSuccess(db *sql.DB, currentRunID int64, allowReporting bool) (model.ScanTaskRunChanges, error) {
	currentRun, err := storage.GetScanTaskRun(db, currentRunID)
	if err != nil {
		return model.ScanTaskRunChanges{}, err
	}
	if currentRun.Status != model.ScanTaskRunStatusSuccess && !(allowReporting && isReportingRun(currentRun)) {
		return model.ScanTaskRunChanges{}, ErrScanTaskRunNotSuccessful
	}
	current, err := storage.GetScanTaskRunSnapshot(db, currentRunID)
	if err != nil {
		return model.ScanTaskRunChanges{}, err
	}

	runs, err := storage.ListScanTaskRuns(db, currentRun.ScanTaskID)
	if err != nil {
		return model.ScanTaskRunChanges{}, err
	}
	for index := len(runs) - 1; index >= 0; index-- {
		candidate := runs[index]
		if candidate.Sequence >= currentRun.Sequence || candidate.Status != model.ScanTaskRunStatusSuccess {
			continue
		}
		baseline, err := storage.GetScanTaskRunSnapshot(db, candidate.ID)
		if errors.Is(err, storage.ErrScanTaskRunSnapshotUnavailable) {
			continue
		}
		if err != nil {
			return model.ScanTaskRunChanges{}, fmt.Errorf("load previous successful run %d: %w", candidate.ID, err)
		}
		if candidate.ConfigHash != currentRun.ConfigHash {
			return configChangedRunChanges(currentRun.ScanTaskID, candidate.ID, currentRunID), nil
		}
		return compareRunSnapshots(currentRun.ScanTaskID, candidate.ID, currentRunID, baseline, current), nil
	}

	return compareRunSnapshots(
		currentRun.ScanTaskID,
		0,
		currentRunID,
		model.ScanTaskRunSnapshot{Hosts: []model.ScanTaskRunHost{}, Ports: []model.ScanTaskRunPort{}, Vulnerabilities: []model.ScanTaskRunVulnerability{}},
		current,
	), nil
}

func isReportingRun(run model.ScanTaskRun) bool {
	return run.Status == model.ScanTaskRunStatusRunning && run.Stage == model.ScanTaskRunStageReporting
}

func configChangedRunChanges(scanTaskID, baselineRunID, currentRunID int64) model.ScanTaskRunChanges {
	return model.ScanTaskRunChanges{
		ScanTaskID:    scanTaskID,
		BaselineRunID: baselineRunID,
		CurrentRunID:  currentRunID,
		ConfigChanged: true,
		HostChanges: model.HostChanges{
			NewHosts:      make([]string, 0),
			InactiveHosts: make([]string, 0),
		},
		PortChanges: model.PortChanges{
			Opened: make([]model.PortChange, 0),
			Closed: make([]model.PortChange, 0),
		},
		VulnerabilityChanges: model.VulnerabilityChanges{
			New:      make([]model.VulnerabilityChange, 0),
			Resolved: make([]model.VulnerabilityChange, 0),
		},
	}
}

func compareRunSnapshots(scanTaskID, baselineRunID, currentRunID int64, baseline, current model.ScanTaskRunSnapshot) model.ScanTaskRunChanges {
	return model.ScanTaskRunChanges{
		ScanTaskID:           scanTaskID,
		BaselineRunID:        baselineRunID,
		CurrentRunID:         currentRunID,
		HostChanges:          CompareHosts(snapshotHosts(baseline.Hosts), snapshotHosts(current.Hosts)),
		PortChanges:          ComparePorts(snapshotPorts(baseline.Ports), snapshotPorts(current.Ports)),
		VulnerabilityChanges: compareSnapshotVulnerabilities(baseline.Vulnerabilities, current.Vulnerabilities),
	}
}

func snapshotHosts(snapshot []model.ScanTaskRunHost) []model.HostInventory {
	hosts := make([]model.HostInventory, 0, len(snapshot))
	for _, host := range snapshot {
		hosts = append(hosts, model.HostInventory{IP: host.IP, IsActive: host.IsActive})
	}
	return hosts
}

func snapshotPorts(snapshot []model.ScanTaskRunPort) map[string][]int {
	ports := make(map[string][]int)
	for _, port := range snapshot {
		ports[port.IP] = append(ports[port.IP], port.Port)
	}
	return ports
}

func compareSnapshotVulnerabilities(before, after []model.ScanTaskRunVulnerability) model.VulnerabilityChanges {
	beforeByKey := vulnerabilitiesByKey(before)
	afterByKey := vulnerabilitiesByKey(after)
	changes := model.VulnerabilityChanges{
		New:      make([]model.VulnerabilityChange, 0),
		Resolved: make([]model.VulnerabilityChange, 0),
	}
	for key, finding := range afterByKey {
		if _, found := beforeByKey[key]; !found {
			changes.New = append(changes.New, vulnerabilityChange(finding))
		}
	}
	for key, finding := range beforeByKey {
		if _, found := afterByKey[key]; !found {
			changes.Resolved = append(changes.Resolved, vulnerabilityChange(finding))
		}
	}
	sort.Slice(changes.New, func(i, j int) bool { return changes.New[i].FindingKey < changes.New[j].FindingKey })
	sort.Slice(changes.Resolved, func(i, j int) bool { return changes.Resolved[i].FindingKey < changes.Resolved[j].FindingKey })
	return changes
}

func vulnerabilitiesByKey(findings []model.ScanTaskRunVulnerability) map[string]model.ScanTaskRunVulnerability {
	byKey := make(map[string]model.ScanTaskRunVulnerability, len(findings))
	for _, finding := range findings {
		if finding.FindingKey != "" {
			byKey[finding.FindingKey] = finding
		}
	}
	return byKey
}

func vulnerabilityChange(finding model.ScanTaskRunVulnerability) model.VulnerabilityChange {
	return model.VulnerabilityChange{
		FindingKey: finding.FindingKey,
		TemplateID: finding.TemplateID,
		Severity:   finding.Severity,
		Target:     finding.Target,
	}
}
