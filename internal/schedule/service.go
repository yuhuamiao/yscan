package schedule

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/scan"
	"golandproject/yscan/internal/storage"
)

// TaskService is the single creation boundary for v2 logical scan tasks.
// One-time tasks receive one queued run at creation; scheduled tasks wait for
// Runner to materialize each cron occurrence.
type TaskService struct {
	DB                     *sql.DB
	Clock                  Clock
	DefaultNucleiTemplates string
}

func (service *TaskService) WithDefaultNucleiTemplates(path string) *TaskService {
	service.DefaultNucleiTemplates = strings.TrimSpace(path)
	return service
}

func NewTaskService(db *sql.DB, clock Clock) *TaskService {
	if clock == nil {
		clock = ClockFunc(time.Now)
	}
	return &TaskService{DB: db, Clock: clock}
}

func (service *TaskService) Create(ctx context.Context, task model.ScanTask) (model.ScanTask, *model.ScanTaskRun, error) {
	if err := ctx.Err(); err != nil {
		return model.ScanTask{}, nil, err
	}
	if service.DB == nil {
		return model.ScanTask{}, nil, errors.New("scan task service database is required")
	}
	if service.Clock == nil {
		return model.ScanTask{}, nil, errors.New("scan task service clock is required")
	}
	normalizedTarget, err := NormalizeInternalScanTarget(task.ScanType, task.Target)
	if err != nil {
		return model.ScanTask{}, nil, err
	}
	task.Target = normalizedTarget
	service.applyConfigDefaults(&task.Config)
	ports, err := scan.ParsePortSpec(task.Config.PortSpec)
	if err != nil {
		return model.ScanTask{}, nil, fmt.Errorf("invalid port_spec: %w", err)
	}
	if len(ports) > 0 {
		task.Config.PortSpec = scan.FormatPortSpec(ports)
	}
	if task.Mode == model.ScanTaskModeScheduled {
		if _, err := ParseCron(task.Cron, task.Timezone); err != nil {
			return model.ScanTask{}, nil, err
		}
	}

	created, err := storage.CreateScanTask(service.DB, task)
	if err != nil {
		return model.ScanTask{}, nil, err
	}
	if created.Mode != model.ScanTaskModeOnce {
		return created, nil, nil
	}

	run, err := storage.CreateScanTaskRun(service.DB, model.ScanTaskRun{
		ScanTaskID:   created.ID,
		ScheduledFor: service.Clock.Now().UTC().Format(time.RFC3339Nano),
		Status:       model.ScanTaskRunStatusQueued,
	})
	if err == nil {
		return created, &run, nil
	}

	// A partially created one-time task must never remain eligible without its
	// sole execution record. Archive preserves the audit trail for diagnosis.
	if archiveErr := storage.ArchiveScanTask(service.DB, created.ID); archiveErr != nil {
		return model.ScanTask{}, nil, fmt.Errorf("create one-time run: %w; archive task %d: %v", err, created.ID, archiveErr)
	}
	return model.ScanTask{}, nil, fmt.Errorf("create one-time run: %w", err)
}

// Update validates the same admission rules as Create. Existing runs already
// contain configuration snapshots, so this only changes future materialized
// runs.
func (service *TaskService) Update(ctx context.Context, task model.ScanTask) (model.ScanTask, error) {
	if err := ctx.Err(); err != nil {
		return model.ScanTask{}, err
	}
	if service.DB == nil {
		return model.ScanTask{}, errors.New("scan task service database is required")
	}
	normalizedTarget, err := NormalizeInternalScanTarget(task.ScanType, task.Target)
	if err != nil {
		return model.ScanTask{}, err
	}
	task.Target = normalizedTarget
	service.applyConfigDefaults(&task.Config)
	ports, err := scan.ParsePortSpec(task.Config.PortSpec)
	if err != nil {
		return model.ScanTask{}, fmt.Errorf("invalid port_spec: %w", err)
	}
	if len(ports) > 0 {
		task.Config.PortSpec = scan.FormatPortSpec(ports)
	}
	if task.Mode == model.ScanTaskModeScheduled {
		if _, err := ParseCron(task.Cron, task.Timezone); err != nil {
			return model.ScanTask{}, err
		}
	}
	return storage.UpdateScanTask(service.DB, task)
}

func (service *TaskService) applyConfigDefaults(config *model.ScanTaskConfig) {
	if config != nil && config.VulnerabilityOn && strings.TrimSpace(config.NucleiTemplates) == "" {
		config.NucleiTemplates = service.DefaultNucleiTemplates
	}
}

// RunNow materializes an explicitly requested occurrence. The boolean tells
// the caller whether it should launch the returned queued run in this process.
func (service *TaskService) RunNow(ctx context.Context, taskID int64) (model.ScanTaskRun, bool, error) {
	if err := ctx.Err(); err != nil {
		return model.ScanTaskRun{}, false, err
	}
	if service.DB == nil || service.Clock == nil {
		return model.ScanTaskRun{}, false, errors.New("scan task service is not initialized")
	}
	task, err := storage.GetScanTask(service.DB, taskID)
	if err != nil {
		return model.ScanTaskRun{}, false, err
	}
	if task.Status != model.ScanTaskStatusEnabled {
		return model.ScanTaskRun{}, false, fmt.Errorf("%w: %s", storage.ErrScanTaskNotEnabled, task.Status)
	}
	runs, err := storage.ListScanTaskRuns(service.DB, taskID)
	if err != nil {
		return model.ScanTaskRun{}, false, err
	}
	for index := len(runs) - 1; index >= 0; index-- {
		switch runs[index].Status {
		case model.ScanTaskRunStatusQueued:
			return runs[index], true, nil
		case model.ScanTaskRunStatusRunning, model.ScanTaskRunStatusCancelRequested:
			return runs[index], false, nil
		}
	}
	if task.Mode == model.ScanTaskModeOnce {
		return model.ScanTaskRun{}, false, storage.ErrOneTimeScanTaskRunExists
	}
	run, err := storage.CreateScanTaskRun(service.DB, model.ScanTaskRun{
		ScanTaskID: task.ID, Trigger: model.ScanTaskRunTriggerManual,
		ScheduledFor: service.Clock.Now().UTC().Format(time.RFC3339Nano),
	})
	return run, err == nil, err
}

// NormalizeInternalScanTarget is the shared admission boundary for every v2
// entry point. Loopback remains available for local acceptance fixtures;
// routable targets must stay wholly inside one RFC1918 range.
func NormalizeInternalScanTarget(scanType, target string) (string, error) {
	target = strings.TrimSpace(target)
	switch scanType {
	case model.ScanTypeIP:
		ip := net.ParseIP(target).To4()
		if ip == nil || !isInternalIPv4(ip) {
			return "", fmt.Errorf("scan target must be an internal IPv4 address: %s", target)
		}
		return ip.String(), nil
	case model.ScanTypeSubnet:
		ip, network, err := net.ParseCIDR(target)
		if err != nil || ip.To4() == nil || network == nil || !isInternalIPv4Network(network) {
			return "", fmt.Errorf("scan target must be an internal IPv4 CIDR: %s", target)
		}
		return network.String(), nil
	default:
		return "", fmt.Errorf("unsupported scan type: %s", scanType)
	}
}

func isInternalIPv4(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	return ip[0] == 10 || ip[0] == 127 ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168)
}

func isInternalIPv4Network(network *net.IPNet) bool {
	if network == nil {
		return false
	}
	first := network.IP.To4()
	ones, bits := network.Mask.Size()
	if first == nil || bits != 32 || ones < 0 {
		return false
	}
	last := append(net.IP(nil), first...)
	for index := range last {
		last[index] |= ^network.Mask[index]
	}
	return isInternalIPv4(first) && isInternalIPv4(last)
}
