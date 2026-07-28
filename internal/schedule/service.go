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
	"golandproject/yscan/internal/storage"
)

// TaskService is the single creation boundary for v2 logical scan tasks.
// One-time tasks receive one queued run at creation; scheduled tasks wait for
// Runner to materialize each cron occurrence.
type TaskService struct {
	DB    *sql.DB
	Clock Clock
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
	if task.Mode == model.ScanTaskModeScheduled {
		if _, err := ParseCron(task.Cron, task.Timezone); err != nil {
			return model.ScanTask{}, err
		}
	}
	return storage.UpdateScanTask(service.DB, task)
}

// NormalizeInternalScanTarget is the shared admission boundary for v2 CLI and
// API task creation. The current product scope is RFC1918 IPv4 assets only.
func NormalizeInternalScanTarget(scanType, target string) (string, error) {
	target = strings.TrimSpace(target)
	switch scanType {
	case model.ScanTypeIP:
		ip := net.ParseIP(target).To4()
		if ip == nil || !ip.IsPrivate() {
			return "", fmt.Errorf("scan target must be an internal IPv4 address: %s", target)
		}
		return ip.String(), nil
	case model.ScanTypeSubnet:
		ip, network, err := net.ParseCIDR(target)
		if err != nil || ip.To4() == nil || network == nil || network.IP.To4() == nil || !network.IP.IsPrivate() {
			return "", fmt.Errorf("scan target must be an internal IPv4 CIDR: %s", target)
		}
		return network.String(), nil
	default:
		return "", fmt.Errorf("unsupported scan type: %s", scanType)
	}
}
