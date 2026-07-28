package schedule

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
)

type CLIConfig struct {
	NucleiTemplates string
	DNSResolveMode  string
	DNSDenyCIDRs    []string
}

type RunStarter func(context.Context, model.ScanTaskRun) error

// RunCLI owns v2 logical task command parsing and lifecycle management. The
// caller supplies the actual scanner launcher so this package remains free of
// main and workflow dependencies.
func RunCLI(ctx context.Context, db *sql.DB, args []string, config CLIConfig, startRun RunStarter, output io.Writer) error {
	if output == nil {
		return errors.New("schedule command output is required")
	}
	if len(args) == 0 {
		writeUsage(output)
		return nil
	}
	service := NewTaskService(db, nil)
	command := strings.ToLower(strings.TrimSpace(args[0]))
	switch command {
	case "update":
		if len(args) < 3 {
			return writeCommandError(output, errors.New("usage: yscan schedule update <scan_task_id> --target <target> --scan-type ip|subnet --mode once|scheduled ..."))
		}
		id, err := strconv.ParseInt(strings.TrimSpace(args[1]), 10, 64)
		if err != nil || id <= 0 {
			return writeCommandError(output, errors.New("invalid scan task id"))
		}
		task, err := ParseCreateCLIArgs(args[2:], config)
		if err != nil {
			return err
		}
		current, err := storage.GetScanTask(db, id)
		if err != nil {
			return err
		}
		task.ID, task.Status = id, current.Status
		updated, err := service.Update(ctx, task)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "ScanTask %d updated (%s)\n", updated.ID, updated.Target)
		return err
	case "create":
		task, err := ParseCreateCLIArgs(args[1:], config)
		if err != nil {
			return err
		}
		created, run, err := service.Create(ctx, task)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output, "ScanTask %d created (%s %s -> %s)\n", created.ID, created.Mode, created.ScanType, created.Target); err != nil {
			return err
		}
		if run == nil {
			return nil
		}
		if startRun == nil {
			return errors.New("one-time scan task runner is required")
		}
		if err := startRun(ctx, *run); err != nil {
			if errors.Is(err, ErrGlobalConcurrencyUnavailable) {
				_, writeErr := fmt.Fprintf(output, "ScanTask run %d queued: waiting for global execution slot\n", run.ID)
				return writeErr
			}
			return err
		}
		completed, err := storage.GetScanTaskRun(db, run.ID)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "ScanTask run %d finished: %s\n", completed.ID, completed.Status)
		return err

	case "list":
		return writeTaskList(output, db)
	case "show":
		id, err := parseTaskID(args, "usage: yscan schedule show <scan_task_id>")
		if err != nil {
			return writeCommandError(output, err)
		}
		return writeTask(output, db, id)
	case "runs", "history":
		id, err := parseTaskID(args, "usage: yscan schedule runs <scan_task_id>")
		if err != nil {
			return writeCommandError(output, err)
		}
		return writeTaskRuns(output, db, id)
	case "pause", "resume", "archive":
		id, err := parseTaskID(args, "usage: yscan schedule "+command+" <scan_task_id>")
		if err != nil {
			return writeCommandError(output, err)
		}
		if err := transitionTask(db, command, id); err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "ScanTask %d %sd\n", id, command)
		return err
	default:
		writeUsage(output)
		return nil
	}
}

func ParseCreateCLIArgs(args []string, config CLIConfig) (model.ScanTask, error) {
	task := model.ScanTask{Config: model.ScanTaskConfig{
		NucleiTemplates: config.NucleiTemplates,
		DNSResolveMode:  config.DNSResolveMode,
		DNSDenyCIDRs:    append([]string(nil), config.DNSDenyCIDRs...),
	}}
	for index := 0; index < len(args); index++ {
		flag := strings.TrimSpace(args[index])
		if flag == "--vuln" {
			task.Config.VulnerabilityOn = true
			continue
		}
		if index+1 >= len(args) {
			return model.ScanTask{}, fmt.Errorf("%s requires a value", flag)
		}
		value := strings.TrimSpace(args[index+1])
		index++
		switch flag {
		case "--target":
			task.Target = value
		case "--scan-type":
			task.ScanType = strings.ToLower(value)
		case "--mode":
			task.Mode = strings.ToLower(value)
		case "--cron":
			task.Cron = value
		case "--timezone":
			task.Timezone = value
		case "--port-spec":
			task.Config.PortSpec = value
		case "--template-version":
			task.Config.TemplateVersion = value
		default:
			return model.ScanTask{}, fmt.Errorf("unsupported flag: %s", flag)
		}
	}
	if strings.TrimSpace(task.Target) == "" || strings.TrimSpace(task.ScanType) == "" || strings.TrimSpace(task.Mode) == "" {
		return model.ScanTask{}, errors.New("--target, --scan-type and --mode are required")
	}
	return task, nil
}

func parseTaskID(args []string, usage string) (int64, error) {
	if len(args) < 2 {
		return 0, errors.New(usage)
	}
	id, err := strconv.ParseInt(strings.TrimSpace(args[1]), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid scan task id")
	}
	return id, nil
}

func transitionTask(db *sql.DB, command string, taskID int64) error {
	switch command {
	case "pause":
		return storage.PauseScanTask(db, taskID)
	case "resume":
		return storage.ResumeScanTask(db, taskID)
	case "archive":
		return storage.ArchiveScanTask(db, taskID)
	default:
		return fmt.Errorf("unsupported scan task transition: %s", command)
	}
}

func writeTaskList(output io.Writer, db *sql.DB) error {
	tasks, err := storage.ListScanTasks(db)
	if err != nil {
		return err
	}
	if len(tasks) == 0 {
		_, err := fmt.Fprintln(output, "No ScanTasks found.")
		return err
	}
	if _, err := fmt.Fprintln(output, "ID       STATUS     MODE       TYPE       TARGET               CRON"); err != nil {
		return err
	}
	for _, task := range tasks {
		if _, err := fmt.Fprintf(output, "%-8d %-10s %-10s %-10s %-20s %-24s\n", task.ID, task.Status, task.Mode, task.ScanType, task.Target, task.Cron); err != nil {
			return err
		}
	}
	return nil
}

func writeTask(output io.Writer, db *sql.DB, taskID int64) error {
	task, err := storage.GetScanTask(db, taskID)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(output, "ScanTask %d\n  Target   : %s\n  Type     : %s\n  Mode     : %s\n  Status   : %s\n", task.ID, task.Target, task.ScanType, task.Mode, task.Status); err != nil {
		return err
	}
	if task.Mode == model.ScanTaskModeScheduled {
		if _, err := fmt.Fprintf(output, "  Cron     : %s\n  Timezone : %s\n", task.Cron, task.Timezone); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(output, "  Config   : vulnerability=%t templates=%s\n", task.Config.VulnerabilityOn, task.Config.NucleiTemplates)
	return err
}

func writeTaskRuns(output io.Writer, db *sql.DB, taskID int64) error {
	runs, err := storage.ListScanTaskRuns(db, taskID)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output, "RUN ID   STATUS     SCHEDULED FOR            REPORT"); err != nil {
		return err
	}
	for _, run := range runs {
		if _, err := fmt.Fprintf(output, "%-8d %-10s %-24s %-24s\n", run.ID, run.Status, run.ScheduledFor, run.ReportPath); err != nil {
			return err
		}
	}
	return nil
}

func writeUsage(output io.Writer) {
	fmt.Fprintln(output, "usage: yscan schedule create --target <internal-ip-or-cidr> --scan-type ip|subnet --mode once|scheduled [--cron '0 2 * * *' --timezone Asia/Shanghai] [--vuln]")
	fmt.Fprintln(output, "       yscan schedule update <scan_task_id> --target <internal-ip-or-cidr> --scan-type ip|subnet --mode once|scheduled [--cron '0 2 * * *' --timezone Asia/Shanghai] [--vuln]")
	fmt.Fprintln(output, "       yscan schedule list|show|runs|pause|resume|archive <scan_task_id>")
}

func writeCommandError(output io.Writer, err error) error {
	_, writeErr := fmt.Fprintln(output, err)
	return writeErr
}
