package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golandproject/yscan/internal/api"
	"golandproject/yscan/internal/assist"
	"golandproject/yscan/internal/domain"
	"golandproject/yscan/internal/fingerprint"
	"golandproject/yscan/internal/identify"
	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/pipeline"
	"golandproject/yscan/internal/report"
	appRuntime "golandproject/yscan/internal/runtime"
	"golandproject/yscan/internal/scan"
	"golandproject/yscan/internal/schedule"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/vuln"
	"golandproject/yscan/internal/workflow"
)

var errTaskCanceled = errors.New("task canceled")

var (
	executeTaskForTaskExecution = executeTask
	generateTaskReport          = report.GenerateTaskReport
	runTargetTaskRun            = workflow.RunTargetTaskRun
	runSubnetTaskRun            = workflow.RunSubnetTaskRun
	generateScanTaskRunReport   = report.GenerateScanTaskRunReport
)

type serverRunRegistry struct {
	mu  sync.Mutex
	ids map[int64]struct{}
}

func (registry *serverRunRegistry) track(runID int64) {
	if runID <= 0 {
		return
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.ids == nil {
		registry.ids = make(map[int64]struct{})
	}
	registry.ids[runID] = struct{}{}
}

func (registry *serverRunRegistry) cancelQueued(db *sql.DB) error {
	registry.mu.Lock()
	ids := make([]int64, 0, len(registry.ids))
	for id := range registry.ids {
		ids = append(ids, id)
	}
	registry.mu.Unlock()
	if len(ids) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.Exec(`
			UPDATE scan_task_runs
			SET status = ?, stage = ?, error_message = ?, finished_at = datetime('now'), updated_at = datetime('now')
			WHERE id = ? AND status = ?`,
			model.ScanTaskRunStatusCanceled, model.ScanTaskRunStageCanceled,
			"canceled during normal Server shutdown", id, model.ScanTaskRunStatusQueued); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type cliConfig struct {
	Templates      string
	DNSResolveMode string
	DNSDenyCIDRs   []string
	Home           string
	Runtime        appRuntime.ConfigOverrides
}

func runTask(db *sql.DB, baseTask model.Scanner, taskType, target string) {
	taskID, err := storage.CreateTask(db, taskType, target)
	if err != nil {
		log.Printf("创建任务失败: %v", err)
		return
	}

	fmt.Printf("Task created: %d (%s -> %s)\n", taskID, taskType, target)
	processTaskExecution(db, taskID, baseTask, taskType, target)
}

func runTaskAsync(db *sql.DB, baseTask model.Scanner, taskType, target string) (int64, error) {
	taskID, err := storage.CreateTask(db, taskType, target)
	if err != nil {
		return 0, err
	}

	go processTaskExecution(db, taskID, baseTask, taskType, target)
	return taskID, nil
}

func processTaskExecution(db *sql.DB, taskID int64, baseTask model.Scanner, taskType, target string) {
	taskCtx, stopTaskContext := taskExecutionContext(db, taskID)
	defer stopTaskContext()

	executionErr := executeTaskForTaskExecution(taskCtx, db, taskID, baseTask, taskType, target)
	finalStatus, err := storage.FinalizeTask(db, taskID, executionErr)
	if err != nil {
		log.Printf("任务最终状态更新失败: %v", err)
		return
	}

	reportPath, reportErr := generateTaskReport(db, taskID, report.DefaultDirectory)
	if reportErr != nil {
		if err := storage.UpdateTaskReportError(db, taskID, reportErr.Error()); err != nil {
			log.Printf("任务报告错误写入失败: %v", err)
		}
	} else if err := storage.UpdateTaskReportError(db, taskID, ""); err != nil {
		log.Printf("任务报告错误清理失败: %v", err)
	}

	switch finalStatus {
	case model.TaskStatusCanceled:
		if reportErr != nil {
			fmt.Printf("Task %d canceled (report failed: %v)\n", taskID, reportErr)
			return
		}
		fmt.Printf("Task %d canceled (report: %s)\n", taskID, reportPath)
	case model.TaskStatusFailed:
		if reportErr != nil {
			fmt.Printf("Task %d failed: %v (report failed: %v)\n", taskID, executionErr, reportErr)
			return
		}
		fmt.Printf("Task %d failed: %v (report: %s)\n", taskID, executionErr, reportPath)
	case model.TaskStatusSuccess:
		if reportErr != nil {
			fmt.Printf("Task %d finished: success (report failed: %v)\n", taskID, reportErr)
			return
		}
		fmt.Printf("Task %d finished: success (report: %s)\n", taskID, reportPath)
	}
}

func executeTask(ctx context.Context, db *sql.DB, taskID int64, baseTask model.Scanner, taskType, target string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := storage.UpdateTaskStatus(db, taskID, model.TaskStatusRunning, ""); err != nil {
		return err
	}
	_ = storage.UpdateTaskProgress(db, taskID, 5)

	if canceled, err := storage.IsTaskCanceled(db, taskID); err == nil && canceled {
		return errTaskCanceled
	}

	switch taskType {
	case model.TaskTypeScanIP:
		_ = storage.UpdateTaskProgress(db, taskID, 20)
		baseTask.IP = target
		if _, err := portScan(ctx, baseTask, db); err != nil {
			return err
		}
		_ = storage.UpdateTaskProgress(db, taskID, 100)
		return nil

	case model.TaskTypeScanIPVuln:
		_ = storage.UpdateTaskProgress(db, taskID, 20)
		baseTask.IP = target
		openPorts, err := portScan(ctx, baseTask, db)
		if err != nil {
			return err
		}
		_ = storage.UpdateTaskProgress(db, taskID, 60)

		if canceled, err := storage.IsTaskCanceled(db, taskID); err == nil && canceled {
			return errTaskCanceled
		}

		scanCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		findings, err := vuln.RunNucleiForOpenPorts(scanCtx, baseTask.IP, openPorts, baseTask.NucleiTemplates)
		cancel()
		if err != nil {
			return err
		}
		if err := storage.SaveNucleiFindings(db, taskID, findings); err != nil {
			return err
		}
		_ = storage.UpdateTaskProgress(db, taskID, 100)
		return nil

	case model.TaskTypeScanSubnet:
		return runSubnetTask(ctx, db, taskID, baseTask, target, false)

	case model.TaskTypeScanSubnetVuln:
		return runSubnetTask(ctx, db, taskID, baseTask, target, true)

	case model.TaskTypeVulnIP:
		_ = storage.UpdateTaskProgress(db, taskID, 20)
		ip, ports, err := resolveVulnTargetPorts(db, target)
		if err != nil {
			return err
		}
		openPorts := buildOpenPortResults(ip, ports)
		_ = storage.UpdateTaskProgress(db, taskID, 60)

		if canceled, err := storage.IsTaskCanceled(db, taskID); err == nil && canceled {
			return errTaskCanceled
		}

		scanCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		findings, err := vuln.RunNucleiForOpenPorts(scanCtx, ip, openPorts, baseTask.NucleiTemplates)
		cancel()
		if err != nil {
			return err
		}
		if err := storage.SaveNucleiFindings(db, taskID, findings); err != nil {
			return err
		}
		_ = storage.UpdateTaskProgress(db, taskID, 100)
		return nil

	case model.TaskTypeCollectDomain:
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = storage.UpdateTaskProgress(db, taskID, 20)
		_ = pipeline.CollectSubdomains(db, target, pipeline.DomainCollectionOptions{
			ResolvePolicy: domain.ResolvePolicy{
				Mode:      baseTask.DNSResolveMode,
				DenyCIDRs: baseTask.DNSDenyCIDRs,
			},
		})
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = storage.UpdateTaskProgress(db, taskID, 100)
		return nil

	case model.TaskTypeCollectAndScan:
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = storage.UpdateTaskProgress(db, taskID, 20)
		ips := pipeline.CollectSubdomains(db, target, pipeline.DomainCollectionOptions{
			ResolvePolicy: domain.ResolvePolicy{
				Mode:      baseTask.DNSResolveMode,
				DenyCIDRs: baseTask.DNSDenyCIDRs,
			},
		})
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(ips) == 0 {
			_ = storage.UpdateTaskProgress(db, taskID, 100)
			return nil
		}

		for i, ip := range ips {
			if err := ctx.Err(); err != nil {
				return err
			}

			baseTask.IP = ip
			if _, err := domainScan(ctx, baseTask, db); err != nil {
				return err
			}

			progress := 20 + int(float64(i+1)/float64(len(ips))*80)
			_ = storage.UpdateTaskProgress(db, taskID, progress)
		}
		return nil

	case model.TaskTypeCollectScanVuln:
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = storage.UpdateTaskProgress(db, taskID, 20)
		ips := pipeline.CollectSubdomains(db, target, pipeline.DomainCollectionOptions{
			ResolvePolicy: domain.ResolvePolicy{
				Mode:      baseTask.DNSResolveMode,
				DenyCIDRs: baseTask.DNSDenyCIDRs,
			},
		})
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(ips) == 0 {
			_ = storage.UpdateTaskProgress(db, taskID, 100)
			return nil
		}

		for i, ip := range ips {
			if err := ctx.Err(); err != nil {
				return err
			}

			baseTask.IP = ip
			openPorts, err := domainScan(ctx, baseTask, db)
			if err != nil {
				return err
			}

			scanCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
			findings, err := vuln.RunNucleiForOpenPorts(scanCtx, baseTask.IP, openPorts, baseTask.NucleiTemplates)
			cancel()
			if err != nil {
				return err
			}
			if err := storage.SaveNucleiFindings(db, taskID, findings); err != nil {
				return err
			}

			progress := 40 + int(float64(i+1)/float64(len(ips))*60)
			_ = storage.UpdateTaskProgress(db, taskID, progress)
		}
		return nil

	default:
		return fmt.Errorf("不支持的任务类型: %s", taskType)
	}
}

func printTaskStatus(db *sql.DB, taskID int64) {
	task, err := storage.GetTaskByID(db, taskID)
	if err != nil {
		log.Printf("查询任务状态失败: %v", err)
		return
	}

	if task.ErrorMsg == "" {
		task.ErrorMsg = "-"
	}
	if task.StartedAt == "" {
		task.StartedAt = "-"
	}
	if task.FinishedAt == "" {
		task.FinishedAt = "-"
	}

	fmt.Printf("Task %d\n", task.ID)
	fmt.Printf("  Status    : %s\n", task.Status)
	fmt.Printf("  Type      : %s\n", task.TaskType)
	fmt.Printf("  Target    : %s\n", task.Target)
	fmt.Printf("  Progress  : %d%%\n", task.Progress)
	fmt.Printf("  Error     : %s\n", task.ErrorMsg)
	fmt.Printf("  StartedAt : %s\n", task.StartedAt)
	fmt.Printf("  FinishedAt: %s\n", task.FinishedAt)
	fmt.Printf("  CreatedAt : %s\n", task.CreatedAt)
	fmt.Printf("  UpdatedAt : %s\n", task.UpdatedAt)
}

func printTaskList(db *sql.DB) {
	tasks, err := storage.ListTasks(db)
	if err != nil {
		log.Printf("查询任务列表失败: %v", err)
		return
	}

	if len(tasks) == 0 {
		fmt.Println("No tasks found")
		return
	}

	fmt.Printf("%-8s %-12s %-20s %-10s %-30s %-20s\n", "ID", "Status", "Type", "Progress", "Target", "CreatedAt")
	for _, t := range tasks {
		fmt.Printf("%-8d %-12s %-20s %-10s %-30s %-20s\n", t.ID, t.Status, t.TaskType, fmt.Sprintf("%d%%", t.Progress), t.Target, t.CreatedAt)
	}
}

func printTaskFindings(db *sql.DB, taskID int64, severity string) {
	findings, err := storage.ListVulnerabilitiesByTaskWithSeverity(db, taskID, severity)
	if err != nil {
		log.Printf("查询漏洞列表失败: %v", err)
		return
	}

	if len(findings) == 0 {
		if strings.TrimSpace(severity) == "" {
			fmt.Printf("Task %d has no vulnerabilities\n", taskID)
		} else {
			fmt.Printf("Task %d has no vulnerabilities with severity=%s\n", taskID, strings.ToLower(strings.TrimSpace(severity)))
		}
		return
	}

	fmt.Printf("%-6s %-10s %-30s %-22s %-8s %-24s\n", "ID", "Severity", "TemplateID", "Target", "Port", "ScanTime")
	for _, v := range findings {
		fmt.Printf("%-6d %-10s %-30s %-22s %-8d %-24s\n", v.ID, v.Severity, v.TemplateID, v.TargetIP, v.TargetPort, v.ScanTime)
	}
}

func warnIfNucleiMissing() {
	if _, err := vuln.DetectNucleiBinary(); err != nil {
		log.Print("[WARN] nuclei not found in PATH/GOPATH. 漏洞扫描任务将失败。")
		log.Print("[WARN] 安装示例: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
	}
}

func warnIfNucleiTemplatesMissing(templatesPath string) {
	if resolved, err := vuln.ResolveNucleiTemplatesPath(templatesPath); err != nil {
		log.Printf("[WARN] %v", err)
		log.Print("[WARN] 可通过 --templates <dir> 或 YSCAN_NUCLEI_TEMPLATES 配置模板目录。")
	} else {
		log.Printf("[INFO] nuclei templates: %s", resolved)
	}
}

func warnIfExternalDNSPolicy(task model.Scanner) {
	mode := strings.ToLower(strings.TrimSpace(task.DNSResolveMode))
	if mode != domain.DNSModeExternal {
		return
	}
	effective := domain.NormalizeResolvePolicy(domain.ResolvePolicy{
		Mode:      task.DNSResolveMode,
		DenyCIDRs: task.DNSDenyCIDRs,
	})
	log.Printf("[INFO] external DNS filter enabled, deny CIDRs: %s", strings.Join(effective.DenyCIDRs, ","))
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if strings.EqualFold(strings.TrimSpace(a), flag) {
			return true
		}
	}
	return false
}

func parseCLIConfig(args []string) ([]string, cliConfig, error) {
	cfg := cliConfig{DNSResolveMode: domain.DNSModeHybrid, Runtime: appRuntime.ConfigOverrides{}}
	if len(args) == 0 {
		return args, cfg, nil
	}

	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		current := strings.TrimSpace(args[i])
		switch {
		case current == "--templates":
			value, next, err := requiredFlagValue(args, i, current)
			if err != nil {
				return nil, cfg, err
			}
			cfg.Templates, i = value, next
		case strings.HasPrefix(current, "--templates="):
			cfg.Templates = strings.TrimSpace(strings.TrimPrefix(current, "--templates="))
			if cfg.Templates == "" {
				return nil, cfg, errors.New("--templates requires a value")
			}
		case current == "--dns-mode":
			value, next, err := requiredFlagValue(args, i, current)
			if err != nil {
				return nil, cfg, err
			}
			cfg.DNSResolveMode, i = strings.ToLower(value), next
		case strings.HasPrefix(current, "--dns-mode="):
			cfg.DNSResolveMode = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(current, "--dns-mode=")))
			if cfg.DNSResolveMode == "" {
				return nil, cfg, errors.New("--dns-mode requires a value")
			}
		case current == "--dns-deny-cidr":
			value, next, err := requiredFlagValue(args, i, current)
			if err != nil {
				return nil, cfg, err
			}
			cfg.DNSDenyCIDRs, i = append(cfg.DNSDenyCIDRs, value), next
		case strings.HasPrefix(current, "--dns-deny-cidr="):
			value := strings.TrimSpace(strings.TrimPrefix(current, "--dns-deny-cidr="))
			if value == "" {
				return nil, cfg, errors.New("--dns-deny-cidr requires a value")
			}
			cfg.DNSDenyCIDRs = append(cfg.DNSDenyCIDRs, value)
		case current == "--home":
			value, next, err := requiredFlagValue(args, i, current)
			if err != nil {
				return nil, cfg, err
			}
			cfg.Home, i = value, next
		case strings.HasPrefix(current, "--home="):
			cfg.Home = strings.TrimSpace(strings.TrimPrefix(current, "--home="))
			if cfg.Home == "" {
				return nil, cfg, errors.New("--home requires a value")
			}
		case current == "--listen":
			var err error
			i, err = captureRuntimeFlag(args, i, current, appRuntime.ConfigListenAddress, cfg.Runtime)
			if err != nil {
				return nil, cfg, err
			}
		case strings.HasPrefix(current, "--listen="):
			if err := captureRuntimeFlagEquals(current, "--listen=", appRuntime.ConfigListenAddress, cfg.Runtime); err != nil {
				return nil, cfg, err
			}
		case current == "--trusted-cidrs":
			var err error
			i, err = captureRuntimeFlag(args, i, current, appRuntime.ConfigAllowCIDRs, cfg.Runtime)
			if err != nil {
				return nil, cfg, err
			}
		case strings.HasPrefix(current, "--trusted-cidrs="):
			if err := captureRuntimeFlagEquals(current, "--trusted-cidrs=", appRuntime.ConfigAllowCIDRs, cfg.Runtime); err != nil {
				return nil, cfg, err
			}
		case current == "--max-concurrency":
			var err error
			i, err = captureRuntimeFlag(args, i, current, appRuntime.ConfigMaxConcurrency, cfg.Runtime)
			if err != nil {
				return nil, cfg, err
			}
		case strings.HasPrefix(current, "--max-concurrency="):
			if err := captureRuntimeFlagEquals(current, "--max-concurrency=", appRuntime.ConfigMaxConcurrency, cfg.Runtime); err != nil {
				return nil, cfg, err
			}
		case current == "--sqlite-busy-timeout":
			var err error
			i, err = captureRuntimeFlag(args, i, current, appRuntime.ConfigSQLiteBusyTimeout, cfg.Runtime)
			if err != nil {
				return nil, cfg, err
			}
		case strings.HasPrefix(current, "--sqlite-busy-timeout="):
			if err := captureRuntimeFlagEquals(current, "--sqlite-busy-timeout=", appRuntime.ConfigSQLiteBusyTimeout, cfg.Runtime); err != nil {
				return nil, cfg, err
			}
		case current == "--log-max-bytes":
			var err error
			i, err = captureRuntimeFlag(args, i, current, appRuntime.ConfigLogMaxBytes, cfg.Runtime)
			if err != nil {
				return nil, cfg, err
			}
		case strings.HasPrefix(current, "--log-max-bytes="):
			if err := captureRuntimeFlagEquals(current, "--log-max-bytes=", appRuntime.ConfigLogMaxBytes, cfg.Runtime); err != nil {
				return nil, cfg, err
			}
		case current == "--log-max-files":
			var err error
			i, err = captureRuntimeFlag(args, i, current, appRuntime.ConfigLogMaxFiles, cfg.Runtime)
			if err != nil {
				return nil, cfg, err
			}
		case strings.HasPrefix(current, "--log-max-files="):
			if err := captureRuntimeFlagEquals(current, "--log-max-files=", appRuntime.ConfigLogMaxFiles, cfg.Runtime); err != nil {
				return nil, cfg, err
			}
		case current == "--nuclei-binary":
			var err error
			i, err = captureRuntimeFlag(args, i, current, appRuntime.ConfigNucleiBinary, cfg.Runtime)
			if err != nil {
				return nil, cfg, err
			}
		case strings.HasPrefix(current, "--nuclei-binary="):
			if err := captureRuntimeFlagEquals(current, "--nuclei-binary=", appRuntime.ConfigNucleiBinary, cfg.Runtime); err != nil {
				return nil, cfg, err
			}
		default:
			filtered = append(filtered, args[i])
		}
	}

	return filtered, cfg, nil
}

func requiredFlagValue(args []string, index int, flag string) (string, int, error) {
	if index+1 >= len(args) || strings.HasPrefix(strings.TrimSpace(args[index+1]), "-") {
		return "", index, fmt.Errorf("%s requires a value", flag)
	}
	value := strings.TrimSpace(args[index+1])
	if value == "" {
		return "", index, fmt.Errorf("%s requires a value", flag)
	}
	return value, index + 1, nil
}

func captureRuntimeFlag(args []string, index int, flag, key string, overrides appRuntime.ConfigOverrides) (int, error) {
	value, next, err := requiredFlagValue(args, index, flag)
	if err != nil {
		return index, err
	}
	overrides[key] = value
	return next, nil
}

func captureRuntimeFlagEquals(argument, prefix, key string, overrides appRuntime.ConfigOverrides) error {
	value := strings.TrimSpace(strings.TrimPrefix(argument, prefix))
	if value == "" {
		return fmt.Errorf("%s requires a value", strings.TrimSuffix(prefix, "="))
	}
	overrides[key] = value
	return nil
}

func resolveVulnTargetPorts(db *sql.DB, target string) (string, []int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", nil, fmt.Errorf("empty target")
	}

	if host, portStr, err := net.SplitHostPort(target); err == nil {
		port, err := strconv.Atoi(strings.TrimSpace(portStr))
		if err != nil || port <= 0 || port > 65535 {
			return "", nil, fmt.Errorf("invalid port in target: %s", target)
		}
		host = strings.TrimSpace(host)
		if host == "" {
			return "", nil, fmt.Errorf("invalid host in target: %s", target)
		}
		return host, []int{port}, nil
	}

	ip := target
	ports, err := storage.ListOpenPortsByIP(db, ip)
	if err != nil {
		return "", nil, err
	}
	if len(ports) == 0 {
		ports = []int{80}
	}
	return ip, ports, nil
}

func buildOpenPortResults(ip string, ports []int) []model.ScanResult {
	results := make([]model.ScanResult, 0, len(ports))
	for _, p := range ports {
		if p <= 0 || p > 65535 {
			continue
		}
		results = append(results, model.ScanResult{
			Address: net.JoinHostPort(ip, strconv.Itoa(p)),
			Open:    true,
		})
	}
	return results
}

func domainScan(ctx context.Context, task model.Scanner, db *sql.DB) ([]model.ScanResult, error) {
	fmt.Printf("\n=== 开始域名扫描 %s ===\n", task.IP)

	if assist.IsHostAliveContext(ctx, task.IP) {
		openPorts, err := scan.Run(ctx, task.IP, task.Network)
		if err != nil {
			return openPorts, err
		}
		if err := storage.SaveDomainScanResult(db, task.IP, openPorts); err != nil {
			log.Printf("保存扫描结果失败: %v", err)
			return openPorts, err
		}
		persistOpenPorts(db, openPorts)
		return openPorts, nil
	}

	fmt.Println("Can't ping")
	if assist.IsHostAliveTCPContext(ctx, task.IP) {
		openPorts, err := scan.Run(ctx, task.IP, task.Network)
		if err != nil {
			return openPorts, err
		}
		if err := storage.SaveDomainScanResult(db, task.IP, openPorts); err != nil {
			log.Printf("保存扫描结果失败: %v", err)
			return openPorts, err
		}
		persistOpenPorts(db, openPorts)
		return openPorts, nil
	}

	log.Print("没有进入TCP连接")
	fmt.Printf("%s is not alive\n", task.IP)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%s is not alive", task.IP)
}

func portScan(ctx context.Context, task model.Scanner, db *sql.DB) ([]model.ScanResult, error) {
	if assist.IsHostAliveContext(ctx, task.IP) || assist.IsHostAliveTCPContext(ctx, task.IP) {
		openPorts, err := scan.Run(ctx, task.IP, task.Network)
		if err != nil {
			return openPorts, err
		}
		persistOpenPorts(db, openPorts)
		return openPorts, nil
	}

	log.Print("没有进入TCP连接")
	fmt.Printf("%s is not alive\n", task.IP)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%s is not alive", task.IP)
}

func persistOpenPorts(db *sql.DB, openPorts []model.ScanResult) {
	for _, result := range openPorts {
		if !result.Open {
			continue
		}
		if err := storage.SaveResult(db, result); err != nil {
			log.Printf("存储失败 %s: %v", result.Address, err)
		} else {
			log.Printf("成功储存 %s (%s)", result.Address, result.Service)
		}
	}
}

func runSubnetTask(ctx context.Context, db *sql.DB, taskID int64, task model.Scanner, cidr string, withVuln bool) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	summary, err := workflow.RunSubnet(ctx, workflow.SubnetRunOptions{
		DB:                    db,
		TaskID:                taskID,
		CIDR:                  cidr,
		Network:               task.Network,
		TemplatesPath:         task.NucleiTemplates,
		EnableVulnerabilities: withVuln,
		CheckCanceled: func() (bool, error) {
			return storage.IsTaskCanceled(db, taskID)
		},
		UpdateProgress: func(progress int) error {
			return storage.UpdateTaskProgress(db, taskID, progress)
		},
	})
	if errors.Is(err, workflow.ErrCanceled) || errors.Is(err, context.Canceled) {
		return errTaskCanceled
	}
	if err != nil {
		return err
	}

	fmt.Printf("[CHANGE] hosts +%d -%d | ports +%d -%d\n",
		len(summary.HostChanges.NewHosts),
		len(summary.HostChanges.InactiveHosts),
		len(summary.PortChanges.Opened),
		len(summary.PortChanges.Closed),
	)
	return nil
}

type logicalScanTaskRunExecutor struct {
	db       *sql.DB
	baseTask model.Scanner
}

func (executor logicalScanTaskRunExecutor) Execute(ctx context.Context, run model.ScanTaskRun) (model.ScanTaskRunSnapshot, error) {
	updateProgress := func(progress int) error {
		stage := model.ScanTaskRunStageProfiling
		if progress <= 10 {
			stage = model.ScanTaskRunStageDiscovery
		} else if run.Config.VulnerabilityOn && progress >= 85 {
			stage = model.ScanTaskRunStageValidation
		}
		if progress >= 100 {
			progress = 94
			stage = model.ScanTaskRunStageSnapshot
		}
		return storage.UpdateScanTaskRunProgress(executor.db, run.ID, stage, progress)
	}
	switch run.ScanType {
	case model.ScanTypeIP:
		return runTargetTaskRun(ctx, workflow.TargetTaskRunOptions{
			DB: executor.db, Run: run, Network: executor.baseTask.Network,
			UpdateProgress: updateProgress,
		})
	case model.ScanTypeSubnet:
		return runSubnetTaskRun(ctx, workflow.SubnetTaskRunOptions{
			DB: executor.db, Run: run, Network: executor.baseTask.Network,
			UpdateProgress: updateProgress,
		})
	default:
		return model.ScanTaskRunSnapshot{}, fmt.Errorf("unsupported scan task run type: %s", run.ScanType)
	}
}

func executeLogicalScanTaskRun(ctx context.Context, db *sql.DB, baseTask model.Scanner, run model.ScanTaskRun) (returnErr error) {
	log.Printf("scan task run %d started (%s %s)", run.ID, run.ScanType, run.Target)
	defer func() {
		if returnErr != nil {
			log.Printf("scan task run %d finished with error: %v", run.ID, returnErr)
			return
		}
		log.Printf("scan task run %d finished", run.ID)
	}()
	runTimeout := 30 * time.Minute
	if run.ScanType == model.ScanTypeIP {
		// The discovery budget is derived from scanner concurrency and the
		// per-port hard deadline. Remaining time covers evidence and validation.
		runTimeout = scan.FullPortScanWorstCaseBudget() + 20*time.Minute
	}
	scanCtx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	executor := schedule.NewExecutor(db, logicalScanTaskRunExecutor{db: db, baseTask: baseTask})
	var executionErr error
	if run.Status == model.ScanTaskRunStatusRunning {
		executionErr = executor.ExecuteClaimedRun(scanCtx, run.ID)
	} else {
		executionErr = executor.ExecuteRun(scanCtx, run.ID)
	}
	completed, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil {
		if executionErr != nil {
			return fmt.Errorf("execute run: %w; read final run: %v", executionErr, err)
		}
		return err
	}
	pendingSuccess := completed.Status == model.ScanTaskRunStatusRunning && completed.Stage == model.ScanTaskRunStageReporting
	if !pendingSuccess && !isTerminalScanTaskRunStatus(completed.Status) {
		return executionErr
	}
	reportError := ""
	if _, err := generateScanTaskRunReport(db, completed.ScanTaskID, completed.ID, report.DefaultDirectory); err != nil {
		reportError = err.Error()
		log.Printf("scan task run %d report failed: %v", completed.ID, err)
	}
	if pendingSuccess {
		if err := executor.FinalizeSuccessfulRun(completed.ID, reportError); err != nil {
			return fmt.Errorf("finalize successful run: %w", err)
		}
		return executionErr
	}
	if err := storage.UpdateScanTaskRunReportError(db, completed.ID, reportError); err != nil {
		return fmt.Errorf("persist report diagnostic: %w", err)
	}
	return executionErr
}

func generateRecoveredScanTaskRunReport(db *sql.DB, run model.ScanTaskRun) error {
	if _, err := generateScanTaskRunReport(db, run.ScanTaskID, run.ID, report.DefaultDirectory); err != nil {
		if persistErr := storage.UpdateScanTaskRunReportError(db, run.ID, err.Error()); persistErr != nil {
			return fmt.Errorf("generate recovery report: %v; persist diagnostic: %w", err, persistErr)
		}
		log.Printf("recovered scan task run %d report failed: %v", run.ID, err)
	}
	return nil
}

func isTerminalScanTaskRunStatus(status string) bool {
	switch status {
	case model.ScanTaskRunStatusSuccess, model.ScanTaskRunStatusFailed, model.ScanTaskRunStatusCanceled:
		return true
	default:
		return false
	}
}

func taskExecutionContext(db *sql.DB, taskID int64) (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})

	go func() {
		defer close(stopped)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			canceled, err := storage.IsTaskCanceled(db, taskID)
			if err == nil && canceled {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	return ctx, func() {
		cancel()
		<-stopped
	}
}

func main() {
	if err := runMain(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func runMain() error {
	return runMainArgs(os.Args[1:])
}

func runMainArgs(rawArgs []string) (returnErr error) {
	args, cfg, err := parseCLIConfig(rawArgs)
	if err != nil {
		return err
	}
	if len(args) == 0 || isTopLevelHelp(args) {
		printCLIUsage()
		return nil
	}
	if isTopLevelVersion(args) {
		fmt.Println("yscan development")
		return nil
	}
	var deprecatedAPI bool
	args, deprecatedAPI = normalizeServerCommand(args)
	homeOverride := cfg.Home
	if homeOverride == "" {
		homeOverride = strings.TrimSpace(os.Getenv("YSCAN_HOME"))
	}
	paths, err := appRuntime.ResolveHome("", homeOverride)
	if err != nil {
		return err
	}
	if len(args) > 1 && strings.EqualFold(args[0], "server") {
		handled, err := handleServerControlCommand(paths, args[1:])
		if err != nil || handled {
			return err
		}
	}
	overrides := cfg.Runtime
	if cfg.Templates != "" {
		overrides[appRuntime.ConfigNucleiTemplates] = cfg.Templates
	}
	runtimeConfig, err := appRuntime.LoadConfig(paths, overrides, os.LookupEnv)
	if err != nil {
		return err
	}
	vuln.ConfigureNucleiBinary(runtimeConfig.NucleiBinary)
	if err := paths.Prepare(); err != nil {
		return err
	}
	report.ConfigureHomeDirectory(paths.ReportsDir)
	backgroundChild := false
	if len(args) > 1 && strings.EqualFold(args[0], "server") && args[1] == "--background-child" {
		backgroundChild = true
		args = append([]string{"server"}, args[2:]...)
	}
	readyNotified := false
	if backgroundChild {
		defer func() {
			if !readyNotified {
				appRuntime.NotifyBackgroundReady(returnErr)
			}
		}()
	}
	if len(args) > 0 && strings.EqualFold(args[0], "server") {
		handled, err := handleServerManagementCommand(paths, args[1:], runtimeConfig, cfg)
		if err != nil || handled {
			return err
		}
	}
	command := strings.ToLower(strings.TrimSpace(args[0]))
	upgradeSourceHome := ""
	if command == "upgrade" {
		upgradeSourceHome, err = parseUpgradeSourceHome(args[1:])
		if err != nil {
			return err
		}
		if upgradeSourceHome == "" {
			if err := rejectUnmigratedWorkingDirectoryDatabase(paths); err != nil {
				return err
			}
		}
	}
	isServerCommand := len(args) > 0 && strings.EqualFold(strings.TrimSpace(args[0]), "server")
	var preparedServer *preparedServerStartup
	var serverSession *appRuntime.ServerSession
	var serviceLog *appRuntime.RotatingLogWriter
	if isServerCommand {
		preparedServer, err = prepareServerStartup(args, runtimeConfig)
		if err != nil {
			return err
		}
		defer preparedServer.listener.Close()
		serverSession, err = appRuntime.AcquireServerSessionForStartup(paths, preparedServer.listener.Addr().String())
		if err != nil {
			return err
		}
		defer serverSession.Close()
		serviceLog, err = appRuntime.OpenRotatingLogWriter(filepath.Join(paths.LogsDir, "yscan.log"), runtimeConfig.LogMaxBytes, runtimeConfig.LogMaxFiles)
		if err != nil {
			return err
		}
		defer serviceLog.Close()
		processOutput := io.Writer(serviceLog)
		if !backgroundChild {
			processOutput = io.MultiWriter(os.Stderr, serviceLog)
		}
		restoreOutput, captureErr := appRuntime.CaptureProcessOutput(processOutput)
		if captureErr != nil {
			return captureErr
		}
		defer restoreOutput()
		log.SetOutput(processOutput)
		defer log.SetOutput(os.Stderr)
	}
	migrationPending, err := storage.HomeMigrationPending(paths)
	if err != nil {
		return err
	}
	if command == "upgrade" {
		migrated, err := storage.UpgradeLegacyHome(storage.HomeUpgradeOptions{
			Paths: paths, SourceHome: upgradeSourceHome,
			InitializeContent: func(database *sql.DB) error {
				_, err := fingerprint.InitializeEmbeddedSourcesIfEmpty(context.Background(), database)
				return err
			},
		})
		if err != nil {
			return err
		}
		if migrated {
			fmt.Printf("yscan database upgraded to %s\n", paths.Database)
		} else {
			fmt.Println("yscan database is already current")
		}
		return nil
	}
	if migrationPending {
		return fmt.Errorf("interrupted offline upgrade detected under %s; run 'yscan --home %q upgrade' for recovery guidance", paths.DataDir, paths.Home)
	}
	selection, err := paths.SelectDatabase()
	if err != nil {
		return err
	}
	if selection.Mode == appRuntime.DatabaseLegacy {
		return fmt.Errorf("legacy database found at %s; stop all yscan processes and run: yscan --home %q upgrade", selection.Path, paths.Home)
	}
	if err := rejectUnmigratedWorkingDirectoryDatabase(paths); err != nil {
		return err
	}
	managedDatabase, err := storage.OpenManagedDatabase(storage.ManagedDatabaseOptions{
		Paths: paths, BusyTimeout: runtimeConfig.SQLiteBusyTimeout,
		InitializeContent: func(database *sql.DB) error {
			_, err := fingerprint.InitializeEmbeddedSourcesIfEmpty(context.Background(), database)
			return err
		},
	})
	if err != nil {
		return err
	}
	defer managedDatabase.Close()
	db := managedDatabase.DB
	if deprecatedAPI {
		log.Print("[WARN] 'yscan api' is deprecated; use 'yscan server'")
	}
	if _, err := fingerprint.InitializeEmbeddedSourcesIfEmpty(context.Background(), db); err != nil {
		return err
	}
	if commandNeedsLegacyBannerMatcher(args) {
		engine, err := fingerprint.LoadActiveLegacyBannerEngine(db)
		if err != nil {
			return err
		}
		identify.SetFingerprintMatcher(func(banner string) string { return engine.MatchBanner(banner) })
	}

	task := model.Scanner{Network: "tcp"}

	task.NucleiTemplates = runtimeConfig.NucleiTemplates
	task.DNSResolveMode = cfg.DNSResolveMode
	task.DNSDenyCIDRs = cfg.DNSDenyCIDRs
	return runByArgs(args, task, db, runtimeConfig, serverSession, preparedServer, func() error {
		if err := serverSession.MarkRunning(); err != nil {
			return err
		}
		if backgroundChild && !readyNotified {
			appRuntime.NotifyBackgroundReady(nil)
			readyNotified = true
		}
		return nil
	})
}

func parseUpgradeSourceHome(args []string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	if len(args) != 2 || args[0] != "--from-home" {
		return "", errors.New("usage: yscan upgrade [--from-home <legacy_home>]")
	}
	value := strings.TrimSpace(args[1])
	if value == "" || strings.HasPrefix(value, "-") {
		return "", errors.New("--from-home requires a value")
	}
	return value, nil
}

func rejectUnmigratedWorkingDirectoryDatabase(paths appRuntime.HomePaths) error {
	selection, err := paths.SelectDatabase()
	if err != nil || selection.Mode != appRuntime.DatabaseUninitialized {
		return err
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return err
	}
	workingDirectory, err = filepath.Abs(workingDirectory)
	if err != nil {
		return err
	}
	if filepath.Clean(workingDirectory) == filepath.Clean(paths.Home) {
		return nil
	}
	legacyPath := filepath.Join(workingDirectory, "asm.db")
	info, err := os.Lstat(legacyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect legacy working-directory database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("legacy working-directory database is not a regular file: %s", legacyPath)
	}
	return fmt.Errorf("legacy database found at %s; migrate it explicitly with: yscan --home %q upgrade --from-home %q", legacyPath, paths.Home, workingDirectory)
}

func handleServerManagementCommand(paths appRuntime.HomePaths, args []string, config appRuntime.Config, cli cliConfig) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "--background", "start":
		return true, appRuntime.StartBackgroundServer(paths, effectiveBackgroundArguments(config, cli), args[1:], 2*time.Minute)
	case "restart":
		desiredAddress, _, err := validateServerStartup(append([]string{"server"}, args[1:]...), config)
		if err != nil {
			return true, err
		}
		inspection := appRuntime.InspectServerHealth(paths)
		if inspection.Status == appRuntime.ServerRunning && inspection.State != nil && !sameServerListenAddress(inspection.State.ListenAddress, desiredAddress) {
			probe, err := net.Listen("tcp", desiredAddress)
			if err != nil {
				return true, fmt.Errorf("validate restart listen address %s: %w", desiredAddress, err)
			}
			if err := probe.Close(); err != nil {
				return true, fmt.Errorf("release restart listen address %s: %w", desiredAddress, err)
			}
		}
		oldAddress := ""
		if inspection.Status == appRuntime.ServerRunning && inspection.State != nil {
			oldAddress = inspection.State.ListenAddress
		}
		start := func(serverArguments []string) error {
			return appRuntime.StartBackgroundServer(paths, effectiveBackgroundArguments(config, cli), serverArguments, 2*time.Minute)
		}
		if err := restartBackgroundServer(paths, args[1:], oldAddress, start); err != nil {
			return true, err
		}
		return true, nil
	default:
		return false, nil
	}
}

func sameServerListenAddress(left, right string) bool {
	return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
}

func restartBackgroundServer(paths appRuntime.HomePaths, serverArguments []string, oldAddress string, start func([]string) error) error {
	if err := appRuntime.StopServer(paths, 30*time.Second, false); err != nil {
		return err
	}
	if err := start(serverArguments); err != nil {
		if strings.TrimSpace(oldAddress) == "" {
			return err
		}
		recoveryErr := start([]string{oldAddress})
		if recoveryErr != nil {
			return fmt.Errorf("restart failed: %v; restoring previous listener %s also failed: %w", err, oldAddress, recoveryErr)
		}
		return fmt.Errorf("restart failed: %w; previous listener %s was restored", err, oldAddress)
	}
	return nil
}

func handleServerControlCommand(paths appRuntime.HomePaths, args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "stop":
		force := len(args) == 2 && args[1] == "--force"
		if len(args) > 1 && !force {
			return true, errors.New("usage: yscan server stop [--force]")
		}
		return true, appRuntime.StopServer(paths, 30*time.Second, force)
	case "status":
		inspection := appRuntime.InspectServerHealth(paths)
		fmt.Printf("Server: %s\n", inspection.Status)
		if inspection.State != nil {
			fmt.Printf("PID: %d\nListen: %s\nStarted: %s\n", inspection.State.PID, inspection.State.ListenAddress, inspection.State.StartedAt.Format(time.RFC3339))
		}
		if inspection.Error != "" {
			fmt.Printf("Diagnostic: %s\n", inspection.Error)
		}
		if inspection.Status != appRuntime.ServerRunning {
			return true, fmt.Errorf("Server is %s", inspection.Status)
		}
		return true, nil
	case "logs":
		lines, follow := 100, true
		for index := 1; index < len(args); index++ {
			switch args[index] {
			case "--lines":
				if index+1 >= len(args) {
					return true, errors.New("--lines requires a value")
				}
				value, err := strconv.Atoi(args[index+1])
				if err != nil {
					return true, err
				}
				lines, index = value, index+1
			case "--no-follow":
				follow = false
			default:
				return true, fmt.Errorf("unknown server logs option: %s", args[index])
			}
		}
		ctx, stop := signal.NotifyContext(context.Background(), appRuntime.ShutdownSignals()...)
		defer stop()
		return true, appRuntime.PrintServerLogs(ctx, os.Stdout, filepath.Join(paths.LogsDir, "yscan.log"), lines, follow)
	case "uninstall":
		if len(args) > 1 {
			return true, errors.New("usage: yscan server uninstall")
		}
		if err := appRuntime.UninstallSystemd(paths); err != nil {
			return true, err
		}
		fmt.Printf("systemd unit removed; yscan home retained at %s\n", paths.Home)
		return true, nil
	default:
		return false, nil
	}
}

func effectiveBackgroundArguments(config appRuntime.Config, cli cliConfig) []string {
	arguments := []string{
		"--listen", config.ListenAddress,
		"--max-concurrency", strconv.Itoa(config.MaxConcurrency),
		"--sqlite-busy-timeout", config.SQLiteBusyTimeout.String(),
		"--log-max-bytes", strconv.FormatInt(config.LogMaxBytes, 10),
		"--log-max-files", strconv.Itoa(config.LogMaxFiles),
		"--nuclei-binary", config.NucleiBinary,
		"--dns-mode", cli.DNSResolveMode,
	}
	if len(config.AllowCIDRs) > 0 {
		arguments = append(arguments, "--trusted-cidrs", strings.Join(config.AllowCIDRs, ","))
	}
	if config.NucleiTemplates != "" {
		arguments = append(arguments, "--templates", config.NucleiTemplates)
	}
	for _, cidr := range cli.DNSDenyCIDRs {
		arguments = append(arguments, "--dns-deny-cidr", cidr)
	}
	return arguments
}

func normalizeServerCommand(args []string) ([]string, bool) {
	if len(args) == 0 || !strings.EqualFold(strings.TrimSpace(args[0]), "api") {
		return args, false
	}
	normalized := append([]string(nil), args...)
	normalized[0] = "server"
	return normalized, true
}

func isTopLevelVersion(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "version", "--version":
		return true
	default:
		return false
	}
}

func isTopLevelHelp(args []string) bool {
	if len(args) == 0 {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "help", "--help", "-h":
		return true
	default:
		return false
	}
}

func commandNeedsLegacyBannerMatcher(args []string) bool {
	return false
}

func parseQuickScanFlags(args []string) (bool, string, error) {
	withVulnerabilities := false
	portSpec := ""
	for index := 0; index < len(args); index++ {
		switch strings.TrimSpace(args[index]) {
		case "--vuln":
			withVulnerabilities = true
		case "--port-spec", "--ports":
			if index+1 >= len(args) {
				return false, "", fmt.Errorf("%s requires a value", args[index])
			}
			portSpec = strings.TrimSpace(args[index+1])
			index++
		default:
			return false, "", fmt.Errorf("unsupported scan flag: %s", args[index])
		}
	}
	return withVulnerabilities, portSpec, nil
}

func runQuickV2Scan(ctx context.Context, db *sql.DB, baseTask model.Scanner, target, scanType string, withVulnerabilities bool, portSpec string) error {
	service := schedule.NewTaskService(db, nil)
	task, run, err := service.Create(ctx, model.ScanTask{
		Target: target, ScanType: scanType, Mode: model.ScanTaskModeOnce,
		Config: model.ScanTaskConfig{
			PortSpec: portSpec, VulnerabilityOn: withVulnerabilities,
			NucleiTemplates: baseTask.NucleiTemplates, DNSResolveMode: baseTask.DNSResolveMode,
			DNSDenyCIDRs: append([]string(nil), baseTask.DNSDenyCIDRs...),
		},
	})
	if err != nil {
		return err
	}
	if run == nil {
		return errors.New("one-time V2 scan did not create a run")
	}
	fmt.Printf("ScanTask %d created; run %d queued (%s %s)\n", task.ID, run.ID, task.ScanType, task.Target)
	if err := executeLogicalScanTaskRun(ctx, db, baseTask, *run); err != nil {
		return err
	}
	completed, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil {
		return err
	}
	fmt.Printf("ScanTask run %d finished: %s (report: %s)\n", completed.ID, completed.Status, completed.ReportPath)
	if completed.Status != model.ScanTaskRunStatusSuccess {
		return fmt.Errorf("scan task run %d finished with status %s: %s", completed.ID, completed.Status, completed.ErrorMessage)
	}
	return nil
}

func printCLIUsage() {
	fmt.Println("usage: yscan [--home <dir>] scan <internal-ip|cidr> [--vuln] [--port-spec <ports>]")
	fmt.Println("       yscan subnet <internal-cidr> [--vuln] [--port-spec <ports>]")
	fmt.Println("       yscan schedule help")
	fmt.Println("       yscan server [listen_addr] [--allow-cidr <cidr>]...")
	fmt.Println("       yscan server start|stop|restart|status|logs|uninstall")
	fmt.Println("       yscan legacy-list|legacy-status|legacy-findings ...")
	fmt.Println("       yscan version")
	fmt.Println("       yscan upgrade [--from-home <legacy_home>]")
}

type preparedServerStartup struct {
	listener net.Listener
	policy   api.AccessPolicy
}

func validateServerStartup(args []string, runtimeConfig appRuntime.Config) (string, api.AccessPolicy, error) {
	addr := runtimeConfig.ListenAddress
	policy := api.AccessPolicy{TrustedCIDRs: append([]string(nil), runtimeConfig.AllowCIDRs...)}
	index := 1
	if len(args) >= 2 && strings.TrimSpace(args[1]) != "" && !strings.HasPrefix(strings.TrimSpace(args[1]), "--") {
		addr = strings.TrimSpace(args[1])
		index = 2
	}
	for ; index < len(args); index++ {
		if args[index] != "--allow-cidr" || index+1 >= len(args) {
			return "", api.AccessPolicy{}, errors.New("usage: yscan server [listen_addr] [--allow-cidr <cidr>]...")
		}
		policy.TrustedCIDRs = append(policy.TrustedCIDRs, strings.TrimSpace(args[index+1]))
		index++
	}
	if err := policy.Validate(addr); err != nil {
		return "", api.AccessPolicy{}, err
	}
	return addr, policy, nil
}

func prepareServerStartup(args []string, runtimeConfig appRuntime.Config) (*preparedServerStartup, error) {
	addr, policy, err := validateServerStartup(args, runtimeConfig)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &preparedServerStartup{listener: listener, policy: policy}, nil
}

func runByArgs(args []string, task model.Scanner, db *sql.DB, runtimeConfig appRuntime.Config, serverSession *appRuntime.ServerSession, preparedServer *preparedServerStartup, serverReady func() error) error {
	command := strings.ToLower(strings.TrimSpace(args[0]))
	switch command {
	case "help", "--help", "-h":
		printCLIUsage()
		return nil
	case "scan":
		if len(args) < 2 {
			return errors.New("usage: yscan [--templates <dir>] scan <internal-ip|cidr> [--vuln] [--port-spec <ports>]")
		}
		target := strings.TrimSpace(args[1])
		withVuln, portSpec, err := parseQuickScanFlags(args[2:])
		if err != nil {
			return err
		}
		if withVuln {
			warnIfNucleiMissing()
			warnIfNucleiTemplatesMissing(task.NucleiTemplates)
		}
		scanType := model.ScanTypeIP
		if strings.Contains(target, "/") {
			scanType = model.ScanTypeSubnet
		}
		return runQuickV2Scan(context.Background(), db, task, target, scanType, withVuln, portSpec)

	case "subnet":
		if len(args) < 2 {
			return errors.New("usage: yscan [--templates <dir>] subnet <internal-cidr> [--vuln] [--port-spec <ports>]")
		}
		target := strings.TrimSpace(args[1])
		withVuln, portSpec, err := parseQuickScanFlags(args[2:])
		if err != nil {
			return err
		}
		if withVuln {
			warnIfNucleiMissing()
			warnIfNucleiTemplatesMissing(task.NucleiTemplates)
		}
		return runQuickV2Scan(context.Background(), db, task, target, model.ScanTypeSubnet, withVuln, portSpec)

	case "vuln":
		return errors.New("legacy direct vulnerability tasks are disabled; use 'yscan scan <internal-ip> --vuln'")

	case "domain":
		return errors.New("domain collection is outside the V2 internal CAASM product boundary")

	case "list":
		return runScheduleCommand([]string{"list"}, task, db)
	case "status":
		return runScheduleCommand(append([]string{"show"}, args[1:]...), task, db)
	case "cancel", "findings", "report", "changes", "asset":
		return runScheduleCommand(append([]string{command}, args[1:]...), task, db)
	case "legacy-list":
		printTaskList(db)
		return nil
	case "legacy-status":
		if len(args) < 2 {
			return errors.New("usage: yscan legacy-status <legacy_task_id>")
		}
		taskID, err := strconv.ParseInt(strings.TrimSpace(args[1]), 10, 64)
		if err != nil {
			return fmt.Errorf("invalid legacy task id: %w", err)
		}
		printTaskStatus(db, taskID)
		return nil
	case "legacy-findings":
		if len(args) < 2 {
			return errors.New("usage: yscan legacy-findings <legacy_task_id> [severity]")
		}
		taskID, err := strconv.ParseInt(strings.TrimSpace(args[1]), 10, 64)
		if err != nil {
			return fmt.Errorf("invalid legacy task id: %w", err)
		}
		severity := ""
		if len(args) >= 3 {
			severity = args[2]
		}
		printTaskFindings(db, taskID, severity)
		return nil

	case "server":
		if serverSession == nil || preparedServer == nil || preparedServer.listener == nil {
			return errors.New("Server lifecycle session is unavailable")
		}
		policy := preparedServer.policy
		listenHost, _, _ := net.SplitHostPort(preparedServer.listener.Addr().String())
		policy.LocalHealthAddress = listenHost
		policy.LocalHealthToken = serverSession.State().HealthToken
		serviceContext, stopService := signal.NotifyContext(context.Background(), appRuntime.ShutdownSignals()...)
		defer stopService()
		var ownedRuns serverRunRegistry
		runner := schedule.NewRunner(db, nil)
		runner.OnClaim = func(ctx context.Context, run model.ScanTaskRun) {
			if err := executeLogicalScanTaskRun(ctx, db, task, run); err != nil {
				log.Printf("scheduled ScanTask run %d failed: %v", run.ID, err)
			}
		}
		runner.OnRecovered = func(run model.ScanTaskRun) error { return generateRecoveredScanTaskRunReport(db, run) }
		service := schedule.NewTaskService(db, nil).WithDefaultNucleiTemplates(runtimeConfig.NucleiTemplates)
		if err := runner.RecoverStartupState(); err != nil {
			return fmt.Errorf("schedule startup recovery: %w", err)
		}
		serviceErr := runAPIAndSchedulerWithDrain(serviceContext, func(ctx context.Context, drained func() error) error {
			return api.StartServerWithScanTasksAndAccessPolicyListener(ctx, db, preparedServer.listener, func(taskType, target string) (int64, error) {
				return runTaskAsync(db, task, taskType, target)
			}, service, func(ctx context.Context, run model.ScanTaskRun) {
				ownedRuns.track(run.ID)
				if err := executeLogicalScanTaskRun(ctx, db, task, run); err != nil {
					if errors.Is(err, schedule.ErrGlobalConcurrencyUnavailable) {
						return
					}
					log.Printf("one-time ScanTask run %d failed: %v", run.ID, err)
				}
			}, policy, serverReady, drained)
		}, runner.RunLoop)
		if shutdownErr := ownedRuns.cancelQueued(db); shutdownErr != nil {
			if serviceErr != nil {
				return fmt.Errorf("%v; cancel remaining Server queued runs: %w", serviceErr, shutdownErr)
			}
			return fmt.Errorf("cancel remaining Server queued runs: %w", shutdownErr)
		}
		if serviceErr != nil && serviceContext.Err() == nil {
			_ = serverSession.MarkDegraded(serviceErr.Error())
		}
		return serviceErr

	case "schedule":
		return runScheduleCommand(args[1:], task, db)

	case "fingerprint":
		return runFingerprintCommand(args[1:], db)

	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}

func runAPIAndSchedulerWithDrain(parent context.Context, runAPI func(context.Context, func() error) error, runScheduler func(context.Context) error) error {
	apiContext, stopAPI := context.WithCancel(context.Background())
	schedulerContext, stopScheduler := context.WithCancel(context.Background())
	defer stopAPI()
	defer stopScheduler()
	go func() {
		<-parent.Done()
		stopAPI()
	}()
	results := make(chan serviceComponentResult, 2)
	go func() {
		results <- serviceComponentResult{name: "API server", err: runAPI(apiContext, func() error { stopScheduler(); return nil })}
	}()
	go func() {
		results <- serviceComponentResult{name: "schedule runner", err: runScheduler(schedulerContext)}
	}()
	first := <-results
	if first.name == "schedule runner" {
		stopAPI()
	} else {
		stopScheduler()
	}
	second := <-results
	if parent.Err() != nil {
		for _, result := range []serviceComponentResult{first, second} {
			if result.err != nil && !errors.Is(result.err, context.Canceled) {
				return fmt.Errorf("%s stopped: %w", result.name, result.err)
			}
		}
		return nil
	}
	if first.err != nil {
		return fmt.Errorf("%s stopped: %w", first.name, first.err)
	}
	return fmt.Errorf("%s stopped unexpectedly", first.name)
}

type serviceComponentResult struct {
	name string
	err  error
}

func recoverThenRunAPIAndScheduler(parent context.Context, recoverStartup func() error, runAPI, runScheduler func(context.Context) error) error {
	if err := recoverStartup(); err != nil {
		return fmt.Errorf("schedule startup recovery: %w", err)
	}
	return runAPIAndScheduler(parent, runAPI, runScheduler)
}

func runAPIAndScheduler(parent context.Context, runAPI, runScheduler func(context.Context) error) error {
	serviceContext, stopService := context.WithCancel(parent)
	defer stopService()

	results := make(chan serviceComponentResult, 2)
	start := func(name string, run func(context.Context) error) {
		go func() { results <- serviceComponentResult{name: name, err: run(serviceContext)} }()
	}
	start("API server", runAPI)
	start("schedule runner", runScheduler)

	first := <-results
	parentStopped := parent.Err() != nil
	stopService()
	select {
	case second := <-results:
		if parentStopped {
			for _, result := range []serviceComponentResult{first, second} {
				if result.err != nil && !errors.Is(result.err, context.Canceled) {
					return fmt.Errorf("%s stopped: %w", result.name, result.err)
				}
			}
			return nil
		}
	case <-time.After(10 * time.Second):
		return fmt.Errorf("%s stopped, but the other service component did not stop within 10 seconds", first.name)
	}

	if first.err != nil {
		return fmt.Errorf("%s stopped: %w", first.name, first.err)
	}
	return fmt.Errorf("%s stopped unexpectedly", first.name)
}

func runScheduleCommand(args []string, baseTask model.Scanner, db *sql.DB) error {
	return schedule.RunCLI(context.Background(), db, args, schedule.CLIConfig{
		NucleiTemplates: baseTask.NucleiTemplates,
		DNSResolveMode:  baseTask.DNSResolveMode,
		DNSDenyCIDRs:    baseTask.DNSDenyCIDRs,
	}, func(ctx context.Context, run model.ScanTaskRun) error {
		if run.Config.VulnerabilityOn {
			warnIfNucleiMissing()
			warnIfNucleiTemplatesMissing(run.Config.NucleiTemplates)
		}
		return executeLogicalScanTaskRun(ctx, db, baseTask, run)
	}, os.Stdout)
}

func runFingerprintCommand(args []string, db *sql.DB) error {
	// T258+ supplies embedded production manifests and adapters. Until then the
	// command remains usable for listing the migrated legacy source, while
	// import/upgrade correctly reject unknown non-embedded source revisions.
	registry, err := fingerprint.NewEmbeddedRegistry(db)
	if err != nil {
		return fmt.Errorf("load embedded fingerprint registry: %w", err)
	}
	return fingerprint.RunCLI(context.Background(), registry, args, os.Stdout)
}
