package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
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

type cliConfig struct {
	Templates      string
	DNSResolveMode string
	DNSDenyCIDRs   []string
	Home           string
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
		log.Print("[WARN] 可通过 --templates <dir> 或 NUCLEI_TEMPLATES 环境变量指定模板目录。")
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

func parseCLIConfig(args []string) ([]string, cliConfig) {
	cfg := cliConfig{DNSResolveMode: domain.DNSModeHybrid}
	if len(args) == 0 {
		return args, cfg
	}

	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		current := strings.TrimSpace(args[i])
		switch {
		case current == "--templates":
			if i+1 < len(args) {
				cfg.Templates = strings.TrimSpace(args[i+1])
				i++
			}
		case strings.HasPrefix(current, "--templates="):
			cfg.Templates = strings.TrimSpace(strings.TrimPrefix(current, "--templates="))
		case current == "--dns-mode":
			if i+1 < len(args) {
				cfg.DNSResolveMode = strings.TrimSpace(strings.ToLower(args[i+1]))
				i++
			}
		case strings.HasPrefix(current, "--dns-mode="):
			cfg.DNSResolveMode = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(current, "--dns-mode=")))
		case current == "--dns-deny-cidr":
			if i+1 < len(args) {
				cfg.DNSDenyCIDRs = append(cfg.DNSDenyCIDRs, strings.TrimSpace(args[i+1]))
				i++
			}
		case strings.HasPrefix(current, "--dns-deny-cidr="):
			cfg.DNSDenyCIDRs = append(cfg.DNSDenyCIDRs, strings.TrimSpace(strings.TrimPrefix(current, "--dns-deny-cidr=")))
		case current == "--home":
			if i+1 < len(args) {
				cfg.Home = strings.TrimSpace(args[i+1])
				i++
			}
		case strings.HasPrefix(current, "--home="):
			cfg.Home = strings.TrimSpace(strings.TrimPrefix(current, "--home="))
		default:
			filtered = append(filtered, args[i])
		}
	}

	return filtered, cfg
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

func executeLogicalScanTaskRun(ctx context.Context, db *sql.DB, baseTask model.Scanner, run model.ScanTaskRun) error {
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

func runMainArgs(rawArgs []string) error {
	args, cfg := parseCLIConfig(rawArgs)
	if len(args) == 0 || isTopLevelHelp(args) {
		printCLIUsage()
		return nil
	}
	if isTopLevelVersion(args) {
		fmt.Println("yscan development")
		return nil
	}
	homeOverride := cfg.Home
	if homeOverride == "" {
		homeOverride = strings.TrimSpace(os.Getenv("YSCAN_HOME"))
	}
	paths, err := appRuntime.ResolveHome("", homeOverride)
	if err != nil {
		return err
	}
	overrides := appRuntime.ConfigOverrides{}
	if cfg.Templates != "" {
		overrides[appRuntime.ConfigNucleiTemplates] = cfg.Templates
	}
	runtimeConfig, err := appRuntime.LoadConfig(paths, overrides, os.LookupEnv)
	if err != nil {
		return err
	}
	if err := paths.Prepare(); err != nil {
		return err
	}
	report.ConfigureHomeDirectory(paths.ReportsDir)
	isServerCommand := len(args) > 0 && strings.EqualFold(strings.TrimSpace(args[0]), "api")
	var serverSession *appRuntime.ServerSession
	if isServerCommand {
		listenAddress := runtimeConfig.ListenAddress
		if len(args) >= 2 && strings.TrimSpace(args[1]) != "" {
			listenAddress = strings.TrimSpace(args[1])
		}
		serverSession, err = appRuntime.AcquireServerSessionForStartup(paths, listenAddress, runtimeConfig.MaxConcurrency, 2*time.Minute)
		if err != nil {
			return err
		}
		defer serverSession.Close()
	} else {
		effective, changed, err := appRuntime.ActiveServerConcurrency(paths, runtimeConfig.MaxConcurrency)
		if err != nil {
			return fmt.Errorf("read active Server configuration: %w", err)
		}
		if changed {
			log.Printf("[INFO] using active Server concurrency %d; configuration changes require a Server restart", effective)
		}
		runtimeConfig.MaxConcurrency = effective
	}
	command := strings.ToLower(strings.TrimSpace(args[0]))
	migrationPending, err := storage.HomeMigrationPending(paths)
	if err != nil {
		return err
	}
	if command == "upgrade" || migrationPending || serverSession != nil {
		migrated, err := storage.UpgradeLegacyHome(storage.HomeUpgradeOptions{
			Paths: paths, ServerLockHeld: serverSession != nil,
			InitializeContent: func(database *sql.DB) error {
				_, err := fingerprint.InitializeEmbeddedSourcesIfEmpty(context.Background(), database)
				return err
			},
		})
		if err != nil {
			return err
		}
		if command == "upgrade" {
			if migrated {
				fmt.Printf("yscan database upgraded to %s\n", paths.Database)
			} else {
				fmt.Println("yscan database is already current")
			}
			return nil
		}
	}
	managedDatabase, err := storage.OpenManagedDatabase(storage.ManagedDatabaseOptions{
		Paths: paths, BusyTimeout: runtimeConfig.SQLiteBusyTimeout, ServerLockHeld: serverSession != nil,
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
	return runByArgs(args, task, db, runtimeConfig, serverSession)
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
	fmt.Println("       yscan api [listen_addr] [--allow-cidr <cidr>]...")
	fmt.Println("       yscan legacy-list|legacy-status|legacy-findings ...")
	fmt.Println("       yscan version")
	fmt.Println("       yscan upgrade")
}

func runByArgs(args []string, task model.Scanner, db *sql.DB, runtimeConfig appRuntime.Config, serverSession *appRuntime.ServerSession) error {
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

	case "api":
		addr := runtimeConfig.ListenAddress
		policy := api.AccessPolicy{TrustedCIDRs: append([]string(nil), runtimeConfig.AllowCIDRs...)}
		if len(args) >= 2 && strings.TrimSpace(args[1]) != "" {
			addr = strings.TrimSpace(args[1])
		}
		for index := 2; index < len(args); index++ {
			if args[index] != "--allow-cidr" || index+1 >= len(args) {
				return errors.New("usage: yscan api [listen_addr] [--allow-cidr <cidr>]...")
			}
			policy.TrustedCIDRs = append(policy.TrustedCIDRs, strings.TrimSpace(args[index+1]))
			index++
		}
		if serverSession == nil {
			return errors.New("Server lifecycle session is unavailable")
		}
		serviceContext, stopService := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stopService()
		runner := schedule.NewRunner(db, nil)
		runner.OnClaim = func(ctx context.Context, run model.ScanTaskRun) {
			if err := executeLogicalScanTaskRun(ctx, db, task, run); err != nil {
				log.Printf("scheduled ScanTask run %d failed: %v", run.ID, err)
			}
		}
		runner.OnRecovered = func(run model.ScanTaskRun) error { return generateRecoveredScanTaskRunReport(db, run) }
		service := schedule.NewTaskService(db, nil)
		serviceErr := recoverThenRunAPIAndScheduler(serviceContext, runner.RecoverStartupState, func(ctx context.Context) error {
			return api.StartServerWithScanTasksAndAccessPolicyContextReady(ctx, db, addr, func(taskType, target string) (int64, error) {
				return runTaskAsync(db, task, taskType, target)
			}, service, func(ctx context.Context, run model.ScanTaskRun) {
				if err := executeLogicalScanTaskRun(ctx, db, task, run); err != nil {
					if errors.Is(err, schedule.ErrGlobalConcurrencyUnavailable) {
						return
					}
					log.Printf("one-time ScanTask run %d failed: %v", run.ID, err)
				}
			}, policy, serverSession.MarkRunning)
		}, runner.RunLoop)
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
