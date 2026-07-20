package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golandproject/yscan/internal/api"
	"golandproject/yscan/internal/assist"
	"golandproject/yscan/internal/domain"
	"golandproject/yscan/internal/identify"
	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/pipeline"
	"golandproject/yscan/internal/report"
	"golandproject/yscan/internal/scan"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/vuln"
	"golandproject/yscan/internal/workflow"
)

var errTaskCanceled = errors.New("task canceled")

type cliConfig struct {
	Templates      string
	DNSResolveMode string
	DNSDenyCIDRs   []string
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
	err := executeTask(db, taskID, baseTask, taskType, target)
	if err != nil {
		if errors.Is(err, errTaskCanceled) {
			if upErr := storage.UpdateTaskStatus(db, taskID, model.TaskStatusCanceled, ""); upErr != nil {
				log.Printf("任务取消状态更新失败: %v", upErr)
			}
			fmt.Printf("Task %d canceled\n", taskID)
			return
		}

		if upErr := storage.UpdateTaskStatus(db, taskID, model.TaskStatusFailed, err.Error()); upErr != nil {
			log.Printf("任务失败状态更新失败: %v", upErr)
		}
		fmt.Printf("Task %d failed: %v\n", taskID, err)
		return
	}

	reportPath, err := report.GenerateTaskReport(db, taskID, report.DefaultDirectory)
	if err != nil {
		if upErr := storage.UpdateTaskStatus(db, taskID, model.TaskStatusFailed, "generate report: "+err.Error()); upErr != nil {
			log.Printf("任务报告失败状态更新失败: %v", upErr)
		}
		fmt.Printf("Task %d failed to generate report: %v\n", taskID, err)
		return
	}

	if err := storage.UpdateTaskStatus(db, taskID, model.TaskStatusSuccess, ""); err != nil {
		log.Printf("任务完成状态更新失败: %v", err)
		return
	}

	fmt.Printf("Task %d finished: success (report: %s)\n", taskID, reportPath)
}

func executeTask(db *sql.DB, taskID int64, baseTask model.Scanner, taskType, target string) error {
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
		if _, err := portScan(baseTask, db); err != nil {
			return err
		}
		_ = storage.UpdateTaskProgress(db, taskID, 100)
		return nil

	case model.TaskTypeScanIPVuln:
		_ = storage.UpdateTaskProgress(db, taskID, 20)
		baseTask.IP = target
		openPorts, err := portScan(baseTask, db)
		if err != nil {
			return err
		}
		_ = storage.UpdateTaskProgress(db, taskID, 60)

		if canceled, err := storage.IsTaskCanceled(db, taskID); err == nil && canceled {
			return errTaskCanceled
		}

		scanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
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
		return runSubnetTask(db, taskID, baseTask, target, false)

	case model.TaskTypeScanSubnetVuln:
		return runSubnetTask(db, taskID, baseTask, target, true)

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

		scanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
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
		_ = storage.UpdateTaskProgress(db, taskID, 20)
		_ = pipeline.CollectSubdomains(db, target, pipeline.DomainCollectionOptions{
			ResolvePolicy: domain.ResolvePolicy{
				Mode:      baseTask.DNSResolveMode,
				DenyCIDRs: baseTask.DNSDenyCIDRs,
			},
		})
		_ = storage.UpdateTaskProgress(db, taskID, 100)
		return nil

	case model.TaskTypeCollectAndScan:
		_ = storage.UpdateTaskProgress(db, taskID, 20)
		ips := pipeline.CollectSubdomains(db, target, pipeline.DomainCollectionOptions{
			ResolvePolicy: domain.ResolvePolicy{
				Mode:      baseTask.DNSResolveMode,
				DenyCIDRs: baseTask.DNSDenyCIDRs,
			},
		})
		if len(ips) == 0 {
			_ = storage.UpdateTaskProgress(db, taskID, 100)
			return nil
		}

		for i, ip := range ips {
			canceled, err := storage.IsTaskCanceled(db, taskID)
			if err != nil {
				return err
			}
			if canceled {
				return errTaskCanceled
			}

			baseTask.IP = ip
			if _, err := domainScan(baseTask, db); err != nil {
				return err
			}

			progress := 20 + int(float64(i+1)/float64(len(ips))*80)
			_ = storage.UpdateTaskProgress(db, taskID, progress)
		}
		return nil

	case model.TaskTypeCollectScanVuln:
		_ = storage.UpdateTaskProgress(db, taskID, 20)
		ips := pipeline.CollectSubdomains(db, target, pipeline.DomainCollectionOptions{
			ResolvePolicy: domain.ResolvePolicy{
				Mode:      baseTask.DNSResolveMode,
				DenyCIDRs: baseTask.DNSDenyCIDRs,
			},
		})
		if len(ips) == 0 {
			_ = storage.UpdateTaskProgress(db, taskID, 100)
			return nil
		}

		for i, ip := range ips {
			canceled, err := storage.IsTaskCanceled(db, taskID)
			if err != nil {
				return err
			}
			if canceled {
				return errTaskCanceled
			}

			baseTask.IP = ip
			openPorts, err := domainScan(baseTask, db)
			if err != nil {
				return err
			}

			scanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
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

func domainScan(task model.Scanner, db *sql.DB) ([]model.ScanResult, error) {
	fmt.Printf("\n=== 开始域名扫描 %s ===\n", task.IP)

	if assist.IsHostAlive(task.IP) {
		openPorts := scan.Run(task.IP, task.Network)
		if err := storage.SaveDomainScanResult(db, task.IP, openPorts); err != nil {
			log.Printf("保存扫描结果失败: %v", err)
			return openPorts, err
		}
		persistOpenPorts(db, openPorts)
		return openPorts, nil
	}

	fmt.Println("Can't ping")
	if assist.IsHostAliveTCP(task.IP) {
		openPorts := scan.Run(task.IP, task.Network)
		if err := storage.SaveDomainScanResult(db, task.IP, openPorts); err != nil {
			log.Printf("保存扫描结果失败: %v", err)
			return openPorts, err
		}
		persistOpenPorts(db, openPorts)
		return openPorts, nil
	}

	log.Print("没有进入TCP连接")
	fmt.Printf("%s is not alive\n", task.IP)
	return nil, fmt.Errorf("%s is not alive", task.IP)
}

func portScan(task model.Scanner, db *sql.DB) ([]model.ScanResult, error) {
	if assist.IsHostAlive(task.IP) || assist.IsHostAliveTCP(task.IP) {
		openPorts := scan.Run(task.IP, task.Network)
		persistOpenPorts(db, openPorts)
		return openPorts, nil
	}

	log.Print("没有进入TCP连接")
	fmt.Printf("%s is not alive\n", task.IP)
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

func runSubnetTask(db *sql.DB, taskID int64, task model.Scanner, cidr string, withVuln bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
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

func main() {
	db, err := storage.InitDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	identify.SetFingerprintMatcher(func(banner string) string {
		return storage.MatchFingerprint(db, banner)
	})

	task := model.Scanner{Network: "tcp"}

	args, cfg := parseCLIConfig(os.Args[1:])
	task.NucleiTemplates = cfg.Templates
	task.DNSResolveMode = cfg.DNSResolveMode
	task.DNSDenyCIDRs = cfg.DNSDenyCIDRs
	if len(args) > 0 {
		runByArgs(args, task, db)
		return
	}

	runInteractive(task, db)
}

func runByArgs(args []string, task model.Scanner, db *sql.DB) {
	command := strings.ToLower(strings.TrimSpace(args[0]))
	switch command {
	case "scan":
		if len(args) < 2 {
			fmt.Println("usage: yscan [--templates <dir>] [--dns-mode internal|external|hybrid] scan <ip|cidr> [--vuln]")
			return
		}
		target := strings.TrimSpace(args[1])
		withVuln := hasFlag(args[2:], "--vuln")
		if withVuln {
			warnIfNucleiMissing()
			warnIfNucleiTemplatesMissing(task.NucleiTemplates)
		}
		runTask(db, task, taskTypeForScan(target, withVuln), target)

	case "subnet":
		if len(args) < 2 {
			fmt.Println("usage: yscan [--templates <dir>] subnet <cidr> [--vuln]")
			return
		}
		target := strings.TrimSpace(args[1])
		if !pipeline.IsIPv4CIDR(target) {
			fmt.Printf("invalid cidr: %s\n", target)
			return
		}
		withVuln := hasFlag(args[2:], "--vuln")
		if withVuln {
			warnIfNucleiMissing()
			warnIfNucleiTemplatesMissing(task.NucleiTemplates)
		}
		runTask(db, task, taskTypeForSubnet(withVuln), target)

	case "vuln":
		if len(args) < 2 {
			fmt.Println("usage: yscan [--templates <dir>] [--dns-mode internal|external|hybrid] vuln <ip|ip:port>")
			return
		}
		warnIfNucleiMissing()
		warnIfNucleiTemplatesMissing(task.NucleiTemplates)
		runTask(db, task, model.TaskTypeVulnIP, strings.TrimSpace(args[1]))

	case "domain":
		if len(args) < 2 {
			fmt.Println("usage: yscan [--templates <dir>] [--dns-mode internal|external|hybrid] [--dns-deny-cidr <cidr>] domain <domain> [--scan] [--vuln]")
			return
		}
		domainName := strings.TrimSpace(args[1])
		warnIfExternalDNSPolicy(task)
		if hasFlag(args[2:], "--scan") {
			if hasFlag(args[2:], "--vuln") {
				warnIfNucleiMissing()
				warnIfNucleiTemplatesMissing(task.NucleiTemplates)
				runTask(db, task, model.TaskTypeCollectScanVuln, domainName)
				return
			}
			runTask(db, task, model.TaskTypeCollectAndScan, domainName)
			return
		}
		runTask(db, task, model.TaskTypeCollectDomain, domainName)

	case "cancel":
		if len(args) < 2 {
			fmt.Println("usage: yscan cancel <task_id>")
			return
		}
		taskID, err := strconv.ParseInt(strings.TrimSpace(args[1]), 10, 64)
		if err != nil {
			fmt.Printf("invalid task id: %v\n", err)
			return
		}
		if err := storage.CancelTask(db, taskID); err != nil {
			log.Printf("取消任务失败: %v", err)
			return
		}
		fmt.Printf("Task %d canceled\n", taskID)

	case "status":
		if len(args) < 2 {
			fmt.Println("usage: yscan status <task_id>")
			return
		}
		taskID, err := strconv.ParseInt(strings.TrimSpace(args[1]), 10, 64)
		if err != nil {
			fmt.Printf("invalid task id: %v\n", err)
			return
		}
		printTaskStatus(db, taskID)

	case "api":
		addr := ":8080"
		if len(args) >= 2 && strings.TrimSpace(args[1]) != "" {
			addr = strings.TrimSpace(args[1])
		}
		if err := api.StartServer(db, addr, func(taskType, target string) (int64, error) {
			return runTaskAsync(db, task, taskType, target)
		}); err != nil {
			log.Printf("API server stopped: %v", err)
		}

	case "findings":
		if len(args) < 2 {
			fmt.Println("usage: yscan findings <task_id> [severity]")
			return
		}
		taskID, err := strconv.ParseInt(strings.TrimSpace(args[1]), 10, 64)
		if err != nil {
			fmt.Printf("invalid task id: %v\n", err)
			return
		}
		severity := ""
		if len(args) >= 3 {
			severity = args[2]
		}
		printTaskFindings(db, taskID, severity)

	case "list":
		printTaskList(db)

	default:
		fmt.Println("please enter a true command.")
	}
}

func runInteractive(task model.Scanner, db *sql.DB) {
	var command string
	fmt.Print("Please enter a command(domain/scan/subnet/vuln/status/cancel/list/findings): ")
	fmt.Scan(&command)

	if command == "scan" {
		fmt.Print("Please enter your ip or cidr:")
		fmt.Scan(&task.IP)
		var vulnFlag string
		fmt.Print("Enable vuln scan? (y/N):")
		fmt.Scan(&vulnFlag)
		withVuln := strings.EqualFold(strings.TrimSpace(vulnFlag), "y")
		if withVuln {
			warnIfNucleiMissing()
			warnIfNucleiTemplatesMissing(task.NucleiTemplates)
		}
		runTask(db, task, taskTypeForScan(task.IP, withVuln), task.IP)
		return
	}

	if command == "vuln" {
		fmt.Print("Please enter target (ip or ip:port):")
		fmt.Scan(&task.IP)
		warnIfNucleiMissing()
		runTask(db, task, model.TaskTypeVulnIP, task.IP)
		return
	}

	if command == "subnet" {
		var cidr string
		fmt.Print("Please enter your cidr:")
		fmt.Scan(&cidr)
		if !pipeline.IsIPv4CIDR(cidr) {
			fmt.Printf("invalid cidr: %s\n", cidr)
			return
		}
		var vulnFlag string
		fmt.Print("Enable vuln scan? (y/N):")
		fmt.Scan(&vulnFlag)
		withVuln := strings.EqualFold(strings.TrimSpace(vulnFlag), "y")
		if withVuln {
			warnIfNucleiMissing()
			warnIfNucleiTemplatesMissing(task.NucleiTemplates)
		}
		runTask(db, task, taskTypeForSubnet(withVuln), cidr)
		return
	}

	if command == "domain" {
		var domainName string
		fmt.Print("Please enter your domain: ")
		fmt.Scan(&domainName)

		answer := "n"
		fmt.Print("Subdomain collecting is done. Do the domains need to scan?(y/N): ")
		fmt.Scan(&answer)
		if strings.EqualFold(strings.TrimSpace(answer), "y") {
			var vulnFlag string
			fmt.Print("Enable vuln scan for collected ips? (y/N):")
			fmt.Scan(&vulnFlag)
			if strings.EqualFold(strings.TrimSpace(vulnFlag), "y") {
				warnIfNucleiMissing()
				runTask(db, task, model.TaskTypeCollectScanVuln, domainName)
				return
			}
			runTask(db, task, model.TaskTypeCollectAndScan, domainName)
			return
		}
		runTask(db, task, model.TaskTypeCollectDomain, domainName)
		return
	}

	if command == "status" {
		var taskIDStr string
		fmt.Print("Please enter your task id:")
		fmt.Scan(&taskIDStr)
		taskID, err := strconv.ParseInt(strings.TrimSpace(taskIDStr), 10, 64)
		if err != nil {
			fmt.Printf("invalid task id: %v\n", err)
			return
		}
		printTaskStatus(db, taskID)
		return
	}

	if command == "cancel" {
		var taskIDStr string
		fmt.Print("Please enter your task id:")
		fmt.Scan(&taskIDStr)
		taskID, err := strconv.ParseInt(strings.TrimSpace(taskIDStr), 10, 64)
		if err != nil {
			fmt.Printf("invalid task id: %v\n", err)
			return
		}
		if err := storage.CancelTask(db, taskID); err != nil {
			log.Printf("取消任务失败: %v", err)
			return
		}
		fmt.Printf("Task %d canceled\n", taskID)
		return
	}

	if command == "findings" {
		var taskIDStr string
		fmt.Print("Please enter your task id:")
		fmt.Scan(&taskIDStr)
		taskID, err := strconv.ParseInt(strings.TrimSpace(taskIDStr), 10, 64)
		if err != nil {
			fmt.Printf("invalid task id: %v\n", err)
			return
		}
		var severity string
		fmt.Print("Please enter severity filter(optional, use - for none, e.g. high):")
		fmt.Scan(&severity)
		if strings.TrimSpace(severity) == "-" {
			severity = ""
		}
		printTaskFindings(db, taskID, severity)
		return
	}

	if command == "list" {
		printTaskList(db)
		return
	}

	fmt.Println("please enter a true command.")
}

func taskTypeForScan(target string, withVuln bool) string {
	if pipeline.IsIPv4CIDR(target) {
		return taskTypeForSubnet(withVuln)
	}
	if withVuln {
		return model.TaskTypeScanIPVuln
	}
	return model.TaskTypeScanIP
}

func taskTypeForSubnet(withVuln bool) string {
	if withVuln {
		return model.TaskTypeScanSubnetVuln
	}
	return model.TaskTypeScanSubnet
}
