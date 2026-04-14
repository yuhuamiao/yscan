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
	"golandproject/yscan/internal/scan"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/vuln"
)

var errTaskCanceled = errors.New("task canceled")

func aggregateSubdomains(results []domain.CollectResult) map[string]*domain.CollectResult {
	res := make(map[string]*domain.CollectResult)

	for _, r := range results {
		key := r.Subdomain
		agg, ok := res[key]
		if !ok {
			agg = &domain.CollectResult{
				Subdomain: r.Subdomain,
				IPs:       r.IPs,
				FirstSeen: r.FirstSeen,
				Sources:   r.Sources,
			}
			res[key] = agg
			continue
		}

		if agg.FirstSeen.IsZero() || (!r.FirstSeen.IsZero() && r.FirstSeen.Before(agg.FirstSeen)) {
			agg.FirstSeen = r.FirstSeen
		}

		ipSet := make(map[string]bool)
		for _, ip := range agg.IPs {
			ipSet[ip.String()] = true
		}
		for _, ip := range r.IPs {
			s := ip.String()
			if !ipSet[s] {
				ipSet[s] = true
				agg.IPs = append(agg.IPs, ip)
			}
		}

		sourceSet := make(map[string]bool)
		for _, s := range agg.Sources {
			sourceSet[s] = true
		}
		for _, s := range r.Sources {
			if !sourceSet[s] {
				sourceSet[s] = true
				agg.Sources = append(agg.Sources, s)
			}
		}
	}
	return res
}

func collectSubdomains(db *sql.DB, domainName string) []string {
	domainName = strings.TrimSpace(domainName)
	if domainName == "" {
		log.Print("域名不能为空")
		return nil
	}

	var results []domain.CollectResult

	if crtResults, err := (&domain.CRTshCollector{}).Collect(domainName, 30*time.Second); err == nil {
		results = append(results, crtResults...)
	}

	if searchResults, err := domain.NewSearchEngineCollector().Collect(domainName, 30*time.Second); err == nil {
		fmt.Printf("[DEBUG] 搜索引擎结果数量: %d\n", len(searchResults))
		results = append(results, searchResults...)
	} else {
		log.Printf("搜索引擎收集错误: %v", err)
	}

	uniqueIPs := make(map[string]bool)
	var ipsToScan []string

	aggregated := aggregateSubdomains(results)

	for _, res := range aggregated {
		fmt.Printf("[%s] %s (IPs: %v)\n",
			res.FirstSeen.Format("2006-01-02"),
			res.Subdomain,
			res.IPs)

		domainID, err := storage.SaveDomainInfo(db, domainName, res.Subdomain,
			strings.HasPrefix(res.Subdomain, "*."),
			"",
			strings.Join(res.Sources, ","),
		)
		if err != nil {
			log.Printf("保存子域名失败 %s: %v", res.Subdomain, err)
			continue
		}

		for _, ip := range res.IPs {
			ipStr := ip.String()
			if ip.To4() == nil {
				continue
			}

			if err := storage.SaveDomainIP(db, domainID, ipStr, res.Subdomain, nil); err != nil {
				log.Printf("保存IP关联失败 %s: %v", ipStr, err)
			}

			if !uniqueIPs[ipStr] {
				uniqueIPs[ipStr] = true
				ipsToScan = append(ipsToScan, ipStr)
			}
		}
	}

	return ipsToScan
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

	if err := storage.UpdateTaskStatus(db, taskID, model.TaskStatusSuccess, ""); err != nil {
		log.Printf("任务完成状态更新失败: %v", err)
		return
	}

	fmt.Printf("Task %d finished: success\n", taskID)
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
		findings, err := vuln.RunNucleiForOpenPorts(scanCtx, baseTask.IP, openPorts)
		cancel()
		if err != nil {
			return err
		}
		if err := storage.SaveNucleiFindings(db, taskID, findings); err != nil {
			return err
		}
		_ = storage.UpdateTaskProgress(db, taskID, 100)
		return nil

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
		findings, err := vuln.RunNucleiForOpenPorts(scanCtx, ip, openPorts)
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
		_ = collectSubdomains(db, target)
		_ = storage.UpdateTaskProgress(db, taskID, 100)
		return nil

	case model.TaskTypeCollectAndScan:
		_ = storage.UpdateTaskProgress(db, taskID, 20)
		ips := collectSubdomains(db, target)
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
		ips := collectSubdomains(db, target)
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
			findings, err := vuln.RunNucleiForOpenPorts(scanCtx, baseTask.IP, openPorts)
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

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if strings.EqualFold(strings.TrimSpace(a), flag) {
			return true
		}
	}
	return false
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
		if result.Service == "unknown" {
			log.Printf("跳过未识别服务 %s", result.Address)
			continue
		}
		if err := storage.SaveResult(db, result); err != nil {
			log.Printf("存储失败 %s: %v", result.Address, err)
		} else {
			log.Printf("成功储存 %s (%s)", result.Address, result.Service)
		}
	}
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

	args := os.Args[1:]
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
			fmt.Println("usage: yscan scan <ip> [--vuln]")
			return
		}
		target := strings.TrimSpace(args[1])
		if hasFlag(args[2:], "--vuln") {
			warnIfNucleiMissing()
			runTask(db, task, model.TaskTypeScanIPVuln, target)
			return
		}
		runTask(db, task, model.TaskTypeScanIP, target)

	case "vuln":
		if len(args) < 2 {
			fmt.Println("usage: yscan vuln <ip|ip:port>")
			return
		}
		warnIfNucleiMissing()
		runTask(db, task, model.TaskTypeVulnIP, strings.TrimSpace(args[1]))

	case "domain":
		if len(args) < 2 {
			fmt.Println("usage: yscan domain <domain> [--scan] [--vuln]")
			return
		}
		domainName := strings.TrimSpace(args[1])
		if hasFlag(args[2:], "--scan") {
			if hasFlag(args[2:], "--vuln") {
				warnIfNucleiMissing()
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
	fmt.Print("Please enter a command(domain/scan/vuln/status/cancel/list/findings): ")
	fmt.Scan(&command)

	if command == "scan" {
		fmt.Print("Please enter your ip:")
		fmt.Scan(&task.IP)
		var vulnFlag string
		fmt.Print("Enable vuln scan? (y/N):")
		fmt.Scan(&vulnFlag)
		if strings.EqualFold(strings.TrimSpace(vulnFlag), "y") {
			warnIfNucleiMissing()
			runTask(db, task, model.TaskTypeScanIPVuln, task.IP)
			return
		}
		runTask(db, task, model.TaskTypeScanIP, task.IP)
		return
	}

	if command == "vuln" {
		fmt.Print("Please enter target (ip or ip:port):")
		fmt.Scan(&task.IP)
		warnIfNucleiMissing()
		runTask(db, task, model.TaskTypeVulnIP, task.IP)
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
