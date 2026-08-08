package scan

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golandproject/yscan/internal/assist"
	"golandproject/yscan/internal/identify"
	"golandproject/yscan/internal/model"
)

var internalBaselinePorts = []int{
	21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 161,
	389, 443, 445, 464, 465, 500, 587, 636, 873, 902, 912, 993, 995,
	1433, 1521, 2049, 2181, 2375, 2376, 3306, 3389, 4369, 5432, 5601,
	5672, 5900, 5984, 5985, 5986, 6379, 6443, 7001, 8080, 8443, 8888,
	9090, 9200, 9300, 11211, 27017,
}

const (
	fullPortCount         = 65535
	fullPortWorkerMinimum = 128
	fullPortWorkerMaximum = 512
	fullPortProbeTimeout  = 1500 * time.Millisecond
	fullPortBudgetMargin  = 2 * time.Minute
)

type PortScanOutcome struct {
	Results        []model.ScanResult
	AttemptedPorts int
	TotalPorts     int
}

func (outcome PortScanOutcome) Complete() bool {
	return outcome.TotalPorts > 0 && outcome.AttemptedPorts == outcome.TotalPorts
}

// ParsePortSpec accepts comma-separated ports and inclusive ranges. Its
// canonical sorted result is used both for execution and coverage semantics.
func ParsePortSpec(value string) ([]int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	seen := make(map[int]struct{})
	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, fmt.Errorf("invalid empty port expression")
		}
		startText, endText, ranged := strings.Cut(token, "-")
		start, err := strconv.Atoi(strings.TrimSpace(startText))
		if err != nil || start < 1 || start > 65535 {
			return nil, fmt.Errorf("invalid port %q", token)
		}
		end := start
		if ranged {
			if strings.Contains(endText, "-") {
				return nil, fmt.Errorf("invalid port range %q", token)
			}
			end, err = strconv.Atoi(strings.TrimSpace(endText))
			if err != nil || end < start || end > 65535 {
				return nil, fmt.Errorf("invalid port range %q", token)
			}
		}
		for port := start; port <= end; port++ {
			seen[port] = struct{}{}
		}
	}
	ports := make([]int, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

func FormatPortSpec(ports []int) string {
	ports = normalizePorts(ports)
	sort.Ints(ports)
	values := make([]string, len(ports))
	for index, port := range ports {
		values[index] = strconv.Itoa(port)
	}
	return strings.Join(values, ",")
}

// FullPortScanWorstCaseBudget is derived from the minimum worker count and the
// per-port hard deadline, with bounded baseline work and scheduling margin.
func FullPortScanWorstCaseBudget() time.Duration {
	baselineWorkers := 10
	baselineBatches := (len(internalBaselinePorts) + baselineWorkers - 1) / baselineWorkers
	remainingBatches := (fullPortCount - len(internalBaselinePorts) + fullPortWorkerMinimum - 1) / fullPortWorkerMinimum
	return time.Duration(baselineBatches)*fullPortProbeTimeout + time.Duration(remainingBatches)*fullPortProbeTimeout + fullPortBudgetMargin
}

func SelectedPortScanWorstCaseBudget(portCount int) time.Duration {
	workers := runtime.NumCPU() * 10
	if workers < 1 {
		workers = 1
	}
	batches := (portCount + workers - 1) / workers
	return time.Duration(batches)*fullPortProbeTimeout + 5*time.Second
}

// InternalBaselinePorts returns the bounded port profile used for internal
// network host profiling.
func InternalBaselinePorts() []int {
	return append([]int(nil), internalBaselinePorts...)
}

func probePort(ctx context.Context, ip string, network string, port int, timeout time.Duration, identifyProduct bool) model.ScanResult {
	result := model.ScanResult{}
	result.Address = net.JoinHostPort(ip, strconv.Itoa(port))
	if err := ctx.Err(); err != nil {
		result.Err = err
		result.ErrType = assist.ErrType(model.ScanResult{Err: err})
		return result
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, network, result.Address)
	if err != nil {
		result.Open = false
		result.Err = err
		result.ErrType = assist.ErrType(model.ScanResult{Err: err})
	} else {
		defer conn.Close()
		readDone := make(chan struct{})
		go func() {
			select {
			case <-dialCtx.Done():
				_ = conn.Close()
			case <-readDone:
			}
		}()

		result.Banner, result.BannerTruncated = identify.ReadBannerEvidence(conn)
		close(readDone)
		if err := ctx.Err(); err != nil {
			result.Err = err
			result.ErrType = assist.ErrType(model.ScanResult{Err: err})
			return result
		}

		result.Open = true
		result.Service = identify.IdentifyService(result.Banner, port)
		if identifyProduct {
			fp := identify.IdentifyFingerprint(result.Banner, port)
			result.Product = fp.Product
			result.FingerprintSource = fp.Source
		}
	}
	return result
}

func ScanWorker(ctx context.Context, id int, ip string, scanner <-chan model.Scanner, results chan<- model.ScanResult, timeout time.Duration, identifyProduct bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-scanner:
			if !ok {
				return
			}
			result := probePort(ctx, ip, task.Network, task.Port, timeout, identifyProduct)
			select {
			case results <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

// ScanPorts concurrently scans the supplied TCP or UDP port list on one host.
func ScanPorts(ctx context.Context, ip, network string, ports []int) ([]model.ScanResult, error) {
	return scanPorts(ctx, ip, network, ports, true)
}

// ScanPortsDiscovery collects transport and service evidence without applying
// process-global or hardcoded product fingerprints. V2 uses this entry point.
func ScanPortsDiscovery(ctx context.Context, ip, network string, ports []int) ([]model.ScanResult, error) {
	return scanPorts(ctx, ip, network, ports, false)
}

func scanPorts(ctx context.Context, ip, network string, ports []int, identifyProduct bool) ([]model.ScanResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var openPorts []model.ScanResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	concurrentLimit := make(chan struct{}, runtime.NumCPU()*10)

	for _, port := range normalizePorts(ports) {
		if err := ctx.Err(); err != nil {
			break
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			select {
			case concurrentLimit <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-concurrentLimit }()

			result := probePort(ctx, ip, network, port, fullPortProbeTimeout, identifyProduct)
			if result.Open {
				mu.Lock()
				openPorts = append(openPorts, result)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	sortOpenPorts(openPorts)
	if err := ctx.Err(); err != nil {
		return openPorts, err
	}
	return openPorts, nil
}

func sortOpenPorts(openPorts []model.ScanResult) {
	sort.Slice(openPorts, func(i, j int) bool {
		_, left, _ := net.SplitHostPort(openPorts[i].Address)
		_, right, _ := net.SplitHostPort(openPorts[j].Address)
		leftPort, _ := strconv.Atoi(left)
		rightPort, _ := strconv.Atoi(right)
		return leftPort < rightPort
	})
}

func scanImportantPorts(ctx context.Context, ip, network string, identifyProduct bool) ([]model.ScanResult, error) {
	openPorts, err := scanPorts(ctx, ip, network, InternalBaselinePorts(), identifyProduct)
	if err != nil {
		return openPorts, err
	}
	for _, result := range openPorts {
		fmt.Printf("[+] 重要端口 %s 开放 (%s)\n", result.Address, result.Service)
	}
	return openPorts, nil
}

func RunQuick(ctx context.Context, ip, network string) ([]model.ScanResult, error) {
	return runQuick(ctx, ip, network, true)
}

func RunQuickDiscovery(ctx context.Context, ip, network string) ([]model.ScanResult, error) {
	return runQuick(ctx, ip, network, false)
}

func runQuick(ctx context.Context, ip, network string, identifyProduct bool) ([]model.ScanResult, error) {
	openPorts, err := scanPorts(ctx, ip, network, InternalBaselinePorts(), identifyProduct)
	if err != nil {
		return openPorts, err
	}
	printOpenPorts(openPorts)
	return openPorts, nil
}

func normalizePorts(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	uniquePorts := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		uniquePorts = append(uniquePorts, port)
	}
	return uniquePorts
}

func Run(ctx context.Context, ip, network string) ([]model.ScanResult, error) {
	outcome, err := run(ctx, ip, network, true)
	return outcome.Results, err
}

func RunDiscovery(ctx context.Context, ip, network string) ([]model.ScanResult, error) {
	outcome, err := RunDiscoveryWithOutcome(ctx, ip, network)
	return outcome.Results, err
}

func RunDiscoveryWithOutcome(ctx context.Context, ip, network string) (PortScanOutcome, error) {
	return run(ctx, ip, network, false)
}

func RunSelectedDiscoveryWithOutcome(ctx context.Context, ip, network string, ports []int) (PortScanOutcome, error) {
	ports = normalizePorts(ports)
	outcome := PortScanOutcome{TotalPorts: len(ports)}
	results, err := scanPorts(ctx, ip, network, ports, false)
	outcome.Results = results
	if err == nil {
		outcome.AttemptedPorts = len(ports)
	}
	return outcome, err
}

func RunSelectedDiscovery(ctx context.Context, ip, network string, ports []int) ([]model.ScanResult, error) {
	outcome, err := RunSelectedDiscoveryWithOutcome(ctx, ip, network, ports)
	return outcome.Results, err
}

func run(ctx context.Context, ip, network string, identifyProduct bool) (PortScanOutcome, error) {
	outcome := PortScanOutcome{TotalPorts: fullPortCount}
	important, err := scanImportantPorts(ctx, ip, network, identifyProduct)
	if err != nil {
		outcome.Results = important
		return outcome, err
	}
	outcome.AttemptedPorts = len(InternalBaselinePorts())

	baselinePorts := InternalBaselinePorts()
	skipPorts := make(map[int]bool, len(baselinePorts))
	for _, p := range baselinePorts {
		skipPorts[p] = true
	}

	totalPorts := 65535 - len(skipPorts)
	scanned := 0
	startTime := time.Now()
	var wg sync.WaitGroup
	tasks := make(chan model.Scanner, 1000)

	results := make(chan model.ScanResult, 1000)
	var openPorts []model.ScanResult
	workers := runtime.NumCPU() * 20
	if workers < fullPortWorkerMinimum {
		workers = fullPortWorkerMinimum
	}
	if workers > fullPortWorkerMaximum {
		workers = fullPortWorkerMaximum
	}

	for i := 0; i < workers; i++ { //分配工作
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ScanWorker(ctx, id, ip, tasks, results, fullPortProbeTimeout, identifyProduct)
		}(i)
	}

	go func() { //添加工作
		defer close(tasks)
		for i := 1; i < 65536; i++ {
			if !skipPorts[i] { //跳过重要端口
				select {
				case tasks <- model.Scanner{Network: network, IP: ip, Port: i, Conn: nil}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go func() { //等待所有任务结束后关闭 worker 池
		wg.Wait()
		close(results) //关闭 results 通道，不再接受其他数据
	}()

	errCount := make(map[string]int)
	for result := range results { //处理数据
		scanned++
		if scanned%100 == 0 || scanned == totalPorts {
			printProgress(scanned, totalPorts, startTime)
		}
		if result.Open {
			openPorts = append(openPorts, result)
		} else {
			if errCount[result.ErrType] < 3 {
				fmt.Printf("[-] %s is %s\n", result.Address, result.ErrType)
			}
			errCount[result.ErrType]++
		}
	}

	openPorts = append(openPorts, important...)
	outcome.Results = openPorts
	outcome.AttemptedPorts += scanned
	if err := ctx.Err(); err != nil {
		return outcome, err
	}
	if outcome.AttemptedPorts != outcome.TotalPorts {
		return outcome, fmt.Errorf("incomplete full port scan: attempted %d of %d ports", outcome.AttemptedPorts, outcome.TotalPorts)
	}
	fmt.Println()
	printOpenPorts(openPorts)
	return outcome, nil
}

func printProgress(current, total int, start time.Time) {
	percent := float64(current) / float64(total) * 100
	elapsed := time.Since(start).Round(time.Second)
	fmt.Printf("\rScanning: %d/%d (%.1f%%) | Elapsed: %v", current, total, percent, elapsed)
}

func printOpenPorts(results []model.ScanResult) {
	fmt.Println("\n=== 开放端口详情 ===")
	fmt.Printf("%-20s\t%-18s\t%-18s\t%-30s\n", "地址", "服务类型", "产品指纹", "Banner信息")
	for _, r := range results {
		banner := r.Banner
		if banner == "" {
			banner = "[无Banner响应]"
		} else if len(banner) > 50 {
			banner = banner[:50] + "..."
		}
		product := r.Product
		if product == "" {
			product = "-"
		}
		fmt.Printf("%-20s\t%-18s\t%-18s\t%-30s\n", r.Address, r.Service, product, banner)
	}
	fmt.Println("\n=== ---------- ===")
}
