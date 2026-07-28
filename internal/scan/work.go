package scan

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strconv"
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

// InternalBaselinePorts returns the bounded port profile used for internal
// network host profiling.
func InternalBaselinePorts() []int {
	return append([]int(nil), internalBaselinePorts...)
}

func probePort(ctx context.Context, ip string, network string, port int, timeout time.Duration) model.ScanResult {
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
			case <-ctx.Done():
				_ = conn.Close()
			case <-readDone:
			}
		}()

		result.Banner = identify.ReadBanner(conn)
		close(readDone)
		if err := ctx.Err(); err != nil {
			result.Err = err
			result.ErrType = assist.ErrType(model.ScanResult{Err: err})
			return result
		}

		result.Open = true
		result.Service = identify.IdentifyService(result.Banner, port)
		fp := identify.IdentifyFingerprint(result.Banner, port)
		result.Product = fp.Product
		result.FingerprintSource = fp.Source
	}
	return result
}

func ScanWorker(ctx context.Context, id int, ip string, scanner <-chan model.Scanner, results chan<- model.ScanResult, timeout time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-scanner:
			if !ok {
				return
			}
			result := probePort(ctx, ip, task.Network, task.Port, timeout)
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

			result := probePort(ctx, ip, network, port, 2*time.Second)
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

func scanImportantPorts(ctx context.Context, ip, network string) ([]model.ScanResult, error) {
	openPorts, err := ScanPorts(ctx, ip, network, InternalBaselinePorts())
	if err != nil {
		return openPorts, err
	}
	for _, result := range openPorts {
		fmt.Printf("[+] 重要端口 %s 开放 (%s)\n", result.Address, result.Service)
	}
	return openPorts, nil
}

func RunQuick(ctx context.Context, ip, network string) ([]model.ScanResult, error) {
	openPorts, err := ScanPorts(ctx, ip, network, InternalBaselinePorts())
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
	important, err := scanImportantPorts(ctx, ip, network)
	if err != nil {
		return important, err
	}

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
	if workers < 64 {
		workers = 64
	}
	if workers > 512 {
		workers = 512
	}

	for i := 0; i < workers; i++ { //分配工作
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ScanWorker(ctx, id, ip, tasks, results, 2*time.Second)
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
	if err := ctx.Err(); err != nil {
		return openPorts, err
	}
	fmt.Println()
	printOpenPorts(openPorts)
	return openPorts, nil
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
