package scan

import (
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
	"time"

	"golandproject/yscan/internal/assist"
	"golandproject/yscan/internal/identify"
	"golandproject/yscan/internal/model"
)

// 定义重要端口列表（根据实际需求调整）
var importantPorts = []int{
	// 常用服务
	21, 22, 23, 25, 53, 80, 110, 143,
	443, 465, 587, 993, 995, 3306, 3389,
	5432, 5900, 6379, 8080, 8443, 8888,

	// 安全相关
	161, 389, 636, 5985, 5986,

	// 数据库
	27017, 1521, 1433,
}

func probePort(ip string, network string, port int, timeout time.Duration) model.ScanResult {
	result := model.ScanResult{}
	result.Address = net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout(network, result.Address, timeout)
	if err != nil {
		result.Open = false
		result.Err = err
		result.ErrType = assist.ErrType(model.ScanResult{Err: err})
	} else {
		result.Open = true
		result.Banner = identify.ReadBanner(conn)
		result.Service = identify.IdentifyService(result.Banner, port)
		conn.Close()
	}
	return result
}

func ScanWorker(id int, ip string, scanner <-chan model.Scanner, results chan<- model.ScanResult, timeout time.Duration) {
	for scan := range scanner {
		result := probePort(ip, scan.Network, scan.Port, timeout)
		results <- result
	}
}

func scanImportantPorts(ip, network string) []model.ScanResult {
	var openPorts []model.ScanResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	concurrentLimit := make(chan struct{}, runtime.NumCPU()*10)

	for _, port := range importantPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			concurrentLimit <- struct{}{}
			defer func() { <-concurrentLimit }()

			result := probePort(ip, network, port, 2*time.Second)
			if result.Open {
				mu.Lock()
				openPorts = append(openPorts, result)
				fmt.Printf("[+] 重要端口 %s 开放 (%s)\n", result.Address, result.Service)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	close(concurrentLimit)
	return openPorts
}

func Run(ip string, network string) []model.ScanResult {
	important := scanImportantPorts(ip, network)

	var (
		totalPorts = 65535      // 总端口数
		scanned    = 0          // 已扫描计数
		startTime  = time.Now() // 记录开始时间
	)
	var wg sync.WaitGroup
	tasks := make(chan model.Scanner, 1000)

	skipPorts := make(map[int]bool)
	for _, r := range important {
		_, portStr, _ := net.SplitHostPort(r.Address) // 分解address
		port, _ := strconv.Atoi(portStr)              // 字符串转整数
		skipPorts[port] = true
	}

	results := make(chan model.ScanResult, 1000)
	var openPorts []model.ScanResult
	workers := runtime.NumCPU() * 100

	for i := 0; i < workers; i++ { //分配工作
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ScanWorker(id, ip, tasks, results, 2*time.Second)
		}(i)
	}

	go func() { //添加工作
		for i := 1; i < 65536; i++ {
			if !skipPorts[i] { //跳过重要端口
				tasks <- model.Scanner{Network: network, IP: ip, Port: i, Conn: nil}
			}
		}
		close(tasks)
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
	fmt.Println()
	printOpenPorts(openPorts)
	return openPorts
}

func printProgress(current, total int, start time.Time) {
	percent := float64(current) / float64(total) * 100
	elapsed := time.Since(start).Round(time.Second)
	fmt.Printf("\rScanning: %d/%d (%.1f%%) | Elapsed: %v", current, total, percent, elapsed)
}

func printOpenPorts(results []model.ScanResult) {
	fmt.Println("\n=== 开放端口详情 ===")
	fmt.Printf("%-20s\t%-25s\t%-30s\n", "地址", "服务类型", "Banner信息")
	for _, r := range results {
		banner := r.Banner
		if banner == "" {
			banner = "[无Banner响应]"
		} else if len(banner) > 50 {
			banner = banner[:50] + "..."
		}
		fmt.Printf("%-20s\t%-25s\t%-30s\n", r.Address, r.Service, banner)
	}
	fmt.Println("\n=== ---------- ===")
}
