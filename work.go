package main

import (
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
	"time"
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

func probePort(ip string, network string, port int, timeout time.Duration) scanResult {
	result := scanResult{}
	result.address = net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout(network, result.address, timeout)
	if err != nil {
		result.open = false
		result.errtype = ErrType(scanResult{err: err})
	} else {
		result.open = true //open 赋值为 true
		result.banner = ReadBanner(conn)
		result.service = IdentifyService(result.banner, port)
		conn.Close() //连接关闭
	}
	return result
}

func ScanWorker(id int, ip string, scanner <-chan scanner, results chan<- scanResult, timeout time.Duration) { //需要进行的任务，这里是进行端口扫描
	for scan := range scanner { //这里的 scanner 是通道，里面是有很多的 scan 个体，这里的 scan 才是一个结构体可以引用 scan 结构体的元素
		result := probePort(ip, scan.network, scan.port, timeout)
		results <- result
	}
}

func scanImportantPorts(ip, network string) []scanResult { //先扫描重要端口
	var openPorts []scanResult
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
			if result.open {
				mu.Lock()
				openPorts = append(openPorts, result)
				fmt.Printf("[+] 重要端口 %s 开放 (%s)\n", result.address, result.service)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	close(concurrentLimit)
	return openPorts
}

func Run(ip string, network string) []scanResult {
	importantPorts := scanImportantPorts(ip, network) //一阶段：重要端口

	//二阶段：全端口
	var (
		totalPorts = 65535      // 总端口数
		scanned    = 0          // 已扫描计数
		startTime  = time.Now() // 记录开始时间
	)
	var wg sync.WaitGroup
	tasks := make(chan scanner, 1000)

	skipPorts := make(map[int]bool)
	for _, r := range importantPorts { //这里因为 scanResults 结构体没有 port 部分，所以通过 address 分解出 port。
		_, portStr, _ := net.SplitHostPort(r.address) // 分解address
		port, _ := strconv.Atoi(portStr)              // 字符串转整数
		skipPorts[port] = true
	}

	results := make(chan scanResult, 1000)
	var openPorts []scanResult
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
				tasks <- scanner{network: network, ip: ip, port: i, conn: nil}
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
		if result.open {
			//fmt.Printf("[+] %s is open\n", result.address)
			openPorts = append(openPorts, result)
		} else {
			if errCount[result.errtype] < 3 {
				fmt.Printf("[-] %s is %s\n", result.address, result.errtype)
			}
			errCount[result.errtype]++

		}
	}

	for _, importantPort := range importantPorts {
		openPorts = append(openPorts, importantPort)
	}

	fmt.Println()
	printOpenPorts(openPorts)

	return openPorts
}
