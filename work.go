package main

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"strconv"
	"sync"
	"time"
)

func ScanWorker(id int, ip string, scanner <-chan scanner, results chan<- scanResult, timeout time.Duration) { //需要进行的任务，这里是进行端口扫描
	for scan := range scanner { //这里的 scanner 是通道，里面是有很多的 scan 个体，这里的 scan 才是一个结构体可以引用 scan 结构体的元素
		result := scanResult{}                                              //这里是定义一个 scanResult 的结构体
		result.address = net.JoinHostPort(ip, strconv.Itoa(scan.port))      //这里是用 ip 和端口一起组成地址
		if err := ValidateInput(scan.network, result.address); err != nil { //用 validateInput 检验地址和网络方式是否正确
			log.Println(err)
			break
		}
		scan.conn, result.err = net.DialTimeout(scan.network, result.address, timeout) //进行连接
		if result.err == nil {                                                         //连接成功
			result.open = true //open 赋值为 true
			result.banner = ReadBanner(scan.conn)
			result.service = IdentifyService(result.banner, scan.port)
			scan.conn.Close() //连接关闭
		} else {
			result.open = false
			result.errtype = ErrType(result)
		}
		results <- result
	}
}

func Run(ip string, network string) []scanResult {
	var (
		totalPorts = 65535      // 总端口数
		scanned    = 0          // 已扫描计数
		startTime  = time.Now() // 记录开始时间
	)
	var wg sync.WaitGroup
	tasks := make(chan scanner, 1000)
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
			tasks <- scanner{network: network, ip: ip, port: i, conn: nil}
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
	fmt.Println()
	printOpenPorts(openPorts)

	return openPorts
}
