package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"golandproject/yscan/internal/assist"
	"golandproject/yscan/internal/domain"
	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/scan"
	"golandproject/yscan/internal/storage"
)

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

func collectSubdomains(db *sql.DB, task model.Scanner) {
	var domainName string

	fmt.Print("Please enter your domain: ")
	fmt.Scan(&domainName)

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
			if !uniqueIPs[ipStr] && ip.To4() != nil {
				uniqueIPs[ipStr] = true
				ipsToScan = append(ipsToScan, ipStr)

				if err := storage.SaveDomainIP(db, domainID, ipStr, res.Subdomain, nil); err != nil {
					log.Printf("保存IP关联失败 %s: %v", ipStr, err)
				}
			}
		}
	}

	answer := "n"
	fmt.Print("Subdomain collecting is done. Do the domains need to scan?(y/N): ")
	fmt.Scan(&answer)

	if answer == "y" {
		for _, ip := range ipsToScan {
			task.IP = ip
			domainScan(task, db)
		}
	} else if answer == "n" {
		fmt.Print("The task is over.")
	}
}

func domainScan(task model.Scanner, db *sql.DB) {
	fmt.Printf("\n=== 开始域名扫描 %s ===\n", task.IP)

	if assist.IsHostAlive(task.IP) {
		openPorts := scan.Run(task.IP, task.Network)
		if err := storage.SaveDomainScanResult(db, task.IP, openPorts); err != nil {
			log.Printf("保存扫描结果失败: %v", err)
		}
	} else {
		fmt.Println("Can't ping")
		if assist.IsHostAliveTCP(task.IP) {
			openPorts := scan.Run(task.IP, task.Network)
			if err := storage.SaveDomainScanResult(db, task.IP, openPorts); err != nil {
				log.Printf("保存扫描结果失败: %v", err)
			}
		} else {
			log.Print("没有进入TCP连接")
			fmt.Printf("%s is not alive\n", task.IP)
		}
	}
}

func portScan(task model.Scanner, db *sql.DB) {
	if assist.IsHostAlive(task.IP) || assist.IsHostAliveTCP(task.IP) {
		openPorts := scan.Run(task.IP, task.Network)
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
	} else {
		log.Print("没有进入TCP连接")
		fmt.Printf("%s is not alive\n", task.IP)
	}
}

func main() {
	db, err := storage.InitDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	task := model.Scanner{Network: "tcp"}

	var command string
	fmt.Print("Please enter a command(domain/scan): ")
	fmt.Scan(&command)

	if command == "scan" {
		fmt.Print("Please enter your ip:")
		fmt.Scan(&task.IP)
		portScan(task, db)
	} else if command == "domain" {
		collectSubdomains(db, task)
	} else {
		fmt.Println("please enter a true command.")
	}
}
