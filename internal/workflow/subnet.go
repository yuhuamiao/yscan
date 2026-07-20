package workflow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"golandproject/yscan/internal/diff"
	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/pipeline"
	"golandproject/yscan/internal/planner"
	"golandproject/yscan/internal/scan"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/vuln"
)

var ErrCanceled = errors.New("subnet task canceled")

type SubnetRunOptions struct {
	DB                    *sql.DB
	TaskID                int64
	CIDR                  string
	Network               string
	TemplatesPath         string
	EnableVulnerabilities bool
	DiscoveryOptions      pipeline.SubnetDiscoveryOptions
	CheckCanceled         func() (bool, error)
	UpdateProgress        func(int) error
}

type subnetDependencies struct {
	discover     func(context.Context, string, pipeline.SubnetDiscoveryOptions) ([]string, error)
	scanHost     func(string, string) []model.ScanResult
	runNuclei    func(context.Context, string, []model.ScanResult, string, []string) ([]model.NucleiFinding, error)
	saveFindings func(*sql.DB, int64, []model.NucleiFinding) error
}

// RunSubnet executes discovery, quick profiling, optional vulnerability
// validation, and persists a task-level change summary.
func RunSubnet(ctx context.Context, options SubnetRunOptions) (model.TaskChangeSummary, error) {
	return runSubnet(ctx, options, subnetDependencies{
		discover:     pipeline.DiscoverAliveHosts,
		scanHost:     scan.RunQuick,
		runNuclei:    vuln.RunNucleiForOpenPortsWithTags,
		saveFindings: storage.SaveNucleiFindings,
	})
}

func runSubnet(ctx context.Context, options SubnetRunOptions, dependencies subnetDependencies) (model.TaskChangeSummary, error) {
	if options.DB == nil {
		return model.TaskChangeSummary{}, errors.New("subnet task database is required")
	}
	if options.TaskID <= 0 {
		return model.TaskChangeSummary{}, fmt.Errorf("invalid task ID: %d", options.TaskID)
	}
	options.CIDR = strings.TrimSpace(options.CIDR)
	if !pipeline.IsIPv4CIDR(options.CIDR) {
		return model.TaskChangeSummary{}, fmt.Errorf("invalid IPv4 CIDR: %s", options.CIDR)
	}
	if strings.TrimSpace(options.Network) == "" {
		options.Network = "tcp"
	}
	if dependencies.discover == nil || dependencies.scanHost == nil || dependencies.runNuclei == nil || dependencies.saveFindings == nil {
		return model.TaskChangeSummary{}, errors.New("subnet task dependencies are required")
	}
	if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
		return model.TaskChangeSummary{}, err
	}
	if err := updateProgress(options.UpdateProgress, 10); err != nil {
		return model.TaskChangeSummary{}, err
	}

	source := "subnet:" + options.CIDR
	beforeHosts, err := storage.ListHostInventory(options.DB, storage.HostInventoryQuery{Source: source})
	if err != nil {
		return model.TaskChangeSummary{}, err
	}

	aliveHosts, err := dependencies.discover(ctx, options.CIDR, options.DiscoveryOptions)
	if err != nil {
		return model.TaskChangeSummary{}, err
	}
	if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
		return model.TaskChangeSummary{}, err
	}
	if err := storage.SyncHostInventory(options.DB, source, aliveHosts); err != nil {
		return model.TaskChangeSummary{}, err
	}
	afterHosts, err := storage.ListHostInventory(options.DB, storage.HostInventoryQuery{Source: source})
	if err != nil {
		return model.TaskChangeSummary{}, err
	}

	summary := model.TaskChangeSummary{
		TaskID:      options.TaskID,
		Target:      options.CIDR,
		HostChanges: diff.CompareHosts(beforeHosts, afterHosts),
		PortChanges: model.PortChanges{Opened: []model.PortChange{}, Closed: []model.PortChange{}},
	}
	if len(aliveHosts) == 0 {
		if err := storage.SaveTaskChangeSummary(options.DB, summary); err != nil {
			return model.TaskChangeSummary{}, err
		}
		if err := updateProgress(options.UpdateProgress, 100); err != nil {
			return model.TaskChangeSummary{}, err
		}
		return summary, nil
	}

	beforePorts, err := snapshotPorts(options.DB, aliveHosts)
	if err != nil {
		return model.TaskChangeSummary{}, err
	}
	afterPorts := make(map[string][]int, len(aliveHosts))

	for index, ip := range aliveHosts {
		if err := checkCanceled(ctx, options.CheckCanceled); err != nil {
			return model.TaskChangeSummary{}, err
		}

		openPorts := dependencies.scanHost(ip, options.Network)
		if err := storage.SyncOpenPorts(options.DB, ip, openPorts); err != nil {
			return model.TaskChangeSummary{}, err
		}
		afterPorts[ip] = portsFromResults(ip, openPorts)

		if groups := planner.TemplateGroupsForScanResults(openPorts); options.EnableVulnerabilities && len(groups) > 0 {
			findings, err := dependencies.runNuclei(ctx, ip, openPorts, options.TemplatesPath, groups)
			if err != nil {
				return model.TaskChangeSummary{}, err
			}
			if err := dependencies.saveFindings(options.DB, options.TaskID, findings); err != nil {
				return model.TaskChangeSummary{}, err
			}
		}

		progress := 20 + int(float64(index+1)/float64(len(aliveHosts))*80)
		if err := updateProgress(options.UpdateProgress, progress); err != nil {
			return model.TaskChangeSummary{}, err
		}
	}

	summary.PortChanges = diff.ComparePorts(beforePorts, afterPorts)
	if err := storage.SaveTaskChangeSummary(options.DB, summary); err != nil {
		return model.TaskChangeSummary{}, err
	}
	return summary, nil
}

func checkCanceled(ctx context.Context, check func() (bool, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if check == nil {
		return nil
	}
	canceled, err := check()
	if err != nil {
		return err
	}
	if canceled {
		return ErrCanceled
	}
	return nil
}

func updateProgress(update func(int) error, progress int) error {
	if update == nil {
		return nil
	}
	return update(progress)
}

func snapshotPorts(db *sql.DB, hosts []string) (map[string][]int, error) {
	snapshot := make(map[string][]int, len(hosts))
	for _, host := range hosts {
		ports, err := storage.ListOpenPortsByIP(db, host)
		if err != nil {
			return nil, err
		}
		snapshot[host] = ports
	}
	return snapshot, nil
}

func portsFromResults(ip string, results []model.ScanResult) []int {
	ports := make([]int, 0, len(results))
	seen := make(map[int]struct{}, len(results))
	for _, result := range results {
		if !result.Open {
			continue
		}
		host, portText, err := net.SplitHostPort(result.Address)
		if err != nil || host != ip {
			continue
		}
		var port int
		if _, err := fmt.Sscanf(portText, "%d", &port); err != nil || port < 1 || port > 65535 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}
