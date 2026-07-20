package model

import "net"

const (
	TaskStatusQueued   = "queued"
	TaskStatusRunning  = "running"
	TaskStatusSuccess  = "success"
	TaskStatusFailed   = "failed"
	TaskStatusCanceled = "canceled"

	TaskTypeScanIP          = "scan_ip"
	TaskTypeScanIPVuln      = "scan_ip_vuln"
	TaskTypeScanSubnet      = "scan_subnet"
	TaskTypeScanSubnetVuln  = "scan_subnet_vuln"
	TaskTypeVulnIP          = "vuln_ip"
	TaskTypeCollectDomain   = "collect_domain"
	TaskTypeCollectAndScan  = "collect_and_scan"
	TaskTypeCollectScanVuln = "collect_scan_vuln"
)

type Scanner struct {
	Network         string
	IP              string
	Port            int
	Conn            net.Conn
	NucleiTemplates string
	DNSResolveMode  string
	DNSDenyCIDRs    []string
}

type ScanResult struct {
	Address           string
	Err               error
	ErrType           string
	Open              bool
	Service           string
	Product           string
	FingerprintSource string
	Banner            string
}

type Task struct {
	ID         int64  `json:"id"`
	TaskType   string `json:"task_type"`
	Target     string `json:"target"`
	Status     string `json:"status"`
	Progress   int    `json:"progress"`
	ErrorMsg   string `json:"error_msg,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

type HostInventory struct {
	ID        int64  `json:"id"`
	IP        string `json:"ip"`
	Source    string `json:"source"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	LastScan  string `json:"last_scan,omitempty"`
	IsActive  bool   `json:"is_active"`
}

type AssetPort struct {
	Port       int    `json:"port"`
	Service    string `json:"service"`
	LastSeenAt string `json:"last_seen_at"`
}

type AssetDetail struct {
	Host  HostInventory `json:"host"`
	Ports []AssetPort   `json:"ports"`
}

type HostChanges struct {
	NewHosts      []string `json:"new_hosts"`
	InactiveHosts []string `json:"inactive_hosts"`
}

type PortChange struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type PortChanges struct {
	Opened []PortChange `json:"opened"`
	Closed []PortChange `json:"closed"`
}

type TaskChangeSummary struct {
	TaskID      int64       `json:"task_id"`
	Target      string      `json:"target"`
	HostChanges HostChanges `json:"host_changes"`
	PortChanges PortChanges `json:"port_changes"`
	GeneratedAt string      `json:"generated_at,omitempty"`
}

type NucleiFinding struct {
	TemplateID  string
	VulnType    string
	Name        string
	Severity    string
	Description string
	Host        string
	MatchedAt   string
	Target      string
	TargetIP    string
	TargetPort  int
	ScanTime    string
	Evidence    string
	Tags        string
}

type Vulnerability struct {
	ID           int64  `json:"id"`
	TaskID       int64  `json:"task_id"`
	ScanResultID int64  `json:"scan_result_id,omitempty"`
	PocID        int64  `json:"poc_id,omitempty"`
	TemplateID   string `json:"template_id,omitempty"`
	VulnType     string `json:"vuln_type,omitempty"`
	Name         string `json:"name,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Target       string `json:"target,omitempty"`
	TargetIP     string `json:"target_ip,omitempty"`
	TargetPort   int    `json:"target_port,omitempty"`
	MatchedAt    string `json:"matched_at,omitempty"`
	ScanTime     string `json:"scan_time,omitempty"`
}
