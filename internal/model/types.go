package model

import (
	"net"
	"strings"
)

const (
	TaskStatusQueued          = "queued"
	TaskStatusRunning         = "running"
	TaskStatusCancelRequested = "cancel_requested"
	TaskStatusSuccess         = "success"
	TaskStatusFailed          = "failed"
	TaskStatusCanceled        = "canceled"

	TaskTypeScanIP          = "scan_ip"
	TaskTypeScanIPVuln      = "scan_ip_vuln"
	TaskTypeScanSubnet      = "scan_subnet"
	TaskTypeScanSubnetVuln  = "scan_subnet_vuln"
	TaskTypeVulnIP          = "vuln_ip"
	TaskTypeCollectDomain   = "collect_domain"
	TaskTypeCollectAndScan  = "collect_and_scan"
	TaskTypeCollectScanVuln = "collect_scan_vuln"
)

const (
	ScanTypeIP     = "ip"
	ScanTypeSubnet = "subnet"

	ScanTaskModeOnce      = "once"
	ScanTaskModeScheduled = "scheduled"

	ScanTaskStatusEnabled  = "enabled"
	ScanTaskStatusPaused   = "paused"
	ScanTaskStatusArchived = "archived"

	ScanTaskRunStatusQueued          = "queued"
	ScanTaskRunStatusRunning         = "running"
	ScanTaskRunStatusCancelRequested = "cancel_requested"
	ScanTaskRunStatusSuccess         = "success"
	ScanTaskRunStatusFailed          = "failed"
	ScanTaskRunStatusCanceled        = "canceled"
	ScanTaskRunStatusSkippedOverlap  = "skipped_overlap"
	ScanTaskRunStatusSkippedMisfire  = "skipped_misfire"
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
	ID          int64  `json:"id"`
	TaskType    string `json:"task_type"`
	Target      string `json:"target"`
	Status      string `json:"status"`
	Progress    int    `json:"progress"`
	ErrorMsg    string `json:"error_msg,omitempty"`
	ReportError string `json:"report_error,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
	FinishedAt  string `json:"finished_at,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

// ScanTaskConfig is the configuration that must be snapshotted on every run.
// It intentionally keeps v1 execution details out of the logical task model.
type ScanTaskConfig struct {
	PortSpec        string   `json:"port_spec,omitempty"`
	VulnerabilityOn bool     `json:"vulnerability_on"`
	NucleiTemplates string   `json:"nuclei_templates,omitempty"`
	DNSResolveMode  string   `json:"dns_resolve_mode,omitempty"`
	DNSDenyCIDRs    []string `json:"dns_deny_cidrs,omitempty"`
	TemplateVersion string   `json:"template_version,omitempty"`
}

// ScanTask is the user-managed logical task. It is separate from the v1 Task,
// which remains a record of one legacy execution.
type ScanTask struct {
	ID         int64          `json:"id"`
	Target     string         `json:"target"`
	ScanType   string         `json:"scan_type"`
	Mode       string         `json:"mode"`
	Status     string         `json:"status"`
	Cron       string         `json:"cron,omitempty"`
	Timezone   string         `json:"timezone,omitempty"`
	Config     ScanTaskConfig `json:"config"`
	ConfigHash string         `json:"config_hash"`
	CreatedAt  string         `json:"created_at"`
	UpdatedAt  string         `json:"updated_at,omitempty"`
	ArchivedAt string         `json:"archived_at,omitempty"`
}

// ScanTaskRun is one immutable scheduling attempt under a ScanTask.
type ScanTaskRun struct {
	ID                int64          `json:"id"`
	ScanTaskID        int64          `json:"scan_task_id"`
	Sequence          int            `json:"sequence"`
	ScheduledFor      string         `json:"scheduled_for"`
	Status            string         `json:"status"`
	Target            string         `json:"target"`
	ScanType          string         `json:"scan_type"`
	Config            ScanTaskConfig `json:"config"`
	ConfigHash        string         `json:"config_hash"`
	ErrorMessage      string         `json:"error_message,omitempty"`
	ReportPath        string         `json:"report_path,omitempty"`
	ReportError       string         `json:"report_error,omitempty"`
	StartedAt         string         `json:"started_at,omitempty"`
	FinishedAt        string         `json:"finished_at,omitempty"`
	SnapshotWrittenAt string         `json:"snapshot_written_at,omitempty"`
	CreatedAt         string         `json:"created_at"`
	UpdatedAt         string         `json:"updated_at,omitempty"`
}

type ScanTaskRunHost struct {
	IP       string `json:"ip"`
	IsActive bool   `json:"is_active"`
}

type ScanTaskRunPort struct {
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	ServiceType string `json:"service_type"`
	Product     string `json:"product,omitempty"`
	Banner      string `json:"banner,omitempty"`
}

type ScanTaskRunVulnerability struct {
	FindingKey string `json:"finding_key"`
	TemplateID string `json:"template_id,omitempty"`
	Name       string `json:"name,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Target     string `json:"target"`
	TargetIP   string `json:"target_ip,omitempty"`
	TargetPort int    `json:"target_port,omitempty"`
	MatchedAt  string `json:"matched_at,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

// ScanTaskRunTemplateCandidate preserves why one reviewed template was chosen.
type ScanTaskRunTemplateCandidate struct {
	TemplateID string `json:"template_id"`
	Path       string `json:"path"`
	Source     string `json:"source"`
	Reason     string `json:"reason"`
}

type ScanTaskRunSnapshot struct {
	RunID              int64                          `json:"run_id"`
	Hosts              []ScanTaskRunHost              `json:"hosts"`
	Ports              []ScanTaskRunPort              `json:"ports"`
	Vulnerabilities    []ScanTaskRunVulnerability     `json:"vulnerabilities"`
	TemplateCandidates []ScanTaskRunTemplateCandidate `json:"template_candidates"`
}

// LegacyTaskSummary exposes v1 task records as read-only history. They never
// participate in M10's run-level Diff baseline.
type LegacyTaskSummary struct {
	LegacyTaskID       int64  `json:"legacy_task_id"`
	TaskType           string `json:"task_type"`
	Target             string `json:"target"`
	Status             string `json:"status"`
	StartedAt          string `json:"started_at,omitempty"`
	FinishedAt         string `json:"finished_at,omitempty"`
	CreatedAt          string `json:"created_at"`
	IsHistorical       bool   `json:"is_historical"`
	ExactDiffAvailable bool   `json:"exact_diff_available"`
}

func IsScanType(scanType string) bool {
	return scanType == ScanTypeIP || scanType == ScanTypeSubnet
}

func IsScanTaskMode(mode string) bool {
	return mode == ScanTaskModeOnce || mode == ScanTaskModeScheduled
}

func IsScanTaskStatus(status string) bool {
	return status == ScanTaskStatusEnabled || status == ScanTaskStatusPaused || status == ScanTaskStatusArchived
}

func IsScanTaskRunStatus(status string) bool {
	switch status {
	case ScanTaskRunStatusQueued,
		ScanTaskRunStatusRunning,
		ScanTaskRunStatusCancelRequested,
		ScanTaskRunStatusSuccess,
		ScanTaskRunStatusFailed,
		ScanTaskRunStatusCanceled,
		ScanTaskRunStatusSkippedOverlap,
		ScanTaskRunStatusSkippedMisfire:
		return true
	default:
		return false
	}
}

func (task ScanTask) Valid() bool {
	if strings.TrimSpace(task.Target) == "" || !IsScanType(task.ScanType) || !IsScanTaskMode(task.Mode) || !IsScanTaskStatus(task.Status) {
		return false
	}
	return task.Mode != ScanTaskModeScheduled || (strings.TrimSpace(task.Cron) != "" && strings.TrimSpace(task.Timezone) != "")
}

func (run ScanTaskRun) Valid() bool {
	return run.ScanTaskID > 0 &&
		run.Sequence > 0 &&
		strings.TrimSpace(run.ScheduledFor) != "" &&
		strings.TrimSpace(run.Target) != "" &&
		IsScanType(run.ScanType) &&
		IsScanTaskRunStatus(run.Status)
}

type HostInventory struct {
	ID         int64  `json:"id"`
	IP         string `json:"ip"`
	Source     string `json:"-"`
	ScopeCount int    `json:"scope_count"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
	LastScan   string `json:"last_scan,omitempty"`
	IsActive   bool   `json:"is_active"`
}

// HostScopeMembership records how one scan scope observes one host. It is
// intentionally separate from the IP-level host inventory aggregate.
type HostScopeMembership struct {
	Scope       string `json:"scope"`
	IP          string `json:"ip"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
	LastChecked string `json:"last_checked"`
	IsActive    bool   `json:"is_active"`
}

func (membership HostScopeMembership) Valid() bool {
	return strings.TrimSpace(membership.Scope) != "" && net.ParseIP(strings.TrimSpace(membership.IP)) != nil
}

type AssetPort struct {
	Port       int    `json:"port"`
	Service    string `json:"service"`
	LastSeenAt string `json:"last_seen_at"`
}

// FingerprintEvidence is the persistence-safe form of one fingerprint match.
// Summary describes the matched rule condition and never stores a raw body,
// header value or TCP banner fragment.
type FingerprintEvidence struct {
	Target     string `json:"target"`
	HeaderName string `json:"header_name,omitempty"`
	Operator   string `json:"operator"`
	Pattern    string `json:"pattern"`
	Summary    string `json:"summary"`
}

// AssetFingerprint is a stateful product conclusion for one IP and port.
// RuleID and SourceID make every conclusion traceable to an audited rule
// snapshot, while Evidence records the non-sensitive reason for the match.
type AssetFingerprint struct {
	IP         string                `json:"ip"`
	Port       int                   `json:"port"`
	Protocol   string                `json:"protocol"`
	RuleID     string                `json:"rule_id"`
	SourceID   string                `json:"source_id"`
	Vendor     string                `json:"vendor,omitempty"`
	Product    string                `json:"product"`
	Version    string                `json:"version,omitempty"`
	CPE        string                `json:"cpe,omitempty"`
	Confidence int                   `json:"confidence"`
	Evidence   []FingerprintEvidence `json:"evidence"`
	FirstSeen  string                `json:"first_seen,omitempty"`
	LastSeen   string                `json:"last_seen,omitempty"`
}

func (fingerprint AssetFingerprint) Valid() bool {
	protocol := strings.ToLower(strings.TrimSpace(fingerprint.Protocol))
	return net.ParseIP(strings.TrimSpace(fingerprint.IP)) != nil &&
		fingerprint.Port > 0 && fingerprint.Port <= 65535 &&
		(protocol == "http" || protocol == "https" || protocol == "tcp" || protocol == "tls") &&
		strings.TrimSpace(fingerprint.RuleID) != "" &&
		strings.TrimSpace(fingerprint.SourceID) != "" &&
		strings.TrimSpace(fingerprint.Product) != "" &&
		fingerprint.Confidence >= 0 && fingerprint.Confidence <= 100 &&
		len(fingerprint.Evidence) > 0
}

type AssetDetail struct {
	Host   HostInventory         `json:"host"`
	Scopes []HostScopeMembership `json:"scopes"`
	Ports  []AssetPort           `json:"ports"`
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

type VulnerabilityChange struct {
	FindingKey string `json:"finding_key"`
	TemplateID string `json:"template_id,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Target     string `json:"target"`
}

type VulnerabilityChanges struct {
	New      []VulnerabilityChange `json:"new"`
	Resolved []VulnerabilityChange `json:"resolved"`
}

type ScanTaskRunChanges struct {
	ScanTaskID           int64                `json:"scan_task_id"`
	BaselineRunID        int64                `json:"baseline_run_id,omitempty"`
	CurrentRunID         int64                `json:"current_run_id"`
	ConfigChanged        bool                 `json:"config_changed"`
	HostChanges          HostChanges          `json:"host_changes"`
	PortChanges          PortChanges          `json:"port_changes"`
	VulnerabilityChanges VulnerabilityChanges `json:"vulnerability_changes"`
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
