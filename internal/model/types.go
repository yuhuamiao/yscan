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

	ScanTaskRunValidationDisabled     = "disabled"
	ScanTaskRunValidationNotStarted   = "not_started"
	ScanTaskRunValidationNoCandidates = "no_candidates"
	ScanTaskRunValidationSuccess      = "success"
	ScanTaskRunValidationFailed       = "failed"
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
	BannerTruncated   bool
	ProtocolEvidence  []ScanTaskRunProtocolEvidence
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
	AuditReportPath   string         `json:"audit_report_path,omitempty"`
	ReportError       string         `json:"report_error,omitempty"`
	StartedAt         string         `json:"started_at,omitempty"`
	FinishedAt        string         `json:"finished_at,omitempty"`
	SnapshotWrittenAt string         `json:"snapshot_written_at,omitempty"`
	CreatedAt         string         `json:"created_at"`
	UpdatedAt         string         `json:"updated_at,omitempty"`
}

// FingerprintSource identifies one stable upstream rule provider. Immutable
// commits and statistics belong to FingerprintImport, never to this record.
type FingerprintSource struct {
	ID              int64  `json:"id"`
	SourceKey       string `json:"source_key"`
	RepositoryURL   string `json:"repository_url"`
	License         string `json:"license,omitempty"`
	Status          string `json:"status"`
	CatalogStatus   string `json:"catalog_status,omitempty"`
	LastError       string `json:"last_error,omitempty"`
	LastFailedAt    string `json:"last_failed_at,omitempty"`
	HasActiveImport bool   `json:"has_active_import"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at,omitempty"`
}

// FingerprintImport is one immutable, manifest-verified source revision.
type FingerprintImport struct {
	ID                    int64  `json:"id"`
	FingerprintSourceID   int64  `json:"fingerprint_source_id"`
	Commit                string `json:"commit"`
	ContentSHA256         string `json:"content_sha256"`
	UpstreamContentSHA256 string `json:"upstream_content_sha256"`
	AdapterVersion        string `json:"adapter_version"`
	ProjectionSHA256      string `json:"projection_sha256"`
	ManifestJSON          string `json:"manifest_json"`
	RuleTotal             int    `json:"rule_total"`
	ExecutableTotal       int    `json:"executable_total"`
	UnsupportedTotal      int    `json:"unsupported_total"`
	ImportErrorTotal      int    `json:"import_error_total"`
	ErrorSummary          string `json:"error_summary,omitempty"`
	IsActive              bool   `json:"is_active"`
	CreatedAt             string `json:"created_at"`
}

// FingerprintImportSummary is safe for catalog and run list endpoints. The
// potentially multi-megabyte manifest is available only from the detail API.
type FingerprintImportSummary struct {
	ID                    int64  `json:"id"`
	FingerprintSourceID   int64  `json:"fingerprint_source_id"`
	Commit                string `json:"commit"`
	ContentSHA256         string `json:"content_sha256"`
	UpstreamContentSHA256 string `json:"upstream_content_sha256"`
	AdapterVersion        string `json:"adapter_version"`
	ProjectionSHA256      string `json:"projection_sha256"`
	RuleTotal             int    `json:"rule_total"`
	ExecutableTotal       int    `json:"executable_total"`
	UnsupportedTotal      int    `json:"unsupported_total"`
	ImportErrorTotal      int    `json:"import_error_total"`
	ErrorSummary          string `json:"error_summary,omitempty"`
	IsActive              bool   `json:"is_active"`
	CreatedAt             string `json:"created_at"`
}

// FingerprintSourceRule preserves an upstream rule before normalization.
type FingerprintSourceRule struct {
	ID                  int64  `json:"id"`
	FingerprintImportID int64  `json:"fingerprint_import_id"`
	SourceRuleID        string `json:"source_rule_id,omitempty"`
	SourcePath          string `json:"source_path"`
	ContentSHA256       string `json:"content_sha256"`
	RawContent          string `json:"raw_content"`
	RawStructure        string `json:"raw_structure,omitempty"`
	ImportStatus        string `json:"import_status"`
	ImportError         string `json:"import_error,omitempty"`
	CreatedAt           string `json:"created_at"`
	Product             string `json:"product,omitempty"`
}

type FingerprintSourceRulePage struct {
	Items    []FingerprintSourceRule `json:"items"`
	Page     int                     `json:"page"`
	PageSize int                     `json:"page_size"`
	Total    int                     `json:"total"`
}

// FingerprintProduct is the normalized product identity attached to one or
// more source rules. Source wording remains preserved on FingerprintSourceRule.
type FingerprintProduct struct {
	ID             int64  `json:"id"`
	CanonicalName  string `json:"canonical_name"`
	Vendor         string `json:"vendor,omitempty"`
	AliasesJSON    string `json:"aliases_json,omitempty"`
	CPE            string `json:"cpe,omitempty"`
	Role           string `json:"role,omitempty"`
	ExclusiveGroup string `json:"exclusive_group,omitempty"`
}

// FingerprintProductClassification is the fixed T320 role projection. Roles
// describe stack layers; only a non-empty exclusive group can create product
// conflicts at one endpoint.
func FingerprintProductClassification(name string, tags []string) (string, string) {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "nginx", "apache", "apache http server", "apache httpd", "httpd", "iis", "microsoft iis", "caddy", "lighttpd", "jetty", "openresty":
		return "web_server", "web_server"
	case "html5", "jquery", "jquery migrate", "bootstrap", "script":
		return "frontend", ""
	case "open-graph-protocol":
		return "metadata", ""
	case "php", "python", "node.js", "nodejs", "ruby", "perl", "java":
		return "runtime", ""
	case "flask", "werkzeug", "thinkphp", "django", "laravel", "spring", "spring framework":
		return "framework", ""
	case "wordpress", "drupal", "joomla", "hexo":
		return "cms_application", ""
	case "ubuntu", "debian", "centos", "red hat enterprise linux", "windows", "linux":
		return "operating_system", ""
	case "http", "https", "ssh", "ftp", "tcp", "unknown", "none_unknown":
		return "protocol", ""
	case "mysql", "postgresql", "mongodb", "redis", "openssh", "dropbear", "dropbear sshd", "dropbear ssh server", "dropbear_ssh_server", "pure-ftpd", "vsftpd", "elasticsearch", "docker-api", "kubernetes-api":
		return "network_service", "network_service"
	}
	if strings.Contains(name, "宝塔") || strings.Contains(name, "bt.cn") || strings.Contains(name, "cpanel") || strings.Contains(name, "plesk") {
		return "control_panel", ""
	}
	if strings.Contains(name, "cdn") {
		return "cdn", ""
	}
	for _, tag := range tags {
		switch strings.ToLower(strings.TrimSpace(tag)) {
		case "cms":
			return "cms_application", ""
		case "framework":
			return "framework", ""
		case "nmap-service", "service", "ftp", "database":
			return "network_service", "network_service"
		}
	}
	return "application", ""
}

// FingerprintRule is an executable projection of one preserved source rule.
type FingerprintRule struct {
	ID                      int64  `json:"id"`
	FingerprintSourceRuleID int64  `json:"fingerprint_source_rule_id"`
	FingerprintProductID    int64  `json:"fingerprint_product_id"`
	SourceProduct           string `json:"source_product,omitempty"`
	Protocol                string `json:"protocol"`
	Status                  string `json:"status"`
	SoftMatch               bool   `json:"soft_match"`
	VersionTemplate         string `json:"version_template,omitempty"`
	CPE                     string `json:"cpe,omitempty"`
	TagsJSON                string `json:"tags_json,omitempty"`
}

// FingerprintMatchGroup preserves AND/OR/nested relations from an upstream
// rule. ParentID is nil for the root group.
type FingerprintMatchGroup struct {
	ID                int64  `json:"id"`
	FingerprintRuleID int64  `json:"fingerprint_rule_id"`
	ParentID          *int64 `json:"parent_id,omitempty"`
	Operator          string `json:"operator"`
	Position          int    `json:"position"`
}

// FingerprintMatcher is one condition within a preserved match group.
type FingerprintMatcher struct {
	ID                      int64  `json:"id"`
	FingerprintMatchGroupID int64  `json:"fingerprint_match_group_id"`
	EvidenceType            string `json:"evidence_type"`
	Target                  string `json:"target,omitempty"`
	Operator                string `json:"operator"`
	Value                   string `json:"value"`
	VersionCapture          string `json:"version_capture,omitempty"`
	Position                int    `json:"position"`
}

// FingerprintRuleProjection is the source-independent executable form written
// in the same transaction as its preserved upstream source rule.
type FingerprintRuleProjection struct {
	SourcePath      string
	ContentSHA256   string
	SourceProduct   string
	Product         FingerprintProduct
	Protocol        string
	SoftMatch       bool
	VersionTemplate string
	CPE             string
	Tags            []string
	Root            FingerprintMatchGroupProjection
}

type FingerprintMatchGroupProjection struct {
	Operator string
	Matchers []FingerprintMatcher
	Children []FingerprintMatchGroupProjection
}

// TemplateMappingImport is an immutable reviewed mapping revision. Its digest
// binds the mapping record to the exact template content reviewed for use.
type TemplateMappingImport struct {
	ID            int64  `json:"id"`
	Revision      string `json:"revision"`
	ContentSHA256 string `json:"content_sha256"`
	ManifestJSON  string `json:"manifest_json"`
	IsActive      bool   `json:"is_active"`
	CreatedAt     string `json:"created_at"`
}

// FingerprintTemplateMapping allows only an approved, content-pinned local
// template to be selected from a fingerprint conclusion.
type FingerprintTemplateMapping struct {
	ID                      int64  `json:"id"`
	TemplateMappingImportID int64  `json:"template_mapping_import_id"`
	ProductKey              string `json:"product_key"`
	SourceKey               string `json:"source_key,omitempty"`
	SourceRuleID            string `json:"source_rule_id,omitempty"`
	TemplateID              string `json:"template_id"`
	TemplatePath            string `json:"template_path"`
	TemplateSHA256          string `json:"template_sha256"`
	TemplateSetRevision     string `json:"template_set_revision"`
	SideEffect              string `json:"side_effect"`
	ReviewStatus            string `json:"review_status"`
	Enabled                 bool   `json:"enabled"`
	CreatedAt               string `json:"created_at"`
	DisabledAt              string `json:"disabled_at,omitempty"`
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

// ScanTaskRunProtocolEvidence is a safe, structured endpoint observation.
// Raw HTTP headers and bodies never enter the run snapshot.
const (
	ProtocolEvidencePassiveBanner = "passive_banner"
	ProtocolEvidenceActiveProbe   = "active_probe"
	ProtocolEvidenceWeb           = "web"

	ProtocolProbeOutcomeResponded      = "responded"
	ProtocolProbeOutcomeNoResponse     = "no_response"
	ProtocolProbeOutcomeConnectFailed  = "connect_failed"
	ProtocolProbeOutcomeConnectTimeout = "connect_timeout"
	ProtocolProbeOutcomeWriteFailed    = "write_failed"
	ProtocolProbeOutcomeReadFailed     = "read_failed"
	ProtocolProbeOutcomeReadTimeout    = "read_timeout"
	ProtocolProbeOutcomeBudgetTimeout  = "budget_timeout"
	ProtocolProbeOutcomeCanceled       = "canceled"
)

type ScanTaskRunProtocolEvidence struct {
	IP                   string `json:"ip"`
	Port                 int    `json:"port"`
	EvidenceType         string `json:"evidence_type"`
	ProbeName            string `json:"probe_name,omitempty"`
	Protocol             string `json:"protocol"`
	Responded            bool   `json:"responded"`
	Outcome              string `json:"outcome,omitempty"`
	Diagnostic           string `json:"diagnostic,omitempty"`
	StatusCode           int    `json:"status_code,omitempty"`
	Server               string `json:"server,omitempty"`
	Title                string `json:"title,omitempty"`
	BannerCapturedLength int    `json:"banner_captured_length,omitempty"`
	BannerSHA256         string `json:"banner_sha256,omitempty"`
	BannerTruncated      bool   `json:"banner_truncated,omitempty"`
	HeaderCapturedLength int    `json:"header_captured_length,omitempty"`
	HeaderSHA256         string `json:"header_sha256,omitempty"`
	HeaderTruncated      bool   `json:"header_truncated,omitempty"`
	BodyCapturedLength   int    `json:"body_captured_length,omitempty"`
	BodySHA256           string `json:"body_sha256,omitempty"`
	BodyTruncated        bool   `json:"body_truncated,omitempty"`
}

type ScanTaskRunVulnerability struct {
	FindingKey  string `json:"finding_key"`
	TemplateID  string `json:"template_id,omitempty"`
	Name        string `json:"name,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Target      string `json:"target"`
	TargetIP    string `json:"target_ip,omitempty"`
	TargetPort  int    `json:"target_port,omitempty"`
	MatchedAt   string `json:"matched_at,omitempty"`
	Description string `json:"description,omitempty"`
	Evidence    string `json:"-"`
}

// ScanTaskRunValidation records what vulnerability verification actually did.
// A successful scan run alone never implies that validation executed.
type ScanTaskRunValidation struct {
	Status                 string   `json:"status"`
	IdentifiedProductCount int      `json:"identified_product_count"`
	MappedProductCount     int      `json:"mapped_product_count"`
	UnmappedProducts       []string `json:"unmapped_products"`
	CandidateEndpointCount int      `json:"candidate_endpoint_count"`
	ExecutedEndpointCount  int      `json:"executed_endpoint_count"`
	TemplateCount          int      `json:"template_count"`
	ExecutedTemplateCount  int      `json:"executed_template_count"`
	FindingCount           int      `json:"finding_count"`
	StartedAt              string   `json:"started_at,omitempty"`
	FinishedAt             string   `json:"finished_at,omitempty"`
	Error                  string   `json:"error,omitempty"`
}

// ScanTaskRunTemplateCandidate preserves why one reviewed template was chosen.
type ScanTaskRunTemplateCandidate struct {
	TemplateID          string `json:"template_id"`
	Path                string `json:"path"`
	ProductKey          string `json:"product_key,omitempty"`
	Source              string `json:"source"`
	Reason              string `json:"reason"`
	TemplateSHA256      string `json:"template_sha256,omitempty"`
	TemplateSetRevision string `json:"template_set_revision,omitempty"`
	MappingImportID     int64  `json:"template_mapping_import_id,omitempty"`
	IP                  string `json:"ip,omitempty"`
	Port                int    `json:"port,omitempty"`
	Protocol            string `json:"protocol,omitempty"`
	Executed            bool   `json:"executed"`
}

type FingerprintMatchEvidence struct {
	MatcherID      int64  `json:"matcher_id"`
	EvidenceType   string `json:"evidence_type"`
	Target         string `json:"target,omitempty"`
	Operator       string `json:"operator"`
	ObservedSHA256 string `json:"observed_sha256"`
	ObservedLength int    `json:"observed_length"`
	Truncated      bool   `json:"truncated"`
	Summary        string `json:"summary"`
}

// FingerprintRunMatch remains in memory until the run snapshot transaction
// commits. SourceRuleID and SourceKey support reviewed source-specific mappings.
type FingerprintRunMatch struct {
	FingerprintImportID     int64                      `json:"fingerprint_import_id"`
	FingerprintSourceRuleID int64                      `json:"fingerprint_source_rule_id"`
	SourceKey               string                     `json:"source_key"`
	SourceRuleID            string                     `json:"source_rule_id"`
	IP                      string                     `json:"ip"`
	Port                    int                        `json:"port"`
	Protocol                string                     `json:"protocol"`
	Product                 string                     `json:"product_key"`
	SourceProduct           string                     `json:"source_product,omitempty"`
	ProductRole             string                     `json:"product_role,omitempty"`
	ExclusiveGroup          string                     `json:"exclusive_group,omitempty"`
	Version                 string                     `json:"version,omitempty"`
	CPE                     string                     `json:"cpe,omitempty"`
	Tags                    []string                   `json:"tags,omitempty"`
	Soft                    bool                       `json:"soft_match"`
	EvidenceSummary         string                     `json:"evidence_summary"`
	Evidence                []FingerprintMatchEvidence `json:"evidence"`
}

type ScanTaskRunSnapshot struct {
	RunID              int64                          `json:"run_id"`
	Hosts              []ScanTaskRunHost              `json:"hosts"`
	Ports              []ScanTaskRunPort              `json:"ports"`
	ProtocolEvidence   []ScanTaskRunProtocolEvidence  `json:"protocol_evidence"`
	Validation         ScanTaskRunValidation          `json:"validation"`
	Vulnerabilities    []ScanTaskRunVulnerability     `json:"vulnerabilities"`
	TemplateCandidates []ScanTaskRunTemplateCandidate `json:"template_candidates"`
	FingerprintMatches []FingerprintRunMatch          `json:"fingerprint_matches,omitempty"`
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
	Port              int                           `json:"port"`
	Transport         string                        `json:"transport"`
	State             string                        `json:"state"`
	Service           string                        `json:"service"`
	ObservationRunID  int64                         `json:"observation_run_id,omitempty"`
	ObservedAt        string                        `json:"observed_at,omitempty"`
	Protocol          string                        `json:"protocol,omitempty"`
	StatusCode        int                           `json:"status_code,omitempty"`
	Server            string                        `json:"server,omitempty"`
	Title             string                        `json:"title,omitempty"`
	ResponseLength    int                           `json:"response_length,omitempty"`
	ResponseSHA256    string                        `json:"response_sha256,omitempty"`
	ResponseTruncated bool                          `json:"response_truncated,omitempty"`
	ProtocolEvidence  []ScanTaskRunProtocolEvidence `json:"protocol_evidence"`
	Technologies      []AssetTechnology             `json:"technologies"`
	Validation        AssetValidationSummary        `json:"validation"`
	UnresolvedReasons []string                      `json:"unresolved_reasons"`
	LastSeenAt        string                        `json:"last_seen_at"`
}

type AssetTechnologySource struct {
	SourceKey     string `json:"source_key"`
	SourceRuleID  string `json:"source_rule_id,omitempty"`
	SourceProduct string `json:"source_product,omitempty"`
}

// AssetTechnology is the user-facing projection of one normalized product.
// It deliberately keeps source wording and protocols without exposing raw
// matcher or response content.
type AssetTechnology struct {
	ProductKey         string                  `json:"product_key"`
	DisplayName        string                  `json:"display_name"`
	SourceProductNames []string                `json:"source_product_names"`
	Role               string                  `json:"role"`
	ExclusiveGroup     string                  `json:"exclusive_group,omitempty"`
	Protocols          []string                `json:"protocols"`
	Version            string                  `json:"version,omitempty"`
	VersionCandidates  []string                `json:"version_candidates"`
	CPE                string                  `json:"cpe,omitempty"`
	CPECandidates      []string                `json:"cpe_candidates"`
	ProductStatus      string                  `json:"product_status"`
	ProductSourceCount int                     `json:"product_source_count"`
	VersionStatus      string                  `json:"version_status"`
	VersionSourceCount int                     `json:"version_source_count"`
	CPEStatus          string                  `json:"cpe_status"`
	CPESourceCount     int                     `json:"cpe_source_count"`
	Tags               []string                `json:"tags"`
	Sources            []AssetTechnologySource `json:"sources"`
	EvidenceSummaries  []string                `json:"evidence_summaries"`
	ConflictCandidates []string                `json:"conflict_candidates"`
}

type AssetValidationSummary struct {
	Enabled                   bool                       `json:"enabled"`
	Status                    string                     `json:"status"`
	Reason                    string                     `json:"reason,omitempty"`
	IdentifiedProductCount    int                        `json:"identified_product_count"`
	MappedProductCount        int                        `json:"mapped_product_count,omitempty"`
	UnmappedProducts          []string                   `json:"unmapped_products"`
	CandidateTemplateCount    int                        `json:"candidate_template_count"`
	ExecutedTemplateCount     int                        `json:"executed_template_count,omitempty"`
	FindingCount              int                        `json:"finding_count"`
	Findings                  []ScanTaskRunVulnerability `json:"findings"`
	RunCandidateEndpointCount int                        `json:"run_candidate_endpoint_count"`
	RunExecutedEndpointCount  int                        `json:"run_executed_endpoint_count"`
	RunIdentifiedProductCount int                        `json:"run_identified_product_count"`
	RunMappedProductCount     int                        `json:"run_mapped_product_count"`
	RunTemplateCount          int                        `json:"run_template_count"`
	RunExecutedTemplateCount  int                        `json:"run_executed_template_count"`
	RunFindingCount           int                        `json:"run_finding_count"`
	StartedAt                 string                     `json:"started_at,omitempty"`
	FinishedAt                string                     `json:"finished_at,omitempty"`
	Error                     string                     `json:"error,omitempty"`
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
