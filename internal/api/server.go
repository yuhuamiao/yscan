package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golandproject/yscan/internal/diff"
	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/report"
	"golandproject/yscan/internal/schedule"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/web"
)

type TaskRunner func(taskType, target string) (int64, error)

type ScanTaskCreator interface {
	Create(context.Context, model.ScanTask) (model.ScanTask, *model.ScanTaskRun, error)
}

type ScanTaskRunOperator interface {
	ScanTaskCreator
	RunNow(context.Context, int64) (model.ScanTaskRun, bool, error)
}

type ScanTaskRunStarter func(context.Context, model.ScanTaskRun)

type AccessPolicy struct{ TrustedCIDRs []string }

type createScanTaskRequest struct {
	Target   string               `json:"target"`
	ScanType string               `json:"scan_type"`
	Mode     string               `json:"mode"`
	Cron     string               `json:"cron,omitempty"`
	Timezone string               `json:"timezone,omitempty"`
	Config   model.ScanTaskConfig `json:"config"`
}

type createScanTaskResponse struct {
	Task model.ScanTask     `json:"task"`
	Run  *model.ScanTaskRun `json:"run,omitempty"`
}

func StartServer(db *sql.DB, addr string, runTask TaskRunner) error {
	return StartServerWithAccessPolicy(db, addr, runTask, AccessPolicy{})
}

func StartServerWithAccessPolicy(db *sql.DB, addr string, runTask TaskRunner, policy AccessPolicy) error {
	handler, err := newHandler(db, runTask)
	if err != nil {
		return err
	}
	if err := policy.Validate(addr); err != nil {
		return err
	}

	log.Printf("API server listening on %s", addr)
	return http.ListenAndServe(addr, policy.Wrap(handler))
}

func StartServerWithScanTasks(db *sql.DB, addr string, runTask TaskRunner, creator ScanTaskCreator, startRun ScanTaskRunStarter) error {
	return StartServerWithScanTasksAndAccessPolicy(db, addr, runTask, creator, startRun, AccessPolicy{})
}

func StartServerWithScanTasksAndAccessPolicy(db *sql.DB, addr string, runTask TaskRunner, creator ScanTaskCreator, startRun ScanTaskRunStarter, policy AccessPolicy) error {
	return StartServerWithScanTasksAndAccessPolicyContext(context.Background(), db, addr, runTask, creator, startRun, policy)
}

func StartServerWithScanTasksAndAccessPolicyContext(ctx context.Context, db *sql.DB, addr string, runTask TaskRunner, creator ScanTaskCreator, startRun ScanTaskRunStarter, policy AccessPolicy) error {
	return StartServerWithScanTasksAndAccessPolicyContextReady(ctx, db, addr, runTask, creator, startRun, policy, nil)
}

func StartServerWithScanTasksAndAccessPolicyContextReady(ctx context.Context, db *sql.DB, addr string, runTask TaskRunner, creator ScanTaskCreator, startRun ScanTaskRunStarter, policy AccessPolicy, ready func() error) error {
	return StartServerWithScanTasksAndAccessPolicyLifecycle(ctx, db, addr, runTask, creator, startRun, policy, ready, nil)
}

func StartServerWithScanTasksAndAccessPolicyLifecycle(ctx context.Context, db *sql.DB, addr string, runTask TaskRunner, creator ScanTaskCreator, startRun ScanTaskRunStarter, policy AccessPolicy, ready, requestsDrained func() error) error {
	var activeRuns sync.WaitGroup
	workerContext, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	handler, err := newHandlerWithScanTasksContextAndGroup(workerContext, db, runTask, creator, startRun, &activeRuns)
	if err != nil {
		return err
	}
	if err := policy.Validate(addr); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if ready != nil {
		if err := ready(); err != nil {
			_ = listener.Close()
			return err
		}
	}
	server := &http.Server{Addr: addr, Handler: policy.Wrap(handler), ReadHeaderTimeout: 10 * time.Second}
	listenResult := make(chan error, 1)
	go func() { listenResult <- server.Serve(listener) }()
	log.Printf("API server listening on %s", addr)
	select {
	case err := <-listenResult:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("graceful API shutdown: %w", err)
		}
		if requestsDrained != nil {
			if err := requestsDrained(); err != nil {
				return fmt.Errorf("after API request drain: %w", err)
			}
		}
		stopWorkers()
		runsStopped := make(chan struct{})
		go func() { activeRuns.Wait(); close(runsStopped) }()
		select {
		case <-runsStopped:
		case <-shutdownContext.Done():
			return errors.New("graceful API shutdown timed out waiting for active scans")
		}
		if err := <-listenResult; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func (policy AccessPolicy) Validate(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid API listen address: %w", err)
	}
	for _, cidr := range policy.TrustedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid trusted client CIDR %q", cidr)
		}
	}
	if host == "localhost" || net.ParseIP(host).IsLoopback() {
		return nil
	}
	// An empty host (":8080") is a wildcard listener, just like 0.0.0.0
	// and [::], and therefore must never inherit the loopback exception.
	if len(policy.TrustedCIDRs) == 0 {
		return errors.New("non-loopback API listener requires at least one trusted client CIDR")
	}
	return nil
}

func (policy AccessPolicy) Wrap(next http.Handler) http.Handler {
	if len(policy.TrustedCIDRs) == 0 {
		return next
	}
	networks := make([]*net.IPNet, 0, len(policy.TrustedCIDRs))
	for _, cidr := range policy.TrustedCIDRs {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			networks = append(networks, network)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		allowed := false
		for _, network := range networks {
			if network.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func newHandler(db *sql.DB, runTask TaskRunner) (http.Handler, error) {
	return newHandlerWithScanTasks(db, runTask, nil, nil)
}

func newHandlerWithScanTasks(db *sql.DB, runTask TaskRunner, creator ScanTaskCreator, startRun ScanTaskRunStarter) (http.Handler, error) {
	return newHandlerWithScanTasksContext(context.Background(), db, runTask, creator, startRun)
}

func newHandlerWithScanTasksContext(serviceContext context.Context, db *sql.DB, runTask TaskRunner, creator ScanTaskCreator, startRun ScanTaskRunStarter) (http.Handler, error) {
	return newHandlerWithScanTasksContextAndGroup(serviceContext, db, runTask, creator, startRun, nil)
}

func newHandlerWithScanTasksContextAndGroup(serviceContext context.Context, db *sql.DB, runTask TaskRunner, creator ScanTaskCreator, startRun ScanTaskRunStarter, activeRuns *sync.WaitGroup) (http.Handler, error) {
	if runTask == nil {
		return nil, fmt.Errorf("task runner is required")
	}
	if serviceContext == nil {
		serviceContext = context.Background()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if db == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": "database is unavailable"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/tasks", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			tasks, err := storage.ListTasks(db)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, tasks)
		case http.MethodPost:
			writeJSON(w, http.StatusGone, map[string]string{"error": "legacy task creation is disabled; use /api/scan-tasks"})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	})

	mux.HandleFunc("/api/tasks/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
		if path == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}

		parts := strings.Split(path, "/")
		taskID, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid task id"})
			return
		}

		if len(parts) == 1 && r.Method == http.MethodGet {
			t, err := storage.GetTaskByID(db, taskID)
			if err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "task not found"})
				return
			}
			writeJSON(w, http.StatusOK, t)
			return
		}

		if len(parts) == 2 {
			switch parts[1] {
			case "cancel":
				if r.Method != http.MethodPost {
					writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
					return
				}
				writeJSON(w, http.StatusGone, map[string]string{"error": "legacy task cancellation is disabled; use /api/scan-tasks"})
				return
			case "findings":
				if r.Method != http.MethodGet {
					writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
					return
				}
				findings, err := storage.ListVulnerabilitiesByTask(db, taskID)
				if err != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
					return
				}
				writeJSON(w, http.StatusOK, findings)
				return
			case "changes":
				if r.Method != http.MethodGet {
					writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
					return
				}
				summary, err := storage.GetTaskChangeSummary(db, taskID)
				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						writeJSON(w, http.StatusNotFound, map[string]string{"error": "task change summary not found"})
					} else {
						writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
					}
					return
				}
				writeJSON(w, http.StatusOK, summary)
				return
			case "report":
				if r.Method != http.MethodGet {
					writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
					return
				}
				content, err := report.ReadTaskReport(report.DefaultDirectory, taskID)
				if err != nil {
					if errors.Is(err, os.ErrNotExist) {
						writeJSON(w, http.StatusNotFound, map[string]string{"error": "task report not found"})
					} else {
						writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
					}
					return
				}
				w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
				_, _ = w.Write(content)
				return
			}
		}

		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})

	mux.HandleFunc("/api/scan-tasks", func(w http.ResponseWriter, r *http.Request) {
		if creator == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan task API is unavailable"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			tasks, err := storage.ListScanTasks(db)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, tasks)
		case http.MethodPost:
			var req createScanTaskRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
				return
			}
			task, run, err := creator.Create(r.Context(), model.ScanTask{
				Target:   strings.TrimSpace(req.Target),
				ScanType: strings.TrimSpace(req.ScanType),
				Mode:     strings.TrimSpace(req.Mode),
				Cron:     strings.TrimSpace(req.Cron),
				Timezone: strings.TrimSpace(req.Timezone),
				Config:   req.Config,
			})
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if run != nil && startRun != nil {
				launchScanTaskRun(serviceContext, activeRuns, startRun, *run)
			}
			writeJSON(w, http.StatusCreated, createScanTaskResponse{Task: task, Run: run})
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	})

	mux.HandleFunc("/api/scan-tasks/", func(w http.ResponseWriter, r *http.Request) {
		if creator == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan task API is unavailable"})
			return
		}
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/scan-tasks/"), "/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		taskID, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || taskID <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid scan task id"})
			return
		}
		if len(parts) == 1 {
			if r.Method == http.MethodPut {
				var req createScanTaskRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
					return
				}
				current, err := storage.GetScanTask(db, taskID)
				if err != nil {
					writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan task not found"})
					return
				}
				updated, err := schedule.NewTaskService(db, nil).Update(r.Context(), model.ScanTask{ID: taskID, Target: strings.TrimSpace(req.Target), ScanType: strings.TrimSpace(req.ScanType), Mode: strings.TrimSpace(req.Mode), Cron: strings.TrimSpace(req.Cron), Timezone: strings.TrimSpace(req.Timezone), Config: req.Config, Status: current.Status})
				if err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
					return
				}
				writeJSON(w, http.StatusOK, updated)
				return
			}
			if r.Method != http.MethodGet {
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
				return
			}
			task, err := storage.GetScanTask(db, taskID)
			if err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan task not found"})
				return
			}
			writeJSON(w, http.StatusOK, task)
			return
		}
		if len(parts) >= 3 && parts[1] == "runs" {
			handleScanTaskRunRoute(db, w, r, taskID, parts)
			return
		}
		if len(parts) != 2 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		switch parts[1] {
		case "runs":
			if r.Method != http.MethodGet {
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
				return
			}
			runs, err := storage.ListScanTaskRuns(db, taskID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, runs)
		case "run-now":
			if r.Method != http.MethodPost {
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
				return
			}
			operator, ok := creator.(ScanTaskRunOperator)
			if !ok {
				writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "run-now is unavailable"})
				return
			}
			run, launch, err := operator.RunNow(r.Context(), taskID)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			if launch && startRun != nil {
				launchScanTaskRun(serviceContext, activeRuns, startRun, run)
			}
			writeJSON(w, http.StatusAccepted, map[string]interface{}{"run": run, "started": launch})
		case "pause", "resume", "archive":
			if r.Method != http.MethodPost {
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
				return
			}
			var err error
			switch parts[1] {
			case "pause":
				err = storage.PauseScanTask(db, taskID)
			case "resume":
				err = storage.ResumeScanTask(db, taskID)
			case "archive":
				err = storage.ArchiveScanTask(db, taskID)
			}
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			task, err := storage.GetScanTask(db, taskID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, task)
		default:
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		}
	})

	mux.HandleFunc("/api/assets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}

		query := storage.HostInventoryQuery{
			Scope:  r.URL.Query().Get("scope"),
			Source: r.URL.Query().Get("source"),
		}
		if rawActive := strings.TrimSpace(r.URL.Query().Get("active")); rawActive != "" {
			active, err := strconv.ParseBool(rawActive)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "active must be true or false"})
				return
			}
			query.IsActive = &active
		}

		assets, err := storage.ListHostInventory(db, query)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, assets)
	})

	// Fingerprint catalog endpoints are intentionally read-only. Mutating
	// imports and review mappings remains a local CLI operation with an
	// auditable manifest, rather than a broadly exposed network API.
	mux.HandleFunc("/api/fingerprints/sources", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		sources, err := storage.ListFingerprintSources(db)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, sources)
	})
	mux.HandleFunc("/api/fingerprints/imports", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		page, pageSize, err := fingerprintPageParams(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		imports, total, err := storage.ListFingerprintImportSummariesPage(db, page, pageSize)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"items": imports, "page": page, "page_size": pageSize, "total": total})
	})
	mux.HandleFunc("/api/fingerprints/imports/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		id, err := strconv.ParseInt(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/fingerprints/imports/"), "/"), 10, 64)
		if err != nil || id <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid fingerprint import id"})
			return
		}
		value, err := storage.GetFingerprintImport(db, id)
		if errors.Is(err, storage.ErrFingerprintImportNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "fingerprint import not found"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, value)
	})
	mux.HandleFunc("/api/fingerprints/sources/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/fingerprints/sources/"), "/"), "/")
		if len(parts) != 2 || parts[1] != "rules" || strings.TrimSpace(parts[0]) == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		page, err := optionalPositiveInt(r.URL.Query().Get("page"), 1)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "page must be a positive integer"})
			return
		}
		pageSizeText := r.URL.Query().Get("page_size")
		if pageSizeText == "" {
			pageSizeText = r.URL.Query().Get("limit")
		}
		pageSize, err := optionalPositiveInt(pageSizeText, 50)
		if err != nil || pageSize > 200 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "page_size must be between 1 and 200"})
			return
		}
		importID, err := optionalPositiveInt64(r.URL.Query().Get("import_id"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "import_id must be a positive integer"})
			return
		}
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		if status != "" && status != "executable" && status != "unsupported" && status != "import_error" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid fingerprint rule status"})
			return
		}
		rules, err := storage.ListFingerprintSourceRulesPage(db, storage.FingerprintSourceRuleQuery{SourceKey: parts[0], ImportID: importID, RuleID: r.URL.Query().Get("rule_id"), Product: r.URL.Query().Get("product"), Status: status, Page: page, PageSize: pageSize})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, rules)
	})
	mux.HandleFunc("/api/fingerprints/template-mappings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		mappings, err := storage.ListFingerprintTemplateMappings(db)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, mappings)
	})

	mux.HandleFunc("/api/assets/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		rawIP := strings.TrimPrefix(r.URL.Path, "/api/assets/")
		ip, err := url.PathUnescape(rawIP)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid asset identifier"})
			return
		}
		detail, err := storage.GetAssetDetail(db, ip)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "asset not found"})
			} else {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			}
			return
		}
		writeJSON(w, http.StatusOK, detail)
	})

	mux.Handle("/", web.Handler())

	return mux, nil
}

func launchScanTaskRun(ctx context.Context, activeRuns *sync.WaitGroup, startRun ScanTaskRunStarter, run model.ScanTaskRun) {
	if activeRuns != nil {
		activeRuns.Add(1)
	}
	go func() {
		if activeRuns != nil {
			defer activeRuns.Done()
		}
		startRun(ctx, run)
	}()
}

func optionalPositiveInt(value string, fallback int) (int, error) {
	if strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, errors.New("not a positive integer")
	}
	return parsed, nil
}

func optionalPositiveInt64(value string) (int64, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, errors.New("not a positive integer")
	}
	return parsed, nil
}

func fingerprintPageParams(r *http.Request) (int, int, error) {
	page, err := optionalPositiveInt(r.URL.Query().Get("page"), 1)
	if err != nil {
		return 0, 0, errors.New("page must be a positive integer")
	}
	pageSize, err := optionalPositiveInt(r.URL.Query().Get("page_size"), 50)
	if err != nil || pageSize > 200 {
		return 0, 0, errors.New("page_size must be between 1 and 200")
	}
	return page, pageSize, nil
}

// handleScanTaskRunRoute exposes immutable run state and its task-local Diff.
// A run ID is always checked against the parent logical task before returning
// data, so callers cannot accidentally compare results across tasks.
func handleScanTaskRunRoute(db *sql.DB, w http.ResponseWriter, r *http.Request, taskID int64, parts []string) {
	if len(parts) < 3 || len(parts) > 5 || (len(parts) == 5 && parts[3] != "fingerprints") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	runID, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || runID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid scan task run id"})
		return
	}
	run, err := storage.GetScanTaskRun(db, runID)
	if errors.Is(err, storage.ErrScanTaskRunNotFound) || (err == nil && run.ScanTaskID != taskID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan task run not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	if len(parts) == 3 {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, run)
		return
	}
	if parts[3] == "cancel" {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if err := storage.CancelScanTaskRun(db, taskID, runID); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"scan_task_id": taskID, "run_id": runID, "status": model.ScanTaskRunStatusCancelRequested})
		return
	}
	if parts[3] == "report" {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		content, err := report.ReadScanTaskRunReport(report.DefaultDirectory, taskID, runID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan task run report not found"})
			} else {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write(content)
		return
	}
	if parts[3] == "audit-report" {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		content, err := report.ReadScanTaskRunAuditReport(report.DefaultDirectory, taskID, runID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan task run audit report not found"})
			} else {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			}
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		_, _ = w.Write(content)
		return
	}
	if parts[3] == "findings" {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		page, pageSize, err := fingerprintPageParams(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		snapshot, err := storage.GetScanTaskRunSnapshot(db, runID)
		if errors.Is(err, storage.ErrScanTaskRunSnapshotUnavailable) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "scan task run snapshot is not available"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		total := len(snapshot.Vulnerabilities)
		start := (page - 1) * pageSize
		if start > total {
			start = total
		}
		end := start + pageSize
		if end > total {
			end = total
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"validation": snapshot.Validation, "items": snapshot.Vulnerabilities[start:end], "page": page, "page_size": pageSize, "total": total})
		return
	}
	if parts[3] == "fingerprints" {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if len(parts) == 4 {
			writeJSON(w, http.StatusOK, map[string]interface{}{"resources": []string{"imports", "matches", "evidence", "conclusions"}})
			return
		}
		page, pageSize, err := fingerprintPageParams(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		var items interface{}
		var total int
		switch parts[4] {
		case "imports":
			items, total, err = storage.ListFingerprintImportsForRunPage(db, runID, page, pageSize)
		case "matches":
			items, total, err = storage.ListFingerprintRunMatchesPage(db, runID, page, pageSize)
		case "evidence":
			items, total, err = storage.ListFingerprintRunEvidencePage(db, runID, page, pageSize)
		case "conclusions":
			items, total, err = storage.ListFingerprintRunConclusionsPage(db, runID, page, pageSize)
		default:
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "page": page, "page_size": pageSize, "total": total})
		return
	}
	if parts[3] != "changes" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var changes model.ScanTaskRunChanges
	baselineRunID := strings.TrimSpace(r.URL.Query().Get("baseline_run_id"))
	if baselineRunID == "" {
		changes, err = diff.CompareRunWithPreviousSuccess(db, runID)
	} else {
		baselineID, parseErr := strconv.ParseInt(baselineRunID, 10, 64)
		if parseErr != nil || baselineID <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "baseline_run_id must be a positive integer"})
			return
		}
		changes, err = diff.CompareScanTaskRuns(db, baselineID, runID)
	}
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrScanTaskRunNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan task run not found"})
		case errors.Is(err, diff.ErrScanTaskRunMismatch):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "baseline run must belong to the same scan task"})
		case errors.Is(err, diff.ErrScanTaskRunNotSuccessful), errors.Is(err, storage.ErrScanTaskRunSnapshotUnavailable):
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}
	writeJSON(w, http.StatusOK, changes)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
