package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"golandproject/yscan/internal/diff"
	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/pipeline"
	"golandproject/yscan/internal/report"
	"golandproject/yscan/internal/schedule"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/web"
)

type TaskRunner func(taskType, target string) (int64, error)

type ScanTaskCreator interface {
	Create(context.Context, model.ScanTask) (model.ScanTask, *model.ScanTaskRun, error)
}

type ScanTaskRunStarter func(context.Context, model.ScanTaskRun)

type createTaskRequest struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

type createTaskResponse struct {
	TaskID int64  `json:"task_id"`
	Status string `json:"status"`
}

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
	handler, err := newHandler(db, runTask)
	if err != nil {
		return err
	}

	log.Printf("API server listening on %s", addr)
	return http.ListenAndServe(addr, handler)
}

func StartServerWithScanTasks(db *sql.DB, addr string, runTask TaskRunner, creator ScanTaskCreator, startRun ScanTaskRunStarter) error {
	handler, err := newHandlerWithScanTasks(db, runTask, creator, startRun)
	if err != nil {
		return err
	}

	log.Printf("API server listening on %s", addr)
	return http.ListenAndServe(addr, handler)
}

func newHandler(db *sql.DB, runTask TaskRunner) (http.Handler, error) {
	return newHandlerWithScanTasks(db, runTask, nil, nil)
}

func newHandlerWithScanTasks(db *sql.DB, runTask TaskRunner, creator ScanTaskCreator, startRun ScanTaskRunStarter) (http.Handler, error) {
	if runTask == nil {
		return nil, fmt.Errorf("task runner is required")
	}

	mux := http.NewServeMux()

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
			var req createTaskRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
				return
			}

			req.Type = strings.TrimSpace(req.Type)
			req.Target = strings.TrimSpace(req.Target)
			if req.Type == "" || req.Target == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type and target are required"})
				return
			}

			supported := map[string]bool{
				model.TaskTypeScanIP:          true,
				model.TaskTypeScanIPVuln:      true,
				model.TaskTypeScanSubnet:      true,
				model.TaskTypeScanSubnetVuln:  true,
				model.TaskTypeVulnIP:          true,
				model.TaskTypeCollectDomain:   true,
				model.TaskTypeCollectAndScan:  true,
				model.TaskTypeCollectScanVuln: true,
			}
			if !supported[req.Type] {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported task type"})
				return
			}
			if (req.Type == model.TaskTypeScanSubnet || req.Type == model.TaskTypeScanSubnetVuln) && !pipeline.IsIPv4CIDR(req.Target) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subnet task target must be an IPv4 CIDR"})
				return
			}

			taskID, err := runTask(req.Type, req.Target)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}

			writeJSON(w, http.StatusAccepted, createTaskResponse{TaskID: taskID, Status: model.TaskStatusQueued})
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
				if err := storage.CancelTask(db, taskID); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
					return
				}
				writeJSON(w, http.StatusOK, map[string]interface{}{"task_id": taskID, "status": model.TaskStatusCancelRequested})
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
				go startRun(context.Background(), *run)
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

// handleScanTaskRunRoute exposes immutable run state and its task-local Diff.
// A run ID is always checked against the parent logical task before returning
// data, so callers cannot accidentally compare results across tasks.
func handleScanTaskRunRoute(db *sql.DB, w http.ResponseWriter, r *http.Request, taskID int64, parts []string) {
	if len(parts) < 3 || len(parts) > 4 {
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
