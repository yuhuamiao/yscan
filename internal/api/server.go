package api

import (
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

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/pipeline"
	"golandproject/yscan/internal/report"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/web"
)

type TaskRunner func(taskType, target string) (int64, error)

type createTaskRequest struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

type createTaskResponse struct {
	TaskID int64  `json:"task_id"`
	Status string `json:"status"`
}

func StartServer(db *sql.DB, addr string, runTask TaskRunner) error {
	handler, err := newHandler(db, runTask)
	if err != nil {
		return err
	}

	log.Printf("API server listening on %s", addr)
	return http.ListenAndServe(addr, handler)
}

func newHandler(db *sql.DB, runTask TaskRunner) (http.Handler, error) {
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
				writeJSON(w, http.StatusOK, map[string]interface{}{"task_id": taskID, "status": model.TaskStatusCanceled})
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

	mux.HandleFunc("/api/assets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}

		query := storage.HostInventoryQuery{Source: r.URL.Query().Get("source")}
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

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
