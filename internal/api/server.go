package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"golandproject/yscan/internal/model"
	"golandproject/yscan/internal/storage"
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
	if runTask == nil {
		return fmt.Errorf("task runner is required")
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
				model.TaskTypeScanIP:         true,
				model.TaskTypeCollectDomain:  true,
				model.TaskTypeCollectAndScan: true,
			}
			if !supported[req.Type] {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported task type"})
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

		if len(parts) == 2 && parts[1] == "cancel" && r.Method == http.MethodPost {
			if err := storage.CancelTask(db, taskID); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"task_id": taskID, "status": model.TaskStatusCanceled})
			return
		}

		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})

	log.Printf("API server listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
