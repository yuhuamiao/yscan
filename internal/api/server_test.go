package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"golandproject/yscan/internal/model"
)

func TestSubnetTaskTypesAreAccepted(t *testing.T) {
	for _, taskType := range []string{model.TaskTypeScanSubnet, model.TaskTypeScanSubnetVuln} {
		t.Run(taskType, func(t *testing.T) {
			var gotType, gotTarget string
			handler, err := newHandler(nil, func(taskType, target string) (int64, error) {
				gotType = taskType
				gotTarget = target
				return 42, nil
			})
			if err != nil {
				t.Fatalf("newHandler: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewBufferString(`{"type":"`+taskType+`","target":"192.168.1.0/24"}`))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			if recorder.Code != http.StatusAccepted {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
			if gotType != taskType || gotTarget != "192.168.1.0/24" {
				t.Fatalf("runner received (%q, %q)", gotType, gotTarget)
			}
		})
	}
}

func TestSubnetTaskRejectsNonCIDRTarget(t *testing.T) {
	handler, err := newHandler(nil, func(string, string) (int64, error) {
		t.Fatal("task runner should not be called")
		return 0, nil
	})
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewBufferString(`{"type":"scan_subnet","target":"192.168.1.10"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestConsoleRoutesServeTheWebApplication(t *testing.T) {
	handler, err := newHandler(nil, func(string, string) (int64, error) { return 0, nil })
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}

	for _, path := range []string{"/", "/tasks", "/assets", "/reports"} {
		t.Run(path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d", recorder.Code)
			}
			if !bytes.Contains(recorder.Body.Bytes(), []byte("yscan")) {
				t.Fatalf("console response does not contain application name")
			}
		})
	}
}
