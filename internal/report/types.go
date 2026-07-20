package report

import (
	"time"

	"golandproject/yscan/internal/model"
)

const DefaultDirectory = "reports"

type TaskReport struct {
	Task        model.Task
	Changes     model.TaskChangeSummary
	Findings    []model.Vulnerability
	GeneratedAt time.Time
}
