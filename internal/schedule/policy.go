package schedule

import "time"

type DuePolicyAction string

const (
	DuePolicyClaim          DuePolicyAction = "claim"
	DuePolicySkippedMisfire DuePolicyAction = "skipped_misfire"
)

// ClassifyDueRun prevents historical schedules from being replayed after a
// scheduler outage. A run due exactly at now remains eligible for execution.
func ClassifyDueRun(scheduledFor, now time.Time) DuePolicyAction {
	if scheduledFor.UTC().Before(now.UTC()) {
		return DuePolicySkippedMisfire
	}
	return DuePolicyClaim
}
