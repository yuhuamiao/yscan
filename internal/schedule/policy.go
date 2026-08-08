package schedule

import "time"

type DuePolicyAction string

const (
	DuePolicyClaim           DuePolicyAction = "claim"
	DuePolicySkippedMisfire  DuePolicyAction = "skipped_misfire"
	scheduledRunMisfireGrace                 = 2 * defaultPollInterval
)

// ClassifyDueRun allows the scheduler enough time to observe one due minute
// across its polling interval while still preventing historical replay after
// an outage. Comparing timestamps for exact equality would skip every real
// run because the clock always advances beyond the cron minute.
func ClassifyDueRun(scheduledFor, now time.Time) DuePolicyAction {
	if scheduledFor.UTC().Before(now.UTC().Add(-scheduledRunMisfireGrace)) {
		return DuePolicySkippedMisfire
	}
	return DuePolicyClaim
}
