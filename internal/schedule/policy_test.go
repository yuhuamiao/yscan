package schedule

import (
	"testing"
	"time"
)

func TestClassifyDueRun(t *testing.T) {
	now := time.Date(2026, time.July, 24, 2, 0, 0, 0, time.UTC)
	if action := ClassifyDueRun(now.Add(-defaultPollInterval), now); action != DuePolicyClaim {
		t.Fatalf("current polling window action = %q, want %q", action, DuePolicyClaim)
	}
	if action := ClassifyDueRun(now.Add(-scheduledRunMisfireGrace-time.Nanosecond), now); action != DuePolicySkippedMisfire {
		t.Fatalf("historical due action = %q, want %q", action, DuePolicySkippedMisfire)
	}
	if action := ClassifyDueRun(now, now); action != DuePolicyClaim {
		t.Fatalf("current due action = %q, want %q", action, DuePolicyClaim)
	}
}
