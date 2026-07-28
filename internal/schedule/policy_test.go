package schedule

import (
	"testing"
	"time"
)

func TestClassifyDueRun(t *testing.T) {
	now := time.Date(2026, time.July, 24, 2, 0, 0, 0, time.UTC)
	if action := ClassifyDueRun(now.Add(-time.Nanosecond), now); action != DuePolicySkippedMisfire {
		t.Fatalf("past due action = %q, want %q", action, DuePolicySkippedMisfire)
	}
	if action := ClassifyDueRun(now, now); action != DuePolicyClaim {
		t.Fatalf("current due action = %q, want %q", action, DuePolicyClaim)
	}
}
