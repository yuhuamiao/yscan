package schedule

import (
	"testing"
	"time"
)

func TestNextScheduledAtUsesTaskTimezoneAndReturnsUTC(t *testing.T) {
	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatalf("load Asia/Shanghai: %v", err)
	}

	daily, err := NextScheduledAt("0 2 * * *", "Asia/Shanghai", time.Date(2026, time.July, 24, 1, 30, 0, 0, shanghai))
	if err != nil {
		t.Fatalf("next daily schedule: %v", err)
	}
	if want := time.Date(2026, time.July, 23, 18, 0, 0, 0, time.UTC); !daily.Equal(want) {
		t.Fatalf("daily next = %s, want %s", daily, want)
	}

	weekly, err := NextScheduledAt("0 9 * * 1", "Asia/Shanghai", time.Date(2026, time.July, 24, 10, 0, 0, 0, shanghai))
	if err != nil {
		t.Fatalf("next weekly schedule: %v", err)
	}
	if want := time.Date(2026, time.July, 27, 1, 0, 0, 0, time.UTC); !weekly.Equal(want) {
		t.Fatalf("weekly next = %s, want %s", weekly, want)
	}
}

func TestParseCronRejectsUnsupportedExpressionsAndTimezones(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		timezone   string
	}{
		{name: "seconds field", expression: "0 0 2 * * *", timezone: "UTC"},
		{name: "every descriptor", expression: "@every 1h", timezone: "UTC"},
		{name: "daily descriptor", expression: "@daily", timezone: "UTC"},
		{name: "embedded timezone", expression: "CRON_TZ=UTC 0 2 * * *", timezone: "UTC"},
		{name: "invalid timezone", expression: "0 2 * * *", timezone: "Mars/Olympus"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseCron(tt.expression, tt.timezone); err == nil {
				t.Fatalf("ParseCron(%q, %q) must fail", tt.expression, tt.timezone)
			}
		})
	}
}

func TestCronScheduleRejectsUninitializedAndZeroReferenceTimes(t *testing.T) {
	if _, err := (CronSchedule{}).Next(time.Now()); err == nil {
		t.Fatal("uninitialized schedule must be rejected")
	}
	schedule, err := ParseCron("0 2 * * *", "UTC")
	if err != nil {
		t.Fatalf("parse cron: %v", err)
	}
	if _, err := schedule.Next(time.Time{}); err == nil {
		t.Fatal("zero reference time must be rejected")
	}
}
