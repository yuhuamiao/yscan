package schedule

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

var fiveFieldParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// CronSchedule is a validated five-field schedule bound to one IANA timezone.
// Its Next method always returns UTC for database persistence.
type CronSchedule struct {
	Expression string
	Timezone   string

	location *time.Location
	schedule cron.Schedule
}

func ParseCron(expression, timezone string) (CronSchedule, error) {
	expression = strings.TrimSpace(expression)
	timezone = strings.TrimSpace(timezone)
	if expression == "" {
		return CronSchedule{}, errors.New("cron expression is required")
	}
	if len(strings.Fields(expression)) != 5 {
		return CronSchedule{}, errors.New("cron expression must contain exactly five fields")
	}
	if strings.HasPrefix(expression, "@") || strings.HasPrefix(expression, "TZ=") || strings.HasPrefix(expression, "CRON_TZ=") {
		return CronSchedule{}, errors.New("cron descriptors and embedded timezones are not supported")
	}
	if timezone == "" {
		return CronSchedule{}, errors.New("timezone is required")
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("invalid timezone %q: %w", timezone, err)
	}
	schedule, err := fiveFieldParser.Parse(expression)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("invalid five-field cron expression: %w", err)
	}
	return CronSchedule{
		Expression: expression,
		Timezone:   timezone,
		location:   location,
		schedule:   schedule,
	}, nil
}

func (schedule CronSchedule) Next(after time.Time) (time.Time, error) {
	if schedule.schedule == nil || schedule.location == nil {
		return time.Time{}, errors.New("cron schedule is not initialized")
	}
	if after.IsZero() {
		return time.Time{}, errors.New("reference time is required")
	}
	next := schedule.schedule.Next(after.In(schedule.location))
	if next.IsZero() {
		return time.Time{}, errors.New("cron schedule has no future occurrence")
	}
	return next.UTC(), nil
}

func NextScheduledAt(expression, timezone string, after time.Time) (time.Time, error) {
	schedule, err := ParseCron(expression, timezone)
	if err != nil {
		return time.Time{}, err
	}
	return schedule.Next(after)
}
