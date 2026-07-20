package diff

import (
	"sort"

	"golandproject/yscan/internal/model"
)

// CompareHosts returns hosts that became active and hosts that became inactive.
func CompareHosts(before, after []model.HostInventory) model.HostChanges {
	beforeActive := activeHostSet(before)
	afterActive := activeHostSet(after)

	changes := model.HostChanges{
		NewHosts:      difference(afterActive, beforeActive),
		InactiveHosts: difference(beforeActive, afterActive),
	}
	return changes
}

func activeHostSet(hosts []model.HostInventory) map[string]struct{} {
	set := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		if host.IsActive && host.IP != "" {
			set[host.IP] = struct{}{}
		}
	}
	return set
}

func difference(left, right map[string]struct{}) []string {
	values := make([]string, 0)
	for value := range left {
		if _, ok := right[value]; !ok {
			values = append(values, value)
		}
	}
	sort.Strings(values)
	return values
}
