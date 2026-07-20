package diff

import (
	"sort"

	"golandproject/yscan/internal/model"
)

// ComparePorts returns newly open and no-longer-open ports between snapshots.
func ComparePorts(before, after map[string][]int) model.PortChanges {
	beforeSet := portSet(before)
	afterSet := portSet(after)

	return model.PortChanges{
		Opened: differencePorts(afterSet, beforeSet),
		Closed: differencePorts(beforeSet, afterSet),
	}
}

type portKey struct {
	ip   string
	port int
}

func portSet(snapshot map[string][]int) map[portKey]struct{} {
	set := make(map[portKey]struct{})
	for ip, ports := range snapshot {
		for _, port := range ports {
			if ip == "" || port < 1 || port > 65535 {
				continue
			}
			set[portKey{ip: ip, port: port}] = struct{}{}
		}
	}
	return set
}

func differencePorts(left, right map[portKey]struct{}) []model.PortChange {
	changes := make([]model.PortChange, 0)
	for key := range left {
		if _, ok := right[key]; !ok {
			changes = append(changes, model.PortChange{IP: key.ip, Port: key.port})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].IP == changes[j].IP {
			return changes[i].Port < changes[j].Port
		}
		return changes[i].IP < changes[j].IP
	})
	return changes
}
