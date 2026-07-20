package main

import (
	"testing"

	"golandproject/yscan/internal/model"
)

func TestTaskTypeForScan(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		withVuln bool
		want     string
	}{
		{name: "ip", target: "192.168.1.10", want: model.TaskTypeScanIP},
		{name: "ip with vuln", target: "192.168.1.10", withVuln: true, want: model.TaskTypeScanIPVuln},
		{name: "cidr", target: "192.168.1.0/24", want: model.TaskTypeScanSubnet},
		{name: "cidr with vuln", target: "192.168.1.0/24", withVuln: true, want: model.TaskTypeScanSubnetVuln},
		{name: "ipv6 cidr remains non subnet", target: "2001:db8::/64", want: model.TaskTypeScanIP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := taskTypeForScan(tt.target, tt.withVuln); got != tt.want {
				t.Fatalf("taskTypeForScan(%q, %t) = %q, want %q", tt.target, tt.withVuln, got, tt.want)
			}
		})
	}
}

func TestTaskTypeForSubnet(t *testing.T) {
	if got := taskTypeForSubnet(false); got != model.TaskTypeScanSubnet {
		t.Fatalf("taskTypeForSubnet(false) = %q", got)
	}
	if got := taskTypeForSubnet(true); got != model.TaskTypeScanSubnetVuln {
		t.Fatalf("taskTypeForSubnet(true) = %q", got)
	}
}
