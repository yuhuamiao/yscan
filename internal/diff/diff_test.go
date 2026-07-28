package diff

import (
	"reflect"
	"testing"

	"golandproject/yscan/internal/model"
)

func TestCompareHosts(t *testing.T) {
	before := []model.HostInventory{
		{IP: "192.168.1.1", IsActive: true},
		{IP: "192.168.1.2", IsActive: true},
		{IP: "192.168.1.3", IsActive: false},
	}
	after := []model.HostInventory{
		{IP: "192.168.1.1", IsActive: true},
		{IP: "192.168.1.2", IsActive: false},
		{IP: "192.168.1.3", IsActive: true},
		{IP: "192.168.1.4", IsActive: true},
	}

	changes := CompareHosts(before, after)
	if want := []string{"192.168.1.3", "192.168.1.4"}; !reflect.DeepEqual(changes.NewHosts, want) {
		t.Fatalf("new hosts = %v, want %v", changes.NewHosts, want)
	}
	if want := []string{"192.168.1.2"}; !reflect.DeepEqual(changes.InactiveHosts, want) {
		t.Fatalf("inactive hosts = %v, want %v", changes.InactiveHosts, want)
	}
}

func TestCompareScopeMembers(t *testing.T) {
	before := []model.HostScopeMembership{
		{Scope: "subnet:192.168.1.0/24", IP: "192.168.1.1", IsActive: true},
		{Scope: "subnet:192.168.1.0/24", IP: "192.168.1.2", IsActive: true},
	}
	after := []model.HostScopeMembership{
		{Scope: "subnet:192.168.1.0/24", IP: "192.168.1.1", IsActive: true},
		{Scope: "subnet:192.168.1.0/24", IP: "192.168.1.2", IsActive: false},
		{Scope: "subnet:192.168.1.0/24", IP: "192.168.1.3", IsActive: true},
	}

	changes := CompareScopeMembers(before, after)
	if want := []string{"192.168.1.3"}; !reflect.DeepEqual(changes.NewHosts, want) {
		t.Fatalf("new hosts = %v, want %v", changes.NewHosts, want)
	}
	if want := []string{"192.168.1.2"}; !reflect.DeepEqual(changes.InactiveHosts, want) {
		t.Fatalf("inactive hosts = %v, want %v", changes.InactiveHosts, want)
	}
}

func TestComparePorts(t *testing.T) {
	changes := ComparePorts(
		map[string][]int{"192.168.1.1": {80, 443}, "192.168.1.2": {22}},
		map[string][]int{"192.168.1.1": {443, 8080}, "192.168.1.3": {6379}},
	)

	if want := []model.PortChange{{IP: "192.168.1.1", Port: 8080}, {IP: "192.168.1.3", Port: 6379}}; !reflect.DeepEqual(changes.Opened, want) {
		t.Fatalf("opened ports = %v, want %v", changes.Opened, want)
	}
	if want := []model.PortChange{{IP: "192.168.1.1", Port: 80}, {IP: "192.168.1.2", Port: 22}}; !reflect.DeepEqual(changes.Closed, want) {
		t.Fatalf("closed ports = %v, want %v", changes.Closed, want)
	}
}
