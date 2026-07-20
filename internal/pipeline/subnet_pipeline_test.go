package pipeline

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestExpandIPv4CIDR(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		maxHosts  int
		wantCount int
		first     string
		last      string
		wantErr   bool
	}{
		{name: "single host", cidr: "192.0.2.10/32", maxHosts: 1, wantCount: 1, first: "192.0.2.10", last: "192.0.2.10"},
		{name: "point to point", cidr: "192.0.2.10/31", maxHosts: 2, wantCount: 2, first: "192.0.2.10", last: "192.0.2.11"},
		{name: "class c", cidr: "192.0.2.0/24", maxHosts: 254, wantCount: 254, first: "192.0.2.1", last: "192.0.2.254"},
		{name: "limit exceeded", cidr: "192.0.2.0/24", maxHosts: 253, wantErr: true},
		{name: "ipv6 rejected", cidr: "2001:db8::/64", maxHosts: 10, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts, err := ExpandIPv4CIDR(tt.cidr, tt.maxHosts)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ExpandIPv4CIDR(%q) error = %v, wantErr %t", tt.cidr, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(hosts) != tt.wantCount {
				t.Fatalf("host count = %d, want %d", len(hosts), tt.wantCount)
			}
			if hosts[0] != tt.first || hosts[len(hosts)-1] != tt.last {
				t.Fatalf("host range = %s-%s, want %s-%s", hosts[0], hosts[len(hosts)-1], tt.first, tt.last)
			}
		})
	}
}

func TestProbeAliveHosts(t *testing.T) {
	probe := func(_ context.Context, ip string) bool {
		return ip == "192.0.2.2" || ip == "192.0.2.10"
	}

	hosts, err := probeAliveHosts(context.Background(), []string{
		"192.0.2.10", "invalid", "192.0.2.2", "192.0.2.10",
	}, 2, probe)
	if err != nil {
		t.Fatalf("probeAliveHosts returned error: %v", err)
	}
	want := []string{"192.0.2.2", "192.0.2.10"}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("alive hosts = %v, want %v", hosts, want)
	}
}

func TestProbeAliveHostsHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := probeAliveHosts(ctx, []string{"192.0.2.1"}, 1, func(context.Context, string) bool {
		return true
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
