package pipeline

import "testing"

func TestIsIPv4CIDR(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{name: "network", target: "192.168.1.0/24", want: true},
		{name: "single host", target: "10.0.0.1/32", want: true},
		{name: "trimmed", target: " 172.16.0.0/16 ", want: true},
		{name: "plain ip", target: "192.168.1.1", want: false},
		{name: "domain", target: "example.com", want: false},
		{name: "ipv6", target: "2001:db8::/64", want: false},
		{name: "invalid mask", target: "192.168.1.0/33", want: false},
		{name: "empty", target: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsIPv4CIDR(tt.target); got != tt.want {
				t.Fatalf("IsIPv4CIDR(%q) = %t, want %t", tt.target, got, tt.want)
			}
		})
	}
}
