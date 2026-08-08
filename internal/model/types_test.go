package model

import "testing"

func TestHostScopeMembershipValid(t *testing.T) {
	tests := []struct {
		name       string
		membership HostScopeMembership
		want       bool
	}{
		{name: "valid IPv4 scope member", membership: HostScopeMembership{Scope: "subnet:192.168.10.0/24", IP: "192.168.10.10"}, want: true},
		{name: "missing scope", membership: HostScopeMembership{IP: "192.168.10.10"}, want: false},
		{name: "invalid IP", membership: HostScopeMembership{Scope: "subnet:192.168.10.0/24", IP: "not-an-ip"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.membership.Valid(); got != tt.want {
				t.Fatalf("Valid() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestFingerprintProductClassificationSeparatesWebStackLayers(t *testing.T) {
	for _, test := range []struct {
		name, role, group string
	}{
		{name: "nginx", role: "web_server", group: "web_server"},
		{name: "Apache HTTP Server", role: "web_server", group: "web_server"},
		{name: "宝塔-BT.cn", role: "control_panel"},
		{name: "HTML5", role: "markup"},
		{name: "script", role: "web_primitive"},
	} {
		role, group := FingerprintProductClassification(test.name, nil)
		if role != test.role || group != test.group {
			t.Fatalf("classification(%q)=%q/%q want %q/%q", test.name, role, group, test.role, test.group)
		}
	}
}
