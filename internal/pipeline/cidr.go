package pipeline

import (
	"net"
	"strings"
)

// IsIPv4CIDR reports whether target is a valid IPv4 CIDR expression.
func IsIPv4CIDR(target string) bool {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(target))
	if err != nil || ip.To4() == nil {
		return false
	}

	_, bits := network.Mask.Size()
	return bits == net.IPv4len*8
}
