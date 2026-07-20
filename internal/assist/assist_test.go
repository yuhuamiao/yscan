package assist

import "testing"

func TestInternalTCPProbePortsIncludeWindowsServices(t *testing.T) {
	want := map[int]bool{135: false, 445: false, 3389: false, 5985: false}
	for _, port := range internalTCPProbePorts {
		if _, ok := want[port]; ok {
			want[port] = true
		}
	}
	for port, found := range want {
		if !found {
			t.Fatalf("internal TCP probe ports do not include %d", port)
		}
	}
}
