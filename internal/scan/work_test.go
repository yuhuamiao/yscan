package scan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
)

func TestScanPortsFindsSpecifiedOpenPort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-yscan-test\r\n"))
		close(accepted)
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	results, err := ScanPorts(context.Background(), "127.0.0.1", "tcp", []int{0, -1, port, port, 65536})
	if err != nil {
		t.Fatalf("scan ports: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("open results = %d, want 1", len(results))
	}
	if results[0].Address != net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) {
		t.Fatalf("address = %s", results[0].Address)
	}
	<-accepted
}

func TestScanPortsReturnsCanceledContextWithoutStartingProbes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := ScanPorts(ctx, "127.0.0.1", "tcp", []int{1, 2, 3})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if len(results) != 0 {
		t.Fatalf("results = %v, want no probes", results)
	}
}

func TestInternalBaselinePortsCoverInternalServices(t *testing.T) {
	ports := InternalBaselinePorts()
	required := map[int]bool{
		445:  false, // SMB
		3389: false, // RDP
		389:  false, // LDAP
		5985: false, // WinRM
		3306: false, // database
		2375: false, // Docker API
		6443: false, // Kubernetes API
	}
	for _, port := range ports {
		if _, ok := required[port]; ok {
			required[port] = true
		}
	}
	for port, found := range required {
		if !found {
			t.Fatalf("baseline does not contain %d", port)
		}
	}

	ports[0] = 1
	if InternalBaselinePorts()[0] == 1 {
		t.Fatal("baseline ports must not expose mutable internal state")
	}
}
