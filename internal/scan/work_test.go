package scan

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"golandproject/yscan/internal/identify"
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

func TestV2DiscoveryDoesNotUseProcessGlobalFingerprint(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for count := 0; count < 2; count++ {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = connection.Write([]byte("Jenkins fixture\r\n"))
			_ = connection.Close()
		}
	}()
	identify.SetFingerprintMatcher(func(string) string { return "Jenkins" })
	t.Cleanup(func() { identify.SetFingerprintMatcher(nil) })
	port := listener.Addr().(*net.TCPAddr).Port
	legacy, err := ScanPorts(context.Background(), "127.0.0.1", "tcp", []int{port})
	if err != nil || len(legacy) != 1 || legacy[0].Product != "jenkins" {
		t.Fatalf("legacy fingerprint result=%#v err=%v", legacy, err)
	}
	discovery, err := ScanPortsDiscovery(context.Background(), "127.0.0.1", "tcp", []int{port})
	if err != nil || len(discovery) != 1 || discovery[0].Product != "" || discovery[0].FingerprintSource != "" {
		t.Fatalf("V2 discovery result=%#v err=%v", discovery, err)
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

func TestFullPortBudgetAndCanceledCoverage(t *testing.T) {
	if budget := FullPortScanWorstCaseBudget(); budget <= 0 || budget >= 30*time.Minute {
		t.Fatalf("full port scan budget = %s, want a positive budget below 30m", budget)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, err := RunDiscoveryWithOutcome(ctx, "127.0.0.1", "tcp")
	if !errors.Is(err, context.Canceled) || outcome.Complete() || outcome.AttemptedPorts >= outcome.TotalPorts {
		t.Fatalf("canceled outcome=%#v err=%v", outcome, err)
	}
}

func TestProbeDeadlineAlsoBoundsBannerRead(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		close(accepted)
		<-time.After(time.Second)
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	started := time.Now()
	result := probePort(context.Background(), "127.0.0.1", "tcp", port, 40*time.Millisecond, false)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("banner read exceeded probe deadline: %s", elapsed)
	}
	if !result.Open {
		t.Fatalf("connected port must remain open: %#v", result)
	}
	<-accepted
}

func TestRunDiscoversNonBaselineTCPPort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	for _, baselinePort := range InternalBaselinePorts() {
		if port == baselinePort {
			t.Skipf("test listener selected baseline port %d", port)
		}
	}
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = connection.Write([]byte("SSH-2.0-yscan-full-scan-test\r\n"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	results, err := Run(ctx, "127.0.0.1", "tcp")
	if err != nil {
		t.Fatalf("run full TCP scan: %v", err)
	}
	wantAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for _, result := range results {
		if result.Address == wantAddress && result.Open {
			return
		}
	}
	t.Fatalf("full scan did not discover non-baseline port %s: %#v", wantAddress, results)
}

func TestParsePortSpecCanonicalizesRangesAndRejectsInvalidInput(t *testing.T) {
	ports, err := ParsePortSpec("443, 80, 8000-8002,443")
	if err != nil || FormatPortSpec(ports) != "80,443,8000-8002" {
		t.Fatalf("ports=%v canonical=%q err=%v", ports, FormatPortSpec(ports), err)
	}
	fullRange, err := ParsePortSpec("1-65535")
	if err != nil || len(fullRange) != 65535 || FormatPortSpec(fullRange) != "1-65535" {
		t.Fatalf("full range count=%d canonical=%q err=%v", len(fullRange), FormatPortSpec(fullRange), err)
	}
	for _, invalid := range []string{"0", "65536", "443-80", "80,,443", "abc", "80-90-100"} {
		if _, err := ParsePortSpec(invalid); err == nil {
			t.Fatalf("invalid port spec %q was accepted", invalid)
		}
	}
}
