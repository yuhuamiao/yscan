package identify

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTryReadBannerKeepsSixteenKiBAndReportsTruncation(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	go func() {
		_, _ = server.Write([]byte(strings.Repeat("A", MaxBannerBytes+512)))
		_ = server.Close()
	}()
	banner, truncated := tryReadBanner(client)
	if len(banner) != MaxBannerBytes || !truncated {
		t.Fatalf("banner bytes=%d truncated=%t", len(banner), truncated)
	}
}

func TestTryReadBannerKeepsBytesReturnedWithEOF(t *testing.T) {
	expected := "SSH-2.0-OpenSSH_9.6\r\n"
	conn := &readErrorConn{payload: []byte(expected)}
	banner, truncated := tryReadBanner(conn)
	if banner != expected || truncated {
		t.Fatalf("banner=%q truncated=%t", banner, truncated)
	}
}

func TestIdentifyServiceRecognizesSSHOnNonStandardPort(t *testing.T) {
	if got := IdentifyService("SSH-2.0-OpenSSH_9.6 FreeBSD-14\r\n", 42441); got != "openssh" {
		t.Fatalf("service = %q, want openssh", got)
	}
	if got := IdentifyService("SSH-2.0-dropbear_2024.86\r\n", 42442); got != "ssh" {
		t.Fatalf("service = %q, want ssh", got)
	}
}

type readErrorConn struct{ payload []byte }

func (conn *readErrorConn) Read(buffer []byte) (int, error) {
	if len(conn.payload) == 0 {
		return 0, io.EOF
	}
	n := copy(buffer, conn.payload)
	conn.payload = conn.payload[n:]
	return n, io.EOF
}
func (*readErrorConn) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (*readErrorConn) Close() error                     { return nil }
func (*readErrorConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*readErrorConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*readErrorConn) SetDeadline(time.Time) error      { return nil }
func (*readErrorConn) SetReadDeadline(time.Time) error  { return nil }
func (*readErrorConn) SetWriteDeadline(time.Time) error { return nil }
