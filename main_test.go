package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"golandproject/yscan/internal/model"
	appRuntime "golandproject/yscan/internal/runtime"
	"golandproject/yscan/internal/schedule"
	"golandproject/yscan/internal/storage"
	"golandproject/yscan/internal/workflow"
)

func TestTopLevelHelpDoesNotInitializeDatabase(t *testing.T) {
	workingDirectory := t.TempDir()
	previousDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previousDirectory) })

	if err := runMainArgs([]string{"--help"}); err != nil {
		t.Fatalf("run help: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workingDirectory, "asm.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("help initialized asm.db: %v", err)
	}
}

func TestTopLevelVersionDoesNotInitializeHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "missing-home")
	if err := runMainArgs([]string{"--home", home, "--version"}); err != nil {
		t.Fatalf("run version: %v", err)
	}
	if _, err := os.Stat(home); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("version initialized home: %v", err)
	}
}

func TestRejectUnmigratedWorkingDirectoryDatabase(t *testing.T) {
	home := t.TempDir()
	workingDirectory := t.TempDir()
	paths, err := appRuntime.ResolveHome(os.Args[0], home)
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workingDirectory, "asm.db"), []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	err = rejectUnmigratedWorkingDirectoryDatabase(paths)
	if err == nil || !strings.Contains(err.Error(), "upgrade --from-home") || !strings.Contains(err.Error(), workingDirectory) {
		t.Fatalf("legacy cwd diagnostic = %v", err)
	}
}

func TestParseUpgradeSourceHome(t *testing.T) {
	if source, err := parseUpgradeSourceHome([]string{"--from-home", "/var/lib/yscan"}); err != nil || source != "/var/lib/yscan" {
		t.Fatalf("source = %q, %v", source, err)
	}
	for _, args := range [][]string{{"--from-home"}, {"--from-home", ""}, {"--unknown", "x"}, {"--from-home", "a", "extra"}} {
		if _, err := parseUpgradeSourceHome(args); err == nil {
			t.Fatalf("invalid upgrade arguments accepted: %v", args)
		}
	}
}

func TestNormalizeServerCommandKeepsOneServiceEntry(t *testing.T) {
	server, deprecated := normalizeServerCommand([]string{"server", "127.0.0.1:8080"})
	if deprecated || strings.Join(server, " ") != "server 127.0.0.1:8080" {
		t.Fatalf("server normalization = %v, %t", server, deprecated)
	}
	legacy, deprecated := normalizeServerCommand([]string{"api", "127.0.0.1:9090", "--allow-cidr", "192.168.1.0/24"})
	if !deprecated || strings.Join(legacy, " ") != "server 127.0.0.1:9090 --allow-cidr 192.168.1.0/24" {
		t.Fatalf("API compatibility normalization = %v, %t", legacy, deprecated)
	}
}

func TestPrepareServerStartupFailsBeforeDatabaseWork(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	config := appRuntime.Config{ListenAddress: listener.Addr().String()}
	if _, err := prepareServerStartup([]string{"server"}, config); err == nil {
		t.Fatal("occupied listener was accepted")
	}
}

func TestOccupiedServerPortDoesNotInitializeDatabase(t *testing.T) {
	home := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	err = runMainArgs([]string{"--home", home, "--listen", listener.Addr().String(), "server"})
	if err == nil {
		t.Fatal("occupied listener was accepted")
	}
	paths, err := appRuntime.ResolveHome(os.Args[0], home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths.Database); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("database changed before listen succeeded: %v", err)
	}
	if _, err := os.Stat(paths.ServerState); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("server state changed before listen succeeded: %v", err)
	}
}

func TestParseCLIConfigCapturesRuntimeOverrides(t *testing.T) {
	args, config, err := parseCLIConfig([]string{
		"--listen", "127.0.0.1:9090", "--trusted-cidrs=192.168.1.0/24", "--max-concurrency", "4",
		"--sqlite-busy-timeout=7s", "--log-max-bytes", "2048", "--log-max-files=5", "--nuclei-binary", "/opt/nuclei", "server",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(args, " ") != "server" {
		t.Fatalf("filtered arguments = %v", args)
	}
	want := map[string]string{
		appRuntime.ConfigListenAddress: "127.0.0.1:9090", appRuntime.ConfigAllowCIDRs: "192.168.1.0/24",
		appRuntime.ConfigMaxConcurrency: "4", appRuntime.ConfigSQLiteBusyTimeout: "7s", appRuntime.ConfigLogMaxBytes: "2048",
		appRuntime.ConfigLogMaxFiles: "5", appRuntime.ConfigNucleiBinary: "/opt/nuclei",
	}
	for key, value := range want {
		if config.Runtime[key] != value {
			t.Fatalf("runtime override %s = %q, want %q", key, config.Runtime[key], value)
		}
	}
}

func TestParseCLIConfigRejectsMissingValues(t *testing.T) {
	flags := []string{"--templates", "--dns-mode", "--dns-deny-cidr", "--home", "--listen", "--trusted-cidrs", "--max-concurrency", "--sqlite-busy-timeout", "--log-max-bytes", "--log-max-files", "--nuclei-binary"}
	for _, flag := range flags {
		t.Run(flag, func(t *testing.T) {
			if _, _, err := parseCLIConfig([]string{flag}); err == nil || !strings.Contains(err.Error(), "requires a value") {
				t.Fatalf("missing %s value error = %v", flag, err)
			}
			if _, _, err := parseCLIConfig([]string{flag + "="}); err == nil || !strings.Contains(err.Error(), "requires a value") {
				t.Fatalf("empty %s value error = %v", flag, err)
			}
		})
	}
}

func TestEffectiveBackgroundArgumentsPreserveResolvedConfiguration(t *testing.T) {
	config := appRuntime.Config{ListenAddress: "127.0.0.1:39091", AllowCIDRs: []string{"10.0.0.0/8"}, MaxConcurrency: 4, SQLiteBusyTimeout: 7 * time.Second, LogMaxBytes: 2048, LogMaxFiles: 5, NucleiBinary: "/opt/nuclei", NucleiTemplates: "/opt/templates"}
	arguments := effectiveBackgroundArguments(config, cliConfig{DNSResolveMode: "internal", DNSDenyCIDRs: []string{"192.168.0.0/16"}})
	_, parsed, err := parseCLIConfig(arguments)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Templates != "" {
		parsed.Runtime[appRuntime.ConfigNucleiTemplates] = parsed.Templates
	}
	resolved, err := appRuntime.LoadConfig(appRuntime.HomePaths{EnvFile: filepath.Join(t.TempDir(), "missing.env")}, parsed.Runtime, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ListenAddress != config.ListenAddress || resolved.MaxConcurrency != config.MaxConcurrency || resolved.SQLiteBusyTimeout != config.SQLiteBusyTimeout || resolved.NucleiBinary != config.NucleiBinary || resolved.NucleiTemplates != config.NucleiTemplates || strings.Join(resolved.AllowCIDRs, ",") != strings.Join(config.AllowCIDRs, ",") {
		t.Fatalf("background configuration = %#v, want %#v", resolved, config)
	}
}

func TestBackgroundServerPreservesEffectiveConfigurationAndDynamicStatus(t *testing.T) {
	home := t.TempDir()
	binary := filepath.Join(home, "yscan")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = "."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build test binary: %v\n%s", err, output)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	templates := filepath.Join(home, "templates")
	if err := os.MkdirAll(templates, 0750); err != nil {
		t.Fatal(err)
	}
	start := exec.Command(binary,
		"--home", home, "--listen", address, "--max-concurrency", "4",
		"--sqlite-busy-timeout", "7s", "--log-max-bytes", "2048", "--log-max-files", "2",
		"--nuclei-binary", "/bin/false", "--templates", templates, "server", "start")
	start.Dir = home
	if output, err := start.CombinedOutput(); err != nil {
		t.Fatalf("start background Server: %v\n%s", err, output)
	}
	paths, err := appRuntime.ResolveHome(binary, home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop := exec.Command(binary, "--home", home, "server", "stop", "--force")
		stop.Dir = home
		_ = stop.Run()
	})
	inspection := appRuntime.InspectServerHealth(paths)
	if inspection.Status != appRuntime.ServerRunning || inspection.State == nil || inspection.State.ListenAddress != address {
		t.Fatalf("background inspection = %#v", inspection)
	}
	commandLine, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", inspection.State.PID))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.ReplaceAll(strings.TrimRight(string(commandLine), "\x00"), "\x00", " ")
	for _, expected := range []string{"--listen " + address, "--max-concurrency 4", "--sqlite-busy-timeout 7s", "--log-max-bytes 2048", "--log-max-files 2", "--nuclei-binary /bin/false", "--templates " + templates} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("child command line %q does not contain %q", joined, expected)
		}
	}
	status := exec.Command(binary, "--home", home, "server", "status")
	status.Dir = home
	output, err := status.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "Server: running") || !strings.Contains(string(output), "Listen: "+address) {
		t.Fatalf("dynamic status: %v\n%s", err, output)
	}
	stop := exec.Command(binary, "--home", home, "server", "stop")
	stop.Dir = home
	if output, err := stop.CombinedOutput(); err != nil {
		t.Fatalf("stop Server: %v\n%s", err, output)
	}
	status = exec.Command(binary, "--home", home, "server", "status")
	status.Dir = home
	if err := status.Run(); err == nil {
		t.Fatal("stopped Server status returned success")
	}
	listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	envAddress := listener.Addr().String()
	_ = listener.Close()
	envContent := fmt.Sprintf("YSCAN_LISTEN_ADDR=%s\nYSCAN_MAX_CONCURRENCY=3\nYSCAN_SQLITE_BUSY_TIMEOUT=5s\nYSCAN_LOG_MAX_BYTES=4096\nYSCAN_LOG_MAX_FILES=2\nYSCAN_NUCLEI_BINARY=/bin/false\nYSCAN_NUCLEI_TEMPLATES=\nYSCAN_ALLOW_CIDRS=\n", envAddress)
	if err := os.WriteFile(paths.EnvFile, []byte(envContent), 0600); err != nil {
		t.Fatal(err)
	}
	start = exec.Command(binary, "--home", home, "server", "start")
	start.Dir = home
	start.Env = append(os.Environ(), "NUCLEI_TEMPLATES=legacy-templates")
	if output, err := start.CombinedOutput(); err != nil {
		t.Fatalf("start from .env: %v\n%s", err, output)
	}
	inspection = appRuntime.InspectServerHealth(paths)
	if inspection.Status != appRuntime.ServerRunning || inspection.State == nil || inspection.State.ListenAddress != envAddress {
		t.Fatalf(".env background inspection = %#v", inspection)
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
	request, err := http.NewRequest(http.MethodPost, "http://"+envAddress+"/api/scan-tasks", strings.NewReader(`{"target":"127.0.0.1","scan_type":"ip","mode":"scheduled","cron":"0 2 * * *","timezone":"UTC","config":{"port_spec":"1","vulnerability_on":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	createdResponse, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		Task model.ScanTask `json:"task"`
	}
	decodeErr := json.NewDecoder(createdResponse.Body).Decode(&created)
	_ = createdResponse.Body.Close()
	wantLegacyTemplates := filepath.Join(home, "legacy-templates")
	if decodeErr != nil || createdResponse.StatusCode != http.StatusCreated || created.Task.Config.NucleiTemplates != wantLegacyTemplates {
		t.Fatalf("legacy templates were not frozen by real Server: status=%d task=%#v err=%v", createdResponse.StatusCode, created.Task, decodeErr)
	}
	stablePID, stableHealthToken := inspection.State.PID, inspection.State.HealthToken
	for name, arguments := range map[string][]string{
		"invalid address": {"server", "restart", "not-an-address"},
		"invalid CIDR":    {"server", "restart", "--allow-cidr", "not-a-cidr"},
		"unknown option":  {"server", "restart", "--unknown"},
	} {
		t.Run(name, func(t *testing.T) {
			restart := exec.Command(binary, append([]string{"--home", home}, arguments...)...)
			restart.Dir = home
			if output, err := restart.CombinedOutput(); err == nil {
				t.Fatalf("invalid restart succeeded:\n%s", output)
			}
			current := appRuntime.InspectServerHealth(paths)
			if current.Status != appRuntime.ServerRunning || current.State == nil || current.State.PID != stablePID || current.State.HealthToken != stableHealthToken {
				t.Fatalf("invalid restart changed healthy Server: %#v", current)
			}
		})
	}
	if err := os.WriteFile(paths.EnvFile, []byte("YSCAN_UNKNOWN_SETTING=broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	restart := exec.Command(binary, "--home", home, "server", "restart")
	restart.Dir = home
	if output, err := restart.CombinedOutput(); err == nil || !strings.Contains(string(output), "unknown configuration key") {
		t.Fatalf("restart with invalid configuration: %v\n%s", err, output)
	}
	if inspection = appRuntime.InspectServerHealth(paths); inspection.Status != appRuntime.ServerRunning || inspection.State == nil || inspection.State.PID != stablePID || inspection.State.HealthToken != stableHealthToken {
		t.Fatalf("invalid restart stopped the existing Server: %#v", inspection)
	}
	status = exec.Command(binary, "--home", home, "server", "status")
	status.Dir = home
	if output, err := status.CombinedOutput(); err != nil || !strings.Contains(string(output), "Server: running") {
		t.Fatalf("status with invalid .env: %v\n%s", err, output)
	}
	logs := exec.Command(binary, "--home", home, "server", "logs", "--lines", "1", "--no-follow")
	logs.Dir = home
	if output, err := logs.CombinedOutput(); err != nil {
		t.Fatalf("logs with invalid .env: %v\n%s", err, output)
	}
	stop = exec.Command(binary, "--home", home, "server", "stop")
	stop.Dir = home
	if output, err := stop.CombinedOutput(); err != nil {
		t.Fatalf("stop .env Server: %v\n%s", err, output)
	}
	if nonLoopbackIP := testNonLoopbackIPv4(t); nonLoopbackIP != "" {
		listener, err = net.Listen("tcp", net.JoinHostPort(nonLoopbackIP, "0"))
		if err != nil {
			t.Fatalf("reserve non-loopback listener: %v", err)
		}
		nonLoopbackAddress := listener.Addr().String()
		_ = listener.Close()
		if err := os.WriteFile(paths.EnvFile, []byte(""), 0600); err != nil {
			t.Fatal(err)
		}
		start = exec.Command(binary, "--home", home, "--listen", nonLoopbackAddress, "--trusted-cidrs", "192.0.2.0/24", "server", "start")
		start.Dir = home
		if output, err := start.CombinedOutput(); err != nil {
			t.Fatalf("start non-loopback Server: %v\n%s", err, output)
		}
		inspection = appRuntime.InspectServerHealth(paths)
		if inspection.Status != appRuntime.ServerRunning || inspection.State == nil || inspection.State.ListenAddress != nonLoopbackAddress {
			t.Fatalf("non-loopback health inspection = %#v", inspection)
		}
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
		response, err := client.Get("http://" + nonLoopbackAddress + "/api/healthz")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("untrusted non-loopback health response = %d", response.StatusCode)
		}
		stop = exec.Command(binary, "--home", home, "server", "stop")
		stop.Dir = home
		if output, err := stop.CombinedOutput(); err != nil {
			t.Fatalf("stop non-loopback Server: %v\n%s", err, output)
		}
	}
	unit, err := os.ReadFile("deploy/yscan.service")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unit), "127.0.0.1:8080") || strings.Contains(string(unit), "curl") || !strings.Contains(string(unit), "server status") {
		t.Fatalf("systemd health command is not dynamic:\n%s", unit)
	}
}

func TestForegroundServerScansUseRotatingServiceLog(t *testing.T) {
	home := t.TempDir()
	binary := filepath.Join(home, "yscan")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = "."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build foreground Server binary: %v\n%s", err, output)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	command := exec.Command(binary, "--home", home, "--listen", address, "--log-max-bytes", "1024", "--log-max-files", "2", "server")
	command.Dir = home
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	paths, err := appRuntime.ResolveHome(binary, home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop := exec.Command(binary, "--home", home, "server", "stop", "--force")
		stop.Dir = home
		_ = stop.Run()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
		}
	})
	waitForServerStatus(t, paths, appRuntime.ServerRunning, 20*time.Second)

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	for index := 0; index < 20; index++ {
		request, err := http.NewRequest(http.MethodPost, "http://"+address+"/api/scan-tasks", strings.NewReader(`{"target":"127.0.0.1","scan_type":"ip","mode":"once","config":{"port_spec":"1"}}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var created struct {
			Task model.ScanTask    `json:"task"`
			Run  model.ScanTaskRun `json:"run"`
		}
		decodeErr := json.NewDecoder(response.Body).Decode(&created)
		_ = response.Body.Close()
		if decodeErr != nil || response.StatusCode != http.StatusCreated || created.Run.ID == 0 {
			t.Fatalf("create scan %d status=%d response=%#v err=%v", index, response.StatusCode, created, decodeErr)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			runResponse, err := client.Get(fmt.Sprintf("http://%s/api/scan-tasks/%d/runs/%d", address, created.Task.ID, created.Run.ID))
			if err != nil {
				t.Fatal(err)
			}
			var run model.ScanTaskRun
			decodeErr := json.NewDecoder(runResponse.Body).Decode(&run)
			_ = runResponse.Body.Close()
			if decodeErr != nil || runResponse.StatusCode != http.StatusOK {
				t.Fatalf("read scan %d status=%d run=%#v err=%v", index, runResponse.StatusCode, run, decodeErr)
			}
			if run.Status == model.ScanTaskRunStatusSuccess {
				break
			}
			if run.Status == model.ScanTaskRunStatusFailed || run.Status == model.ScanTaskRunStatusCanceled || time.Now().After(deadline) {
				t.Fatalf("scan %d did not complete successfully: %#v", index, run)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	stop := exec.Command(binary, "--home", home, "server", "stop")
	stop.Dir = home
	if output, err := stop.CombinedOutput(); err != nil {
		t.Fatalf("stop foreground Server: %v\n%s", err, output)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("foreground Server exit: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("foreground Server did not exit")
	}
	serviceLog := filepath.Join(paths.LogsDir, "yscan.log")
	for _, path := range []string{serviceLog, serviceLog + ".1", serviceLog + ".2"} {
		content, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(content), "scan task run") {
			t.Fatalf("rotated foreground scan log %s content=%q err=%v", path, content, err)
		}
	}
}

func waitForServerStatus(t *testing.T, paths appRuntime.HomePaths, expected appRuntime.ServerStatus, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if appRuntime.InspectServerHealth(paths).Status == expected {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Server did not reach %s: %#v", expected, appRuntime.InspectServerHealth(paths))
}

func testNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			return ip.String()
		}
	}
	t.Log("no non-loopback IPv4 address is available; process-level health test skipped")
	return ""
}

func TestServerUninstallRejectsDeleteHomeOption(t *testing.T) {
	paths, err := appRuntime.ResolveHome(os.Args[0], t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handled, err := handleServerControlCommand(paths, []string{"uninstall", "--delete-home"})
	if !handled || err == nil || !strings.Contains(err.Error(), "usage: yscan server uninstall") {
		t.Fatalf("delete-home result handled=%t error=%v", handled, err)
	}
}

func TestServerServiceLogRotationAndTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yscan.log")
	writer, err := appRuntime.OpenRotatingLogWriter(path, 1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 5; index++ {
		if _, err := writer.Write([]byte(strings.Repeat("x", 700) + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{path, path + ".1", path + ".2"} {
		if _, err := os.Stat(expected); err != nil {
			t.Fatalf("missing rotated log %s: %v", expected, err)
		}
	}
	if _, err := os.Stat(path + ".3"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unbounded rotated log remains: %v", err)
	}
	for _, bounded := range []string{path, path + ".1", path + ".2"} {
		info, err := os.Stat(bounded)
		if err != nil || info.Size() > 1024 {
			t.Fatalf("rotated log %s size=%d err=%v", bounded, info.Size(), err)
		}
	}
	if err := os.WriteFile(path, []byte("one\ntwo\nthree\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := appRuntime.PrintServerLogs(context.Background(), &output, path, 2, false); err != nil {
		t.Fatal(err)
	}
	if output.String() != "two\nthree\n" {
		t.Fatalf("tail = %q", output.String())
	}
}

func TestCapturedStandardOutputUsesRotatingServiceLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yscan.log")
	writer, err := appRuntime.OpenRotatingLogWriter(path, 1024, 2)
	if err != nil {
		t.Fatal(err)
	}
	restore, err := appRuntime.CaptureProcessOutput(writer)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 8; index++ {
		_, _ = fmt.Fprintln(os.Stdout, strings.Repeat("stdout", 120))
		_, _ = fmt.Fprintln(os.Stderr, strings.Repeat("stderr", 120))
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{path, path + ".1", path + ".2"} {
		if info, err := os.Stat(expected); err != nil || info.Size() == 0 || info.Size() > 1024 {
			t.Fatalf("captured rotated log %s info=%v err=%v", expected, info, err)
		}
	}
}

func TestServerLogFollowDrainsRotatedInodeBeforeSwitching(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yscan.log")
	if err := os.WriteFile(path, []byte("initial\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output strings.Builder
	result := make(chan error, 1)
	go func() { result <- appRuntime.PrintServerLogs(ctx, &output, path, 0, true) }()
	time.Sleep(300 * time.Millisecond)
	old, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.WriteString("old-inode-tail\n"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new-inode-head\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(750 * time.Millisecond)
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "old-inode-tail") || !strings.Contains(output.String(), "new-inode-head") {
		t.Fatalf("follow output lost rotated content: %q", output.String())
	}
}

func TestRunAPIAndSchedulerStopsAPIWhenSchedulerFails(t *testing.T) {
	apiStarted := make(chan struct{})
	apiStopped := make(chan struct{})
	schedulerFailure := errors.New("scheduler database failure")

	err := runAPIAndScheduler(context.Background(), func(ctx context.Context) error {
		close(apiStarted)
		<-ctx.Done()
		close(apiStopped)
		return nil
	}, func(context.Context) error {
		<-apiStarted
		return schedulerFailure
	})
	if err == nil || !strings.Contains(err.Error(), "schedule runner stopped") || !errors.Is(err, schedulerFailure) {
		t.Fatalf("service error = %v", err)
	}
	select {
	case <-apiStopped:
	default:
		t.Fatal("API component was not stopped after scheduler failure")
	}
}

func TestRecoveryCompletesBeforeAPIAndSchedulerStart(t *testing.T) {
	recoveryStarted := make(chan struct{})
	releaseRecovery := make(chan struct{})
	apiStarted := make(chan struct{})
	schedulerFailure := errors.New("stop after startup ordering check")

	result := make(chan error, 1)
	go func() {
		result <- recoverThenRunAPIAndScheduler(context.Background(), func() error {
			close(recoveryStarted)
			<-releaseRecovery
			return nil
		}, func(ctx context.Context) error {
			close(apiStarted)
			<-ctx.Done()
			return nil
		}, func(context.Context) error {
			<-apiStarted
			return schedulerFailure
		})
	}()

	<-recoveryStarted
	select {
	case <-apiStarted:
		t.Fatal("API started before startup recovery completed")
	default:
	}
	close(releaseRecovery)
	if err := <-result; err == nil || !errors.Is(err, schedulerFailure) {
		t.Fatalf("service result = %v", err)
	}
}

func TestServerShutdownDrainsAPIRequestsBeforeSchedulerStops(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	requestEntered := make(chan struct{})
	releaseRequest := make(chan struct{})
	schedulerStopped := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- runAPIAndSchedulerWithDrain(parent, func(ctx context.Context, drained func() error) error {
			close(requestEntered)
			<-ctx.Done()
			<-releaseRequest
			return drained()
		}, func(ctx context.Context) error {
			<-ctx.Done()
			close(schedulerStopped)
			return nil
		})
	}()
	<-requestEntered
	cancel()
	select {
	case <-schedulerStopped:
		t.Fatal("scheduler stopped before the entered API request drained")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseRequest)
	select {
	case <-schedulerStopped:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after API requests drained")
	}
	if err := <-result; err != nil {
		t.Fatalf("graceful service shutdown: %v", err)
	}
}

func TestServerRunRegistryCancelsOnlyOwnedQueuedRuns(t *testing.T) {
	db := openLogicalScanTaskRunTestDB(t)
	task, err := storage.CreateScanTask(db, model.ScanTask{Target: "127.0.0.1", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeScheduled, Cron: "0 0 * * *", Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	owned, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-08-12T10:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	unowned, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-08-12T10:01:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	running, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-08-12T10:02:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ?, stage = ? WHERE id = ?`, model.ScanTaskRunStatusRunning, model.ScanTaskRunStageStarting, running.ID); err != nil {
		t.Fatal(err)
	}
	registry := serverRunRegistry{}
	registry.track(owned.ID)
	registry.track(running.ID)
	if err := registry.cancelQueued(db); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		id     int64
		status string
	}{{owned.ID, model.ScanTaskRunStatusCanceled}, {unowned.ID, model.ScanTaskRunStatusQueued}, {running.ID, model.ScanTaskRunStatusRunning}} {
		run, err := storage.GetScanTaskRun(db, check.id)
		if err != nil || run.Status != check.status {
			t.Fatalf("run %d status=%q error=%v, want %q", check.id, run.Status, err, check.status)
		}
	}
}

func TestRecoveredServicePreservesRunCreatedAfterAPIStarts(t *testing.T) {
	db := openLogicalScanTaskRunTestDB(t)
	oldTask, err := storage.CreateScanTask(db, model.ScanTask{
		Target: "192.168.10.20", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce,
	})
	if err != nil {
		t.Fatalf("create prior task: %v", err)
	}
	oldRun, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{
		ScanTaskID: oldTask.ID, ScheduledFor: "2026-08-10T01:00:00Z", Status: model.ScanTaskRunStatusRunning,
	})
	if err != nil {
		t.Fatalf("create prior running run: %v", err)
	}

	runner := schedule.NewRunner(db, nil)
	serviceContext, stopService := context.WithCancel(context.Background())
	defer stopService()
	type creationResult struct {
		run model.ScanTaskRun
		err error
	}
	created := make(chan creationResult, 1)
	serviceResult := make(chan error, 1)
	go func() {
		serviceResult <- recoverThenRunAPIAndScheduler(serviceContext, runner.RecoverStartupState, func(ctx context.Context) error {
			prior, err := storage.GetScanTaskRun(db, oldRun.ID)
			if err != nil {
				created <- creationResult{err: err}
				return err
			}
			if prior.Status != model.ScanTaskRunStatusFailed || prior.ErrorMessage != "interrupted by service restart" {
				err := fmt.Errorf("prior run was not recovered before API start: %#v", prior)
				created <- creationResult{err: err}
				return err
			}
			newTask, err := storage.CreateScanTask(db, model.ScanTask{
				Target: "192.168.10.21", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce,
			})
			if err != nil {
				created <- creationResult{err: err}
				return err
			}
			newRun, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{
				ScanTaskID: newTask.ID, ScheduledFor: "2026-08-10T01:01:00Z", Status: model.ScanTaskRunStatusRunning,
			})
			created <- creationResult{run: newRun, err: err}
			if err != nil {
				return err
			}
			<-ctx.Done()
			return nil
		}, runner.RunLoop)
	}()

	creation := <-created
	if creation.err != nil {
		t.Fatalf("API creation after recovery: %v", creation.err)
	}
	stopService()
	if err := <-serviceResult; err != nil {
		t.Fatalf("service shutdown: %v", err)
	}
	persisted, err := storage.GetScanTaskRun(db, creation.run.ID)
	if err != nil {
		t.Fatalf("get current-process run: %v", err)
	}
	if persisted.Status != model.ScanTaskRunStatusRunning || persisted.ErrorMessage != "" {
		t.Fatalf("current-process run was treated as restart residue: %#v", persisted)
	}
}

func TestRunAPIAndSchedulerTreatsParentCancellationAsCleanShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 2)
	result := make(chan error, 1)
	run := func(ctx context.Context) error {
		started <- struct{}{}
		<-ctx.Done()
		return nil
	}
	go func() { result <- runAPIAndScheduler(ctx, run, run) }()
	<-started
	<-started
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("clean shutdown returned error: %v", err)
	}
}

func TestCommandNeedsLegacyBannerMatcher(t *testing.T) {
	for _, command := range []string{"scan", "subnet", "status", "list", "cancel", "findings", "schedule", "fingerprint", "api", "legacy-list", "legacy-status", "legacy-findings"} {
		if commandNeedsLegacyBannerMatcher([]string{command}) {
			t.Fatalf("management command %s must not load a matcher engine", command)
		}
	}
	if commandNeedsLegacyBannerMatcher(nil) {
		t.Fatal("help mode must not load a matcher engine")
	}
}

func TestLogicalScanTaskRunExecutorRoutesIPRuns(t *testing.T) {
	originalTargetRun := runTargetTaskRun
	t.Cleanup(func() { runTargetTaskRun = originalTargetRun })
	runTargetTaskRun = func(_ context.Context, options workflow.TargetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
		if options.Run.ID != 42 || options.Network != "tcp" {
			t.Fatalf("target run options = %#v", options)
		}
		return model.ScanTaskRunSnapshot{RunID: options.Run.ID}, nil
	}

	snapshot, err := (logicalScanTaskRunExecutor{baseTask: model.Scanner{Network: "tcp"}}).Execute(context.Background(), model.ScanTaskRun{
		ID:       42,
		ScanType: model.ScanTypeIP,
	})
	if err != nil || snapshot.RunID != 42 {
		t.Fatalf("logical IP executor result = %#v, error = %v", snapshot, err)
	}
}

func TestQuickScanCreatesOnlyV2TaskRunAndSnapshot(t *testing.T) {
	db, err := storage.InitDBAt(filepath.Join(t.TempDir(), "quick-v2.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	originalTargetRun, originalReport := runTargetTaskRun, generateScanTaskRunReport
	t.Cleanup(func() { runTargetTaskRun, generateScanTaskRunReport = originalTargetRun, originalReport })
	runTargetTaskRun = func(_ context.Context, options workflow.TargetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
		if options.Run.Target != "127.0.0.1" || options.Run.Config.PortSpec != "80,443" {
			t.Fatalf("quick run options=%#v", options.Run)
		}
		return model.ScanTaskRunSnapshot{Hosts: []model.ScanTaskRunHost{{IP: "127.0.0.1", IsActive: true}}, Ports: []model.ScanTaskRunPort{{IP: "127.0.0.1", Port: 80, ServiceType: "http"}}}, nil
	}
	generateScanTaskRunReport = func(*sql.DB, int64, int64, string) (string, error) { return "reports/quick-v2.md", nil }
	if err := runQuickV2Scan(context.Background(), db, model.Scanner{Network: "tcp"}, "127.0.0.1", model.ScanTypeIP, false, "80,443"); err != nil {
		t.Fatalf("quick V2 scan: %v", err)
	}
	tasks, err := storage.ListScanTasks(db)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("V2 tasks=%#v err=%v", tasks, err)
	}
	runs, err := storage.ListScanTaskRuns(db, tasks[0].ID)
	if err != nil || len(runs) != 1 || runs[0].Status != model.ScanTaskRunStatusSuccess || runs[0].Progress != 100 {
		t.Fatalf("V2 runs=%#v err=%v", runs, err)
	}
	snapshot, err := storage.GetScanTaskRunSnapshot(db, runs[0].ID)
	if err != nil || len(snapshot.Ports) != 1 || snapshot.Ports[0].Port != 80 {
		t.Fatalf("V2 snapshot=%#v err=%v", snapshot, err)
	}
	legacyTasks, err := storage.ListTasks(db)
	if err != nil || len(legacyTasks) != 0 {
		t.Fatalf("legacy tasks=%#v err=%v", legacyTasks, err)
	}
}

func TestSuccessfulScanTaskRunIsNotPublishedBeforeReportFinishes(t *testing.T) {
	db, err := storage.InitDBAt(filepath.Join(t.TempDir(), "report-finalization.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service := schedule.NewTaskService(db, nil)
	task, run, err := service.Create(context.Background(), model.ScanTask{
		Target: "127.0.0.1", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce,
		Config: model.ScanTaskConfig{PortSpec: "80"},
	})
	if err != nil || run == nil {
		t.Fatalf("create task=%#v run=%#v err=%v", task, run, err)
	}
	originalTargetRun, originalReport := runTargetTaskRun, generateScanTaskRunReport
	t.Cleanup(func() { runTargetTaskRun, generateScanTaskRunReport = originalTargetRun, originalReport })
	runTargetTaskRun = func(context.Context, workflow.TargetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
		return model.ScanTaskRunSnapshot{Hosts: []model.ScanTaskRunHost{{IP: "127.0.0.1", IsActive: true}}}, nil
	}
	reportStarted := make(chan model.ScanTaskRun, 1)
	releaseReport := make(chan struct{})
	generateScanTaskRunReport = func(db *sql.DB, _, runID int64, _ string) (string, error) {
		observed, lookupErr := storage.GetScanTaskRun(db, runID)
		if lookupErr != nil {
			return "", lookupErr
		}
		reportStarted <- observed
		<-releaseReport
		return "reports/ready.md", nil
	}
	done := make(chan error, 1)
	go func() {
		done <- executeLogicalScanTaskRun(context.Background(), db, model.Scanner{Network: "tcp"}, *run)
	}()

	observed := <-reportStarted
	if observed.Status != model.ScanTaskRunStatusRunning || observed.Stage != model.ScanTaskRunStageReporting || observed.Progress != 99 || observed.FinishedAt != "" {
		t.Fatalf("run exposed before report completion: %#v", observed)
	}
	persisted, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || persisted.Status != model.ScanTaskRunStatusRunning || persisted.Stage != model.ScanTaskRunStageReporting || persisted.Progress != 99 {
		t.Fatalf("persisted reporting run=%#v err=%v", persisted, err)
	}
	close(releaseReport)
	if err := <-done; err != nil {
		t.Fatalf("finish run: %v", err)
	}
	completed, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || completed.Status != model.ScanTaskRunStatusSuccess || completed.Stage != model.ScanTaskRunStageCompleted || completed.Progress != 100 || completed.FinishedAt == "" || completed.ReportError != "" {
		t.Fatalf("completed run=%#v err=%v", completed, err)
	}
}

func TestSuccessfulScanTaskRunKeepsReportFailureDiagnosticAtFinalization(t *testing.T) {
	db, err := storage.InitDBAt(filepath.Join(t.TempDir(), "report-error-finalization.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service := schedule.NewTaskService(db, nil)
	_, run, err := service.Create(context.Background(), model.ScanTask{Target: "127.0.0.1", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce, Config: model.ScanTaskConfig{PortSpec: "80"}})
	if err != nil || run == nil {
		t.Fatalf("create run=%#v err=%v", run, err)
	}
	originalTargetRun, originalReport := runTargetTaskRun, generateScanTaskRunReport
	t.Cleanup(func() { runTargetTaskRun, generateScanTaskRunReport = originalTargetRun, originalReport })
	runTargetTaskRun = func(context.Context, workflow.TargetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
		return model.ScanTaskRunSnapshot{}, nil
	}
	generateScanTaskRunReport = func(*sql.DB, int64, int64, string) (string, error) {
		return "", errors.New("report directory is read-only")
	}
	if err := executeLogicalScanTaskRun(context.Background(), db, model.Scanner{Network: "tcp"}, *run); err != nil {
		t.Fatal(err)
	}
	completed, err := storage.GetScanTaskRun(db, run.ID)
	if err != nil || completed.Status != model.ScanTaskRunStatusSuccess || completed.Stage != model.ScanTaskRunStageCompleted || completed.Progress != 100 || completed.ReportError != "report directory is read-only" {
		t.Fatalf("completed run=%#v err=%v", completed, err)
	}
}

func TestFailedAndCanceledScanTaskRunsKeepTerminalStageWhileReportGenerates(t *testing.T) {
	tests := []struct {
		name       string
		cancelRun  bool
		wantStatus string
		wantStage  string
	}{
		{name: "failed", wantStatus: model.ScanTaskRunStatusFailed, wantStage: model.ScanTaskRunStageFailed},
		{name: "canceled", cancelRun: true, wantStatus: model.ScanTaskRunStatusCanceled, wantStage: model.ScanTaskRunStageCanceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := storage.InitDBAt(filepath.Join(t.TempDir(), "terminal-report.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			service := schedule.NewTaskService(db, nil)
			task, run, err := service.Create(context.Background(), model.ScanTask{
				Target: "127.0.0.1", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeOnce,
				Config: model.ScanTaskConfig{PortSpec: "80"},
			})
			if err != nil || run == nil {
				t.Fatalf("create task=%#v run=%#v err=%v", task, run, err)
			}
			if tt.cancelRun {
				if err := storage.CancelScanTaskRun(db, task.ID, run.ID); err != nil {
					t.Fatal(err)
				}
			}

			originalTargetRun, originalReport := runTargetTaskRun, generateScanTaskRunReport
			t.Cleanup(func() { runTargetTaskRun, generateScanTaskRunReport = originalTargetRun, originalReport })
			runTargetTaskRun = func(context.Context, workflow.TargetTaskRunOptions) (model.ScanTaskRunSnapshot, error) {
				return model.ScanTaskRunSnapshot{}, errors.New("scan failed")
			}
			reportStarted := make(chan model.ScanTaskRun, 1)
			releaseReport := make(chan struct{})
			generateScanTaskRunReport = func(db *sql.DB, _, runID int64, _ string) (string, error) {
				observed, lookupErr := storage.GetScanTaskRun(db, runID)
				if lookupErr != nil {
					return "", lookupErr
				}
				reportStarted <- observed
				<-releaseReport
				return "reports/terminal.md", nil
			}
			done := make(chan error, 1)
			go func() {
				done <- executeLogicalScanTaskRun(context.Background(), db, model.Scanner{Network: "tcp"}, *run)
			}()

			observed := <-reportStarted
			if observed.Status != tt.wantStatus || observed.Stage != tt.wantStage || observed.Progress == 99 {
				t.Fatalf("run changed while report was pending: %#v", observed)
			}
			close(releaseReport)
			if err := <-done; err != nil {
				t.Fatalf("finish terminal report: %v", err)
			}
			completed, err := storage.GetScanTaskRun(db, run.ID)
			if err != nil || completed.Status != tt.wantStatus || completed.Stage != tt.wantStage || completed.Progress == 99 {
				t.Fatalf("terminal run=%#v err=%v", completed, err)
			}
		})
	}
}

func TestProcessTaskExecutionGeneratesReportFromFinalSnapshot(t *testing.T) {
	db := openTaskExecutionTestDB(t)
	taskID, err := storage.CreateTask(db, model.TaskTypeScanIP, "192.168.1.10")
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	restoreTaskExecutionDependencies(t)
	executeTaskForTaskExecution = func(context.Context, *sql.DB, int64, model.Scanner, string, string) error {
		return nil
	}
	var reportTask model.Task
	generateTaskReport = func(db *sql.DB, taskID int64, _ string) (string, error) {
		var err error
		reportTask, err = storage.GetTaskByID(db, taskID)
		return "reports/task-1.md", err
	}

	processTaskExecution(db, taskID, model.Scanner{}, model.TaskTypeScanIP, "192.168.1.10")
	if reportTask.Status != model.TaskStatusSuccess || reportTask.FinishedAt == "" {
		t.Fatalf("report read non-final task snapshot: %#v", reportTask)
	}

	task, err := storage.GetTaskByID(db, taskID)
	if err != nil {
		t.Fatalf("get completed task: %v", err)
	}
	if task.Status != model.TaskStatusSuccess || task.FinishedAt == "" || task.ReportError != "" {
		t.Fatalf("completed task = %#v", task)
	}
}

func TestProcessTaskExecutionKeepsSuccessWhenReportFails(t *testing.T) {
	db := openTaskExecutionTestDB(t)
	taskID, err := storage.CreateTask(db, model.TaskTypeScanIP, "192.168.1.10")
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	restoreTaskExecutionDependencies(t)
	executeTaskForTaskExecution = func(context.Context, *sql.DB, int64, model.Scanner, string, string) error {
		return nil
	}
	generateTaskReport = func(*sql.DB, int64, string) (string, error) {
		return "", errors.New("report directory is read-only")
	}

	processTaskExecution(db, taskID, model.Scanner{}, model.TaskTypeScanIP, "192.168.1.10")
	task, err := storage.GetTaskByID(db, taskID)
	if err != nil {
		t.Fatalf("get task after report failure: %v", err)
	}
	if task.Status != model.TaskStatusSuccess || task.FinishedAt == "" {
		t.Fatalf("report failure changed scan terminal state: %#v", task)
	}
	if task.ReportError != "report directory is read-only" {
		t.Fatalf("report error = %q", task.ReportError)
	}
}

func TestProcessTaskExecutionReportsFailureAndCancellationSnapshots(t *testing.T) {
	tests := []struct {
		name       string
		cancelTask bool
		wantStatus string
	}{
		{name: "failure", wantStatus: model.TaskStatusFailed},
		{name: "cancellation", cancelTask: true, wantStatus: model.TaskStatusCanceled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openTaskExecutionTestDB(t)
			taskID, err := storage.CreateTask(db, model.TaskTypeScanIP, "192.168.1.10")
			if err != nil {
				t.Fatalf("create task: %v", err)
			}
			if tt.cancelTask {
				if err := storage.CancelTask(db, taskID); err != nil {
					t.Fatalf("request cancellation: %v", err)
				}
			}

			restoreTaskExecutionDependencies(t)
			executeTaskForTaskExecution = func(context.Context, *sql.DB, int64, model.Scanner, string, string) error {
				return errors.New("scan execution failed")
			}
			var reportTask model.Task
			generateTaskReport = func(db *sql.DB, taskID int64, _ string) (string, error) {
				var err error
				reportTask, err = storage.GetTaskByID(db, taskID)
				return "reports/task-1.md", err
			}

			processTaskExecution(db, taskID, model.Scanner{}, model.TaskTypeScanIP, "192.168.1.10")
			if reportTask.Status != tt.wantStatus || reportTask.FinishedAt == "" {
				t.Fatalf("report task = %#v, want status %q with finished time", reportTask, tt.wantStatus)
			}
		})
	}
}

func TestLogicalScanTaskRunDoesNotReportWhileQueuedForGlobalSlot(t *testing.T) {
	db := openLogicalScanTaskRunTestDB(t)
	firstTask, err := storage.CreateScanTask(db, model.ScanTask{
		Target:   "192.168.80.10",
		ScanType: model.ScanTypeIP,
		Mode:     model.ScanTaskModeOnce,
	})
	if err != nil {
		t.Fatalf("create first task: %v", err)
	}
	queued, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: firstTask.ID, ScheduledFor: "2026-07-28T00:00:00Z"})
	if err != nil {
		t.Fatalf("create queued run: %v", err)
	}
	secondTask, err := storage.CreateScanTask(db, model.ScanTask{
		Target:   "192.168.80.11",
		ScanType: model.ScanTypeIP,
		Mode:     model.ScanTaskModeOnce,
	})
	if err != nil {
		t.Fatalf("create second task: %v", err)
	}
	active, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: secondTask.ID, ScheduledFor: "2026-07-28T00:01:00Z"})
	if err != nil {
		t.Fatalf("create active run: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ?, started_at = datetime('now') WHERE id = ?`, model.ScanTaskRunStatusRunning, active.ID); err != nil {
		t.Fatalf("mark active run: %v", err)
	}

	originalGenerate := generateScanTaskRunReport
	t.Cleanup(func() { generateScanTaskRunReport = originalGenerate })
	reportCalls := 0
	generateScanTaskRunReport = func(*sql.DB, int64, int64, string) (string, error) {
		reportCalls++
		return "", nil
	}

	err = executeLogicalScanTaskRun(context.Background(), db, model.Scanner{}, queued)
	if !errors.Is(err, schedule.ErrGlobalConcurrencyUnavailable) {
		t.Fatalf("execute queued run error=%v", err)
	}
	persisted, err := storage.GetScanTaskRun(db, queued.ID)
	if err != nil {
		t.Fatalf("get queued run: %v", err)
	}
	if persisted.Status != model.ScanTaskRunStatusQueued || persisted.ReportPath != "" || persisted.ReportError != "" || reportCalls != 0 {
		t.Fatalf("queued run=%#v reportCalls=%d", persisted, reportCalls)
	}
}

func TestRecoveredInterruptedRunGeneratesTerminalReport(t *testing.T) {
	db := openLogicalScanTaskRunTestDB(t)
	task, err := storage.CreateScanTask(db, model.ScanTask{Target: "192.168.80.20", ScanType: model.ScanTypeIP, Mode: model.ScanTaskModeScheduled, Cron: "0 2 * * *", Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := storage.CreateScanTaskRun(db, model.ScanTaskRun{ScanTaskID: task.ID, ScheduledFor: "2026-08-09T02:00:00Z", Trigger: model.ScanTaskRunTriggerScheduled})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE scan_task_runs SET status = ?, stage = ?, started_at = datetime('now') WHERE id = ?`, model.ScanTaskRunStatusRunning, model.ScanTaskRunStageDiscovery, run.ID); err != nil {
		t.Fatal(err)
	}
	recovered, err := storage.FinalizeInterruptedScanTaskRunsWithResult(db)
	if err != nil || len(recovered) != 1 || recovered[0].Status != model.ScanTaskRunStatusFailed {
		t.Fatalf("recovered=%#v err=%v", recovered, err)
	}
	originalReport := generateScanTaskRunReport
	t.Cleanup(func() { generateScanTaskRunReport = originalReport })
	reportCalls := 0
	generateScanTaskRunReport = func(_ *sql.DB, taskID, runID int64, _ string) (string, error) {
		reportCalls++
		if taskID != task.ID || runID != run.ID {
			t.Fatalf("report target=%d/%d", taskID, runID)
		}
		return "reports/recovered.md", nil
	}
	if err := generateRecoveredScanTaskRunReport(db, recovered[0]); err != nil || reportCalls != 1 {
		t.Fatalf("generate recovered report calls=%d err=%v", reportCalls, err)
	}
}

func restoreTaskExecutionDependencies(t *testing.T) {
	t.Helper()
	originalExecute := executeTaskForTaskExecution
	originalGenerate := generateTaskReport
	t.Cleanup(func() {
		executeTaskForTaskExecution = originalExecute
		generateTaskReport = originalGenerate
	})
}

func openTaskExecutionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Exec(`
		CREATE TABLE tasks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			task_type TEXT NOT NULL,
			target TEXT NOT NULL,
			status TEXT NOT NULL,
			progress INTEGER NOT NULL DEFAULT 0,
			error_msg TEXT,
			report_error TEXT,
			started_at DATETIME,
			finished_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT (datetime('now')),
			updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
		)`); err != nil {
		t.Fatalf("create task schema: %v", err)
	}
	return db
}

func openLogicalScanTaskRunTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		`CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, scan_type TEXT NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL, cron TEXT, timezone TEXT, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL DEFAULT (datetime('now')), updated_at DATETIME NOT NULL DEFAULT (datetime('now')), archived_at DATETIME)`,
		`CREATE TABLE scan_task_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_task_id INTEGER NOT NULL, sequence INTEGER NOT NULL, scheduled_for DATETIME NOT NULL, status TEXT NOT NULL, trigger TEXT NOT NULL DEFAULT 'scheduled', stage TEXT NOT NULL DEFAULT 'queued', progress INTEGER NOT NULL DEFAULT 0, target TEXT NOT NULL, scan_type TEXT NOT NULL, config_json TEXT NOT NULL DEFAULT '{}', config_hash TEXT NOT NULL DEFAULT '', error_message TEXT, report_path TEXT, audit_report_path TEXT, report_error TEXT, started_at DATETIME, finished_at DATETIME, snapshot_written_at DATETIME, created_at DATETIME NOT NULL DEFAULT (datetime('now')), updated_at DATETIME NOT NULL DEFAULT (datetime('now')), UNIQUE(scan_task_id, sequence), UNIQUE(scan_task_id, scheduled_for))`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("create scan task run test schema: %v", err)
		}
	}
	return db
}
