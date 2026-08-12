package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	backgroundReadyFDEnvironment = "YSCAN_BACKGROUND_READY_FD"
	defaultStopTimeout           = 30 * time.Second
)

type backgroundReadyMessage struct {
	Ready bool   `json:"ready"`
	Error string `json:"error,omitempty"`
}

type RotatingLogWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	maxFiles int
	file     *os.File
	size     int64
}

func OpenRotatingLogWriter(path string, maxBytes int64, maxFiles int) (*RotatingLogWriter, error) {
	if maxBytes < 1024 || maxFiles < 1 {
		return nil, errors.New("invalid service log rotation limits")
	}
	writer := &RotatingLogWriter{path: path, maxBytes: maxBytes, maxFiles: maxFiles}
	if err := writer.open(); err != nil {
		return nil, err
	}
	return writer, nil
}

func (writer *RotatingLogWriter) Write(content []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.file == nil {
		return 0, errors.New("service log is closed")
	}
	total := 0
	for len(content) > 0 {
		if writer.size >= writer.maxBytes {
			if err := writer.rotate(); err != nil {
				return total, err
			}
		}
		remaining := writer.maxBytes - writer.size
		chunkSize := int64(len(content))
		if chunkSize > remaining {
			chunkSize = remaining
		}
		written, err := writer.file.Write(content[:int(chunkSize)])
		writer.size += int64(written)
		total += written
		content = content[written:]
		if err != nil {
			return total, err
		}
		if written == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (writer *RotatingLogWriter) Close() error {
	if writer == nil {
		return nil
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.file == nil {
		return nil
	}
	err := writer.file.Close()
	writer.file = nil
	return err
}

func (writer *RotatingLogWriter) open() error {
	if err := os.MkdirAll(filepath.Dir(writer.path), 0750); err != nil {
		return err
	}
	file, err := os.OpenFile(writer.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	writer.file = file
	writer.size = info.Size()
	return nil
}

func (writer *RotatingLogWriter) rotate() error {
	if err := writer.file.Close(); err != nil {
		return err
	}
	writer.file = nil
	oldest := fmt.Sprintf("%s.%d", writer.path, writer.maxFiles)
	_ = os.Remove(oldest)
	for index := writer.maxFiles - 1; index >= 1; index-- {
		from := fmt.Sprintf("%s.%d", writer.path, index)
		to := fmt.Sprintf("%s.%d", writer.path, index+1)
		if err := os.Rename(from, to); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(writer.path, writer.path+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writer.open()
}

func StartBackgroundServer(paths HomePaths, serverArguments []string, timeout time.Duration) error {
	if inspection := InspectServer(paths); inspection.Status != ServerStopped {
		return fmt.Errorf("yscan Server is %s", inspection.Status)
	}
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	defer reader.Close()
	logFile, err := os.OpenFile(filepath.Join(paths.LogsDir, "yscan.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		_ = writer.Close()
		return err
	}
	defer logFile.Close()
	nullInput, err := os.Open(os.DevNull)
	if err != nil {
		_ = writer.Close()
		return err
	}
	defer nullInput.Close()

	arguments := []string{"--home", paths.Home, "server", "--background-child"}
	arguments = append(arguments, serverArguments...)
	command := exec.Command(paths.Executable, arguments...)
	command.Stdin = nullInput
	command.Stdout = logFile
	command.Stderr = logFile
	command.ExtraFiles = []*os.File{writer}
	command.Env = append(os.Environ(), backgroundReadyFDEnvironment+"=3")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		_ = writer.Close()
		return err
	}
	_ = writer.Close()

	result := make(chan error, 1)
	go func() {
		var message backgroundReadyMessage
		err := json.NewDecoder(reader).Decode(&message)
		if err != nil {
			result <- fmt.Errorf("read background Server readiness: %w", err)
			return
		}
		if !message.Ready {
			result <- errors.New(message.Error)
			return
		}
		result <- nil
	}()
	processExit := make(chan error, 1)
	go func() { processExit <- command.Wait() }()
	select {
	case err := <-result:
		return err
	case err := <-processExit:
		if err == nil {
			return errors.New("background Server exited before readiness")
		}
		return fmt.Errorf("background Server failed before readiness: %w", err)
	case <-time.After(timeout):
		_ = command.Process.Signal(syscall.SIGTERM)
		return errors.New("background Server readiness timed out")
	}
}

func NotifyBackgroundReady(err error) {
	rawFD := strings.TrimSpace(os.Getenv(backgroundReadyFDEnvironment))
	if rawFD == "" {
		return
	}
	fd, parseErr := strconv.Atoi(rawFD)
	if parseErr != nil || fd < 3 {
		return
	}
	file := os.NewFile(uintptr(fd), "background-ready")
	if file == nil {
		return
	}
	defer file.Close()
	message := backgroundReadyMessage{Ready: err == nil}
	if err != nil {
		message.Error = err.Error()
	}
	_ = json.NewEncoder(file).Encode(message)
	_ = os.Unsetenv(backgroundReadyFDEnvironment)
}

func StopServer(paths HomePaths, timeout time.Duration, force bool) error {
	inspection := InspectServer(paths)
	if inspection.Status == ServerStopped {
		return nil
	}
	if inspection.State == nil || inspection.State.PID <= 1 {
		return fmt.Errorf("cannot stop Server in %s state: %s", inspection.Status, inspection.Error)
	}
	confirmed := InspectServer(paths)
	if confirmed.State == nil || confirmed.State.InstanceID != inspection.State.InstanceID || confirmed.State.PID != inspection.State.PID {
		return errors.New("Server identity changed while preparing to stop; retry the command")
	}
	if err := verifyControlledServerProcess(paths, inspection.State.PID); err != nil {
		return err
	}
	process, err := os.FindProcess(inspection.State.PID)
	if err != nil {
		return err
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("signal Server process %d: %w", inspection.State.PID, err)
	}
	if timeout <= 0 {
		timeout = defaultStopTimeout
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if InspectServer(paths).Status == ServerStopped {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !force {
		return errors.New("Server did not stop within the graceful timeout; use --force to terminate it")
	}
	if err := process.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("force Server stop: %w", err)
	}
	return nil
}

func InspectServerHealth(paths HomePaths) ServerInspection {
	inspection := InspectServer(paths)
	if inspection.Status != ServerRunning || inspection.State == nil {
		return inspection
	}
	host, port, err := net.SplitHostPort(inspection.State.ListenAddress)
	if err != nil {
		inspection.Status = ServerDegraded
		inspection.Error = err.Error()
		return inspection
	}
	if host == "" || net.ParseIP(host).IsUnspecified() {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + net.JoinHostPort(host, port) + "/api/healthz")
	if err != nil {
		inspection.Status = ServerDegraded
		inspection.Error = err.Error()
		return inspection
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		inspection.Status = ServerDegraded
		inspection.Error = response.Status
	}
	return inspection
}

func verifyControlledServerProcess(paths HomePaths, pid int) error {
	commandLine, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return fmt.Errorf("verify Server process %d: %w", pid, err)
	}
	arguments := strings.Split(strings.TrimRight(string(commandLine), "\x00"), "\x00")
	if len(arguments) == 0 {
		return fmt.Errorf("Server process %d has no command line", pid)
	}
	executableInfo, err := os.Stat(paths.Executable)
	if err != nil {
		return fmt.Errorf("inspect yscan executable: %w", err)
	}
	processExecutableInfo, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return fmt.Errorf("inspect Server executable: %w", err)
	}
	if !os.SameFile(executableInfo, processExecutableInfo) {
		return fmt.Errorf("refusing to signal PID %d because it is not this yscan executable", pid)
	}
	serverArgument := false
	for _, argument := range arguments[1:] {
		if argument == "server" {
			serverArgument = true
			break
		}
	}
	if !serverArgument {
		return fmt.Errorf("refusing to signal PID %d because it is not a yscan Server command", pid)
	}
	return nil
}

func PrintServerLogs(ctx context.Context, output io.Writer, path string, lines int, follow bool) error {
	if lines < 0 {
		return errors.New("log line count cannot be negative")
	}
	position, err := writeLastLines(output, path, lines)
	if err != nil {
		return err
	}
	if !follow {
		return nil
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			info, err := os.Stat(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			if info.Size() < position {
				position = 0
			}
			if info.Size() == position {
				continue
			}
			file, err := os.Open(path)
			if err != nil {
				continue
			}
			_, _ = file.Seek(position, io.SeekStart)
			written, copyErr := io.Copy(output, file)
			_ = file.Close()
			if copyErr != nil {
				return copyErr
			}
			position += written
		}
	}
}

func writeLastLines(output io.Writer, path string, lines int) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if lines == 0 {
		return info.Size(), nil
	}
	scanner := bufio.NewScanner(file)
	buffer := make([]string, lines)
	count := 0
	for scanner.Scan() {
		buffer[count%lines] = scanner.Text()
		count++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	start := 0
	if count > lines {
		start = count % lines
	} else {
		lines = count
	}
	for index := 0; index < lines; index++ {
		if _, err := fmt.Fprintln(output, buffer[(start+index)%len(buffer)]); err != nil {
			return 0, err
		}
	}
	return info.Size(), nil
}

func UninstallSystemd(paths HomePaths, deleteHome bool) error {
	if os.Geteuid() != 0 {
		return errors.New("systemd uninstall requires root")
	}
	if err := StopServer(paths, defaultStopTimeout, false); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "disable", "--now", "yscan.service").Run()
	if err := os.Remove("/etc/systemd/system/yscan.service"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}
	if deleteHome {
		return os.RemoveAll(paths.Home)
	}
	return nil
}
