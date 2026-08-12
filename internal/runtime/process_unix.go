//go:build !windows

package runtime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func configureDetachedProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func signalGraceful(process *os.Process) error { return process.Signal(syscall.SIGTERM) }
func signalForce(process *os.Process) error    { return process.Signal(syscall.SIGKILL) }
func ShutdownSignals() []os.Signal             { return []os.Signal{os.Interrupt, syscall.SIGTERM} }

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
	for _, argument := range arguments[1:] {
		if argument == "server" {
			return nil
		}
	}
	return fmt.Errorf("refusing to signal PID %d because it is not a yscan Server command", pid)
}

func uninstallSystemdUnit() error {
	if os.Geteuid() != 0 {
		return errors.New("systemd uninstall requires root")
	}
	_ = exec.Command("systemctl", "disable", "--now", "yscan.service").Run()
	if err := os.Remove("/etc/systemd/system/yscan.service"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return exec.Command("systemctl", "daemon-reload").Run()
}
