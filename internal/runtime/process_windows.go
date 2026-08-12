//go:build windows

package runtime

import (
	"errors"
	"os"
	"os/exec"
)

func processExists(pid int) bool {
	_, err := os.FindProcess(pid)
	return pid > 0 && err == nil
}

func configureDetachedProcess(*exec.Cmd) {}

func signalGraceful(process *os.Process) error { return process.Signal(os.Interrupt) }
func signalForce(process *os.Process) error    { return process.Kill() }
func ShutdownSignals() []os.Signal             { return []os.Signal{os.Interrupt} }

func verifyControlledServerProcess(_ HomePaths, pid int) error {
	if !processExists(pid) {
		return errors.New("Server process is no longer running")
	}
	return nil
}

func uninstallSystemdUnit() error { return errors.New("systemd is unavailable on Windows") }
