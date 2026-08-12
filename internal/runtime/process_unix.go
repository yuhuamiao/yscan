//go:build !windows

package runtime

import (
	"errors"
	"syscall"
)

func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
