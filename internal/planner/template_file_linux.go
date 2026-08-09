//go:build linux

package planner

import (
	"fmt"
	"os"
	"syscall"
)

func openNucleiTemplateFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open nuclei template: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("open nuclei template: invalid file descriptor for %s", path)
	}
	return file, nil
}
