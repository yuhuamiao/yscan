package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

var ErrLockHeld = errors.New("lock is held by another process")

type FileLock struct {
	file *os.File
	path string
}

func TryExclusiveLock(path string) (*FileLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("lock path must not be a symbolic link: %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect lock path %s: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w: %s", ErrLockHeld, path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return &FileLock{file: file, path: path}, nil
}

func (lock *FileLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		return fmt.Errorf("unlock %s: %w", lock.path, unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close lock %s: %w", lock.path, closeErr)
	}
	return nil
}
