package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const databaseLockPollInterval = 25 * time.Millisecond

type DatabaseLifecycle struct {
	paths           HomePaths
	upgrade         *FileLock
	database        *FileLock
	temporaryServer *FileLock
	exclusive       bool
}

func AcquireDatabaseShared(paths HomePaths, serverLockHeld bool, timeout time.Duration) (*DatabaseLifecycle, error) {
	deadline := time.Now().Add(timeout)
	for {
		if err := clearStaleUpgradePending(paths, serverLockHeld); err != nil {
			return nil, err
		}
		if _, err := os.Stat(upgradePendingPath(paths)); err == nil {
			if err := waitForDatabaseLock(deadline); err != nil {
				return nil, fmt.Errorf("wait for database upgrade: %w", err)
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect upgrade intent: %w", err)
		}

		upgrade, err := tryFileLock(paths.UpgradeLock, syscall.LOCK_SH)
		if errors.Is(err, ErrLockHeld) {
			if err := waitForDatabaseLock(deadline); err != nil {
				return nil, fmt.Errorf("acquire shared upgrade lock: %w", err)
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		database, err := acquireFileLock(paths.DatabaseLock, syscall.LOCK_SH, deadline)
		if err != nil {
			_ = upgrade.Close()
			return nil, err
		}
		return &DatabaseLifecycle{paths: paths, upgrade: upgrade, database: database}, nil
	}
}

func AcquireDatabaseExclusive(paths HomePaths, serverAlreadyHeld bool, timeout time.Duration) (*DatabaseLifecycle, error) {
	deadline := time.Now().Add(timeout)
	lifecycle := &DatabaseLifecycle{paths: paths, exclusive: true}
	if !serverAlreadyHeld {
		server, err := acquireFileLock(paths.ServerLock, syscall.LOCK_EX, deadline)
		if err != nil {
			return nil, fmt.Errorf("acquire Server lock for database initialization: %w", err)
		}
		lifecycle.temporaryServer = server
		if err := os.Remove(paths.ServerState); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = lifecycle.Close()
			return nil, fmt.Errorf("remove stale Server state before database initialization: %w", err)
		}
	}
	if err := publishUpgradePending(paths); err != nil {
		_ = lifecycle.Close()
		return nil, err
	}
	upgrade, err := acquireFileLock(paths.UpgradeLock, syscall.LOCK_EX, deadline)
	if err != nil {
		_ = lifecycle.Close()
		return nil, err
	}
	lifecycle.upgrade = upgrade
	database, err := acquireFileLock(paths.DatabaseLock, syscall.LOCK_EX, deadline)
	if err != nil {
		_ = lifecycle.Close()
		return nil, err
	}
	lifecycle.database = database
	return lifecycle, nil
}

func (lifecycle *DatabaseLifecycle) DowngradeToShared() error {
	if lifecycle == nil || lifecycle.upgrade == nil || lifecycle.database == nil {
		return errors.New("database lifecycle locks are incomplete")
	}
	if err := syscall.Flock(int(lifecycle.upgrade.file.Fd()), syscall.LOCK_SH); err != nil {
		return fmt.Errorf("downgrade upgrade lock: %w", err)
	}
	if err := syscall.Flock(int(lifecycle.database.file.Fd()), syscall.LOCK_SH); err != nil {
		return fmt.Errorf("downgrade database lock: %w", err)
	}
	lifecycle.exclusive = false
	if err := os.Remove(upgradePendingPath(lifecycle.paths)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove upgrade intent: %w", err)
	}
	if lifecycle.temporaryServer != nil {
		if err := lifecycle.temporaryServer.Close(); err != nil {
			return err
		}
		lifecycle.temporaryServer = nil
	}
	return nil
}

func (lifecycle *DatabaseLifecycle) Close() error {
	if lifecycle == nil {
		return nil
	}
	var result error
	if lifecycle.database != nil {
		result = errors.Join(result, lifecycle.database.Close())
		lifecycle.database = nil
	}
	if lifecycle.upgrade != nil {
		result = errors.Join(result, lifecycle.upgrade.Close())
		lifecycle.upgrade = nil
	}
	if lifecycle.exclusive {
		if err := os.Remove(upgradePendingPath(lifecycle.paths)); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}
	if lifecycle.temporaryServer != nil {
		result = errors.Join(result, lifecycle.temporaryServer.Close())
		lifecycle.temporaryServer = nil
	}
	return result
}

func tryFileLock(path string, mode int) (*FileLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("lock path must not be a symbolic link: %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), mode|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrLockHeld
		}
		return nil, err
	}
	return &FileLock{file: file, path: path}, nil
}

func acquireFileLock(path string, mode int, deadline time.Time) (*FileLock, error) {
	for {
		lock, err := tryFileLock(path, mode)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, ErrLockHeld) {
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if err := waitForDatabaseLock(deadline); err != nil {
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
	}
}

func waitForDatabaseLock(deadline time.Time) error {
	if !time.Now().Before(deadline) {
		return errors.New("timed out")
	}
	time.Sleep(databaseLockPollInterval)
	return nil
}

func upgradePendingPath(paths HomePaths) string {
	return filepath.Join(paths.RunDir, "upgrade.pending")
}

func publishUpgradePending(paths HomePaths) error {
	if err := os.MkdirAll(paths.RunDir, 0750); err != nil {
		return err
	}
	content := []byte(fmt.Sprintf("pid=%d\ncreated_at=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano)))
	if err := os.WriteFile(upgradePendingPath(paths), content, 0600); err != nil {
		return fmt.Errorf("write upgrade intent: %w", err)
	}
	return syncDirectory(paths.RunDir)
}

func clearStaleUpgradePending(paths HomePaths, serverLockHeld bool) error {
	if _, err := os.Stat(upgradePendingPath(paths)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if serverLockHeld {
		return os.Remove(upgradePendingPath(paths))
	}
	probe, err := tryFileLock(paths.ServerLock, syscall.LOCK_EX)
	if errors.Is(err, ErrLockHeld) {
		return nil
	}
	if err != nil {
		return err
	}
	defer probe.Close()
	if err := os.Remove(upgradePendingPath(paths)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
