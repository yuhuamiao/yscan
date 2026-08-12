package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveHomeUsesExecutableInsteadOfWorkingDirectory(t *testing.T) {
	install := t.TempDir()
	other := t.TempDir()
	executable := filepath.Join(install, "yscan-real")
	if err := os.WriteFile(executable, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(install, "yscan")
	if err := os.Symlink(executable, link); err != nil {
		t.Fatal(err)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })

	paths, err := ResolveHome(link, "")
	if err != nil {
		t.Fatal(err)
	}
	if paths.Home != install || paths.Database != filepath.Join(install, "data", "asm.db") {
		t.Fatalf("paths = %#v", paths)
	}
}

func TestPrepareAndDatabaseSelection(t *testing.T) {
	home := t.TempDir()
	paths, err := ResolveHome(filepath.Join(home, "yscan"), home)
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.Prepare(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.EnvFile, paths.DataDir, paths.ReportsDir, paths.RunLogsDir, paths.ExecutionsDir} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing prepared path %s: %v", path, err)
		}
	}
	selection, err := paths.SelectDatabase()
	if err != nil || selection.Mode != DatabaseUninitialized || selection.Path != paths.Database {
		t.Fatalf("uninitialized selection = %#v, %v", selection, err)
	}
	if err := os.WriteFile(paths.LegacyDatabase, []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	selection, err = paths.SelectDatabase()
	if err != nil || selection.Mode != DatabaseLegacy || selection.Path != paths.LegacyDatabase {
		t.Fatalf("legacy selection = %#v, %v", selection, err)
	}
	if _, err := os.Stat(paths.Database); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy selection created current database: %v", err)
	}
	if err := os.WriteFile(paths.Database, []byte("current"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := paths.SelectDatabase(); err == nil || !strings.Contains(err.Error(), "both current and legacy") {
		t.Fatalf("conflicting selection error = %v", err)
	}
}

func TestPrepareDoesNotOverwriteEnvFile(t *testing.T) {
	home := t.TempDir()
	paths, err := ResolveHome(filepath.Join(home, "yscan"), home)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.EnvFile, []byte("YSCAN_MAX_CONCURRENCY=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := paths.Prepare(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(paths.EnvFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "YSCAN_MAX_CONCURRENCY=1\n" {
		t.Fatalf("env file was overwritten: %q", content)
	}
}

func TestLoadConfigPrecedence(t *testing.T) {
	home := t.TempDir()
	paths, err := ResolveHome(filepath.Join(home, "yscan"), home)
	if err != nil {
		t.Fatal(err)
	}
	content := "YSCAN_MAX_CONCURRENCY=3\nYSCAN_SQLITE_BUSY_TIMEOUT=7s\nYSCAN_NUCLEI_TEMPLATES=/from-file\n"
	if err := os.WriteFile(paths.EnvFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	environment := map[string]string{
		ConfigMaxConcurrency:  "4",
		ConfigNucleiTemplates: "/from-environment",
	}
	config, err := LoadConfig(paths, ConfigOverrides{
		ConfigMaxConcurrency:  "5",
		ConfigNucleiTemplates: "/from-cli",
	}, func(key string) (string, bool) {
		value, ok := environment[key]
		return value, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.MaxConcurrency != 5 || config.SQLiteBusyTimeout != 7*time.Second || config.NucleiTemplates != "/from-cli" {
		t.Fatalf("config = %#v", config)
	}
}

func TestLoadConfigReportsUnknownAndDuplicateKeys(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "unknown", content: "# comment\nYSCAN_MAX_CONCURRENCY=2\nYSCAN_MAX_CONCURENCY=3\n", want: ":3: unknown configuration key YSCAN_MAX_CONCURENCY"},
		{name: "duplicate", content: "YSCAN_MAX_CONCURRENCY=2\nYSCAN_MAX_CONCURRENCY=3\n", want: ":2: duplicate configuration key YSCAN_MAX_CONCURRENCY"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			paths, err := ResolveHome(filepath.Join(home, "yscan"), home)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(paths.EnvFile, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}
			_, err = LoadConfig(paths, nil, func(string) (string, bool) { return "", false })
			if err == nil || !strings.Contains(err.Error(), paths.EnvFile+test.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestUnsupportedFilesystemTypes(t *testing.T) {
	for _, filesystemType := range []int64{filesystemNFS, filesystemCIFS, filesystemSMB, filesystem9P, filesystemFUSE} {
		if !unsupportedFilesystem(filesystemType) {
			t.Fatalf("filesystem type 0x%x was accepted", filesystemType)
		}
	}
	if unsupportedFilesystem(0xef53) {
		t.Fatal("local ext filesystem was rejected")
	}
}
