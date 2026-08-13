package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerSessionStateAndStaleRecovery(t *testing.T) {
	home := t.TempDir()
	paths, err := ResolveHome(os.Args[0], home)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.RunDir, 0750); err != nil {
		t.Fatal(err)
	}
	session, err := AcquireServerSession(paths, "127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.MarkRunning(); err != nil {
		t.Fatal(err)
	}
	if err := session.SetRestartArguments([]string{"--listen", "127.0.0.1:8080"}, []string{"127.0.0.1:8080"}); err != nil {
		t.Fatal(err)
	}
	inspection := InspectServer(paths)
	if inspection.Status != ServerRunning || inspection.State == nil || inspection.State.HealthToken == "" {
		t.Fatalf("running inspection = %#v", inspection)
	}
	if strings.Join(inspection.State.RestartEffectiveArguments, " ") != "--listen 127.0.0.1:8080" || strings.Join(inspection.State.RestartServerArguments, " ") != "127.0.0.1:8080" {
		t.Fatalf("restart arguments were not persisted: %#v", inspection.State)
	}
	if err := session.MarkDegraded("scheduler stopped"); err != nil {
		t.Fatal(err)
	}
	inspection = InspectServer(paths)
	if inspection.Status != ServerDegraded || inspection.Error != "scheduler stopped" {
		t.Fatalf("degraded inspection = %#v", inspection)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	stale := ServerState{PID: 2147483647, Status: ServerRunning, ListenAddress: "127.0.0.1:8080", HealthToken: "stale", StartedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := writeServerStateAtomic(paths.ServerState, stale); err != nil {
		t.Fatal(err)
	}
	if inspection := InspectServer(paths); inspection.Status != ServerStopped || inspection.State == nil {
		t.Fatalf("stale inspection = %#v", inspection)
	}
	replacement, err := AcquireServerSessionForStartup(paths, "127.0.0.1:9090")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
}

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
	for _, path := range []string{paths.EnvFile, paths.DataDir, paths.ReportsDir, paths.RunLogsDir, paths.RunDir} {
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

func TestLoadConfigFreezesLegacyNucleiTemplatesEnvironment(t *testing.T) {
	home := t.TempDir()
	paths, err := ResolveHome(filepath.Join(home, "yscan"), home)
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.Prepare(); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(paths, nil, func(key string) (string, bool) {
		if key == LegacyNucleiTemplatesEnvironment {
			return "legacy-templates", true
		}
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.NucleiTemplates != filepath.Join(home, "legacy-templates") {
		t.Fatalf("legacy templates were not frozen relative to home: %q", config.NucleiTemplates)
	}

	config, err = LoadConfig(paths, ConfigOverrides{ConfigNucleiTemplates: "configured-templates"}, func(key string) (string, bool) {
		if key == LegacyNucleiTemplatesEnvironment {
			return "legacy-templates", true
		}
		return "", false
	})
	if err != nil || config.NucleiTemplates != filepath.Join(home, "configured-templates") {
		t.Fatalf("legacy environment overrode configured templates: config=%#v err=%v", config, err)
	}

	config, err = LoadConfig(paths, nil, func(key string) (string, bool) {
		switch key {
		case ConfigNucleiTemplates:
			return "", true
		case LegacyNucleiTemplatesEnvironment:
			return "legacy-templates", true
		default:
			return "", false
		}
	})
	if err != nil || config.NucleiTemplates != "" {
		t.Fatalf("explicit empty new environment did not disable legacy input: config=%#v err=%v", config, err)
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

func TestLoadConfigResolvesRelativeNucleiPathsFromHome(t *testing.T) {
	home := t.TempDir()
	other := t.TempDir()
	paths, err := ResolveHome(filepath.Join(home, "yscan"), home)
	if err != nil {
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

	config, err := LoadConfig(paths, ConfigOverrides{
		ConfigNucleiBinary:    "tools/nuclei",
		ConfigNucleiTemplates: "nuclei-templates",
	}, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	if config.NucleiBinary != filepath.Join(home, "tools", "nuclei") {
		t.Fatalf("binary = %q", config.NucleiBinary)
	}
	if config.NucleiTemplates != filepath.Join(home, "nuclei-templates") {
		t.Fatalf("templates = %q", config.NucleiTemplates)
	}

	config, err = LoadConfig(paths, nil, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	if config.NucleiBinary != "nuclei" {
		t.Fatalf("PATH binary = %q", config.NucleiBinary)
	}
}
