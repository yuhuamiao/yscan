package runtime

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const ConfigProtocolVersion = 1

const (
	ConfigListenAddress     = "YSCAN_LISTEN_ADDR"
	ConfigAllowCIDRs        = "YSCAN_ALLOW_CIDRS"
	ConfigMaxConcurrency    = "YSCAN_MAX_CONCURRENCY"
	ConfigSQLiteBusyTimeout = "YSCAN_SQLITE_BUSY_TIMEOUT"
	ConfigLogMaxBytes       = "YSCAN_LOG_MAX_BYTES"
	ConfigLogMaxFiles       = "YSCAN_LOG_MAX_FILES"
	ConfigNucleiBinary      = "YSCAN_NUCLEI_BINARY"
	ConfigNucleiTemplates   = "YSCAN_NUCLEI_TEMPLATES"
)

type Config struct {
	ListenAddress     string
	AllowCIDRs        []string
	MaxConcurrency    int
	SQLiteBusyTimeout time.Duration
	LogMaxBytes       int64
	LogMaxFiles       int
	NucleiBinary      string
	NucleiTemplates   string
}

type ConfigOverrides map[string]string

func LoadConfig(paths HomePaths, overrides ConfigOverrides, lookupEnv func(string) (string, bool)) (Config, error) {
	values := map[string]string{
		ConfigListenAddress:     "127.0.0.1:8080",
		ConfigAllowCIDRs:        "",
		ConfigMaxConcurrency:    "2",
		ConfigSQLiteBusyTimeout: "5s",
		ConfigLogMaxBytes:       "10485760",
		ConfigLogMaxFiles:       "3",
		ConfigNucleiBinary:      "nuclei",
		ConfigNucleiTemplates:   "",
	}

	fileValues, err := readEnvFile(paths.EnvFile)
	if err != nil {
		return Config{}, err
	}
	for key, value := range fileValues {
		values[key] = value
	}
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	for key := range values {
		if value, ok := lookupEnv(key); ok {
			values[key] = strings.TrimSpace(value)
		}
	}
	for key, value := range overrides {
		if !knownConfigKey(key) {
			return Config{}, fmt.Errorf("unknown command-line configuration key %s", key)
		}
		values[key] = strings.TrimSpace(value)
	}
	return parseConfigValues(values)
}

func readEnvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		key, rawValue, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("%s:%d: expected KEY=VALUE", path, lineNumber)
		}
		if !knownConfigKey(key) {
			if strings.HasPrefix(key, "YSCAN_") {
				return nil, fmt.Errorf("%s:%d: unknown configuration key %s", path, lineNumber, key)
			}
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return nil, fmt.Errorf("%s:%d: duplicate configuration key %s", path, lineNumber, key)
		}
		value, err := parseEnvValue(strings.TrimSpace(rawValue))
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return values, nil
}

func parseEnvValue(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if value[0] != '\'' && value[0] != '"' {
		return value, nil
	}
	if len(value) < 2 || value[len(value)-1] != value[0] {
		return "", errors.New("unterminated quoted value")
	}
	if value[0] == '\'' {
		return value[1 : len(value)-1], nil
	}
	unquoted, err := strconv.Unquote(value)
	if err != nil {
		return "", fmt.Errorf("invalid quoted value: %w", err)
	}
	return unquoted, nil
}

func parseConfigValues(values map[string]string) (Config, error) {
	config := Config{
		ListenAddress:   strings.TrimSpace(values[ConfigListenAddress]),
		NucleiBinary:    strings.TrimSpace(values[ConfigNucleiBinary]),
		NucleiTemplates: strings.TrimSpace(values[ConfigNucleiTemplates]),
	}
	if _, _, err := net.SplitHostPort(config.ListenAddress); err != nil {
		return Config{}, fmt.Errorf("%s: %w", ConfigListenAddress, err)
	}
	for _, value := range strings.Split(values[ConfigAllowCIDRs], ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(value); err != nil {
			return Config{}, fmt.Errorf("%s contains invalid CIDR %q", ConfigAllowCIDRs, value)
		}
		config.AllowCIDRs = append(config.AllowCIDRs, value)
	}
	var err error
	config.MaxConcurrency, err = parseBoundedInt(values[ConfigMaxConcurrency], 1, 8)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", ConfigMaxConcurrency, err)
	}
	config.SQLiteBusyTimeout, err = time.ParseDuration(values[ConfigSQLiteBusyTimeout])
	if err != nil || config.SQLiteBusyTimeout <= 0 || config.SQLiteBusyTimeout > time.Minute {
		return Config{}, fmt.Errorf("%s must be a duration between 1ns and 1m", ConfigSQLiteBusyTimeout)
	}
	config.LogMaxBytes, err = strconv.ParseInt(values[ConfigLogMaxBytes], 10, 64)
	if err != nil || config.LogMaxBytes < 1024 || config.LogMaxBytes > 1<<30 {
		return Config{}, fmt.Errorf("%s must be between 1024 and 1073741824", ConfigLogMaxBytes)
	}
	config.LogMaxFiles, err = parseBoundedInt(values[ConfigLogMaxFiles], 1, 100)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", ConfigLogMaxFiles, err)
	}
	if config.NucleiBinary == "" {
		return Config{}, fmt.Errorf("%s cannot be empty", ConfigNucleiBinary)
	}
	return config, nil
}

func parseBoundedInt(value string, minimum, maximum int) (int, error) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("must be an integer between %d and %d", minimum, maximum)
	}
	return parsed, nil
}

func knownConfigKey(key string) bool {
	switch key {
	case ConfigListenAddress, ConfigAllowCIDRs, ConfigMaxConcurrency, ConfigSQLiteBusyTimeout,
		ConfigLogMaxBytes, ConfigLogMaxFiles, ConfigNucleiBinary, ConfigNucleiTemplates:
		return true
	default:
		return false
	}
}
