package fingerprint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"golandproject/yscan/internal/model"
)

type nmapAdapter struct{}

func (nmapAdapter) SourceKey() string      { return "nmap-service-probes" }
func (nmapAdapter) AdapterVersion() string { return "m11-nmap-read-only-probes-v1" }

func (nmapAdapter) Adapt(snapshot VerifiedSnapshot) ([]model.FingerprintSourceRule, error) {
	raw := snapshot.Files["nmap-service-probes"]
	probes, err := ParseNmapTCPProbes(raw)
	if err != nil {
		return nil, fmt.Errorf("parse Nmap TCP probes: %w", err)
	}
	probeByName := make(map[string]NmapTCPProbe, len(probes))
	for _, probe := range probes {
		probeByName[probe.Name] = probe
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	protocol, probeName, index, lineNo := "", "", 0, 0
	rules := make([]model.FingerprintSourceRule, 0, 12171)
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if strings.HasPrefix(line, "Probe TCP ") {
			protocol = "tcp"
			fields := strings.Fields(line)
			probeName = fields[2]
			continue
		}
		if strings.HasPrefix(line, "Probe UDP ") {
			protocol = "udp"
			fields := strings.Fields(line)
			probeName = fields[2]
			continue
		}
		if protocol == "" || !(strings.HasPrefix(line, "match ") || strings.HasPrefix(line, "softmatch ")) {
			continue
		}
		status, reason, mode := "unsupported", "tcp_probe_not_read_only_allowlisted", "unsupported"
		if protocol == "udp" {
			reason = "udp_not_in_v2_execution_scope"
		} else if match, ok := parseNmapMatch(line); ok {
			pattern, flagsOK := nmapGoPattern(match.Pattern, match.Flags)
			_, regexErr := regexp.Compile(pattern)
			semanticsOK := flagsOK && regexErr == nil && nmapTemplateSupported(match.Version) && nmapTemplateSupported(match.CPE)
			switch {
			case !semanticsOK:
				reason = "tcp_probe_semantics_unsupported"
			case probeName == "NULL":
				status, reason, mode = "executable", "", "passive"
			case isReadOnlyNmapProbe(probeByName[probeName]):
				status, reason, mode = "executable", "", "active"
			}
		}
		structure := nmapProbeProjection{Mode: mode, Name: probeName}
		if probe, exists := probeByName[probeName]; exists {
			structure = nmapProbeProjectionFor(probe, mode)
		}
		structureJSON, err := json.Marshal(structure)
		if err != nil {
			return nil, err
		}
		rules = append(rules, model.FingerprintSourceRule{SourceRuleID: fmt.Sprintf("%s:%s:%d", protocol, probeName, index), SourcePath: fmt.Sprintf("nmap-service-probes:%d", lineNo), ContentSHA256: sha256Hex([]byte(line)), RawContent: line, RawStructure: string(structureJSON), ImportStatus: status, ImportError: reason})
		index++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rules) != 12171 {
		return nil, fmt.Errorf("unexpected nmap match total: %d", len(rules))
	}
	return rules, nil
}
