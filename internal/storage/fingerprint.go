package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"golandproject/yscan/internal/model"
)

// AssetFingerprintQuery narrows stateful fingerprint conclusions. Empty
// fields do not filter; Port uses zero as the no-filter value.
type AssetFingerprintQuery struct {
	IP       string
	Port     int
	Protocol string
	RuleID   string
	SourceID string
}

// UpsertAssetFingerprints persists one or more validated conclusions. The
// primary key preserves source and rule provenance, first_seen remains stable,
// and last_seen records the latest successful confirmation.
func UpsertAssetFingerprints(db *sql.DB, fingerprints []model.AssetFingerprint) error {
	if len(fingerprints) == 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for index, fingerprint := range fingerprints {
		fingerprint, err = normalizeAssetFingerprint(fingerprint)
		if err != nil {
			return fmt.Errorf("normalize fingerprint %d: %w", index, err)
		}
		evidenceJSON, err := json.Marshal(fingerprint.Evidence)
		if err != nil {
			return fmt.Errorf("marshal fingerprint %d evidence: %w", index, err)
		}
		if _, err := tx.Exec(`
			INSERT INTO asset_fingerprints
				(ip, port, protocol, rule_id, source_id, vendor, product, version, cpe, confidence, evidence_json, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
			ON CONFLICT(ip, port, protocol, rule_id, source_id) DO UPDATE SET
				vendor = excluded.vendor,
				product = excluded.product,
				version = excluded.version,
				cpe = excluded.cpe,
				confidence = excluded.confidence,
				evidence_json = excluded.evidence_json,
				last_seen = datetime('now')`,
			fingerprint.IP,
			fingerprint.Port,
			fingerprint.Protocol,
			fingerprint.RuleID,
			fingerprint.SourceID,
			fingerprint.Vendor,
			fingerprint.Product,
			fingerprint.Version,
			fingerprint.CPE,
			fingerprint.Confidence,
			string(evidenceJSON),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListAssetFingerprints returns deterministic, source-traceable conclusions.
func ListAssetFingerprints(db *sql.DB, query AssetFingerprintQuery) ([]model.AssetFingerprint, error) {
	query, err := normalizeAssetFingerprintQuery(query)
	if err != nil {
		return nil, err
	}

	statement := `
		SELECT ip, port, protocol, rule_id, source_id, vendor, product, version, cpe, confidence, evidence_json, first_seen, last_seen
		FROM asset_fingerprints`
	clauses := make([]string, 0, 5)
	arguments := make([]interface{}, 0, 5)
	if query.IP != "" {
		clauses = append(clauses, "ip = ?")
		arguments = append(arguments, query.IP)
	}
	if query.Port != 0 {
		clauses = append(clauses, "port = ?")
		arguments = append(arguments, query.Port)
	}
	if query.Protocol != "" {
		clauses = append(clauses, "protocol = ?")
		arguments = append(arguments, query.Protocol)
	}
	if query.RuleID != "" {
		clauses = append(clauses, "rule_id = ?")
		arguments = append(arguments, query.RuleID)
	}
	if query.SourceID != "" {
		clauses = append(clauses, "source_id = ?")
		arguments = append(arguments, query.SourceID)
	}
	if len(clauses) > 0 {
		statement += " WHERE " + strings.Join(clauses, " AND ")
	}
	statement += " ORDER BY ip ASC, port ASC, protocol ASC, confidence DESC, rule_id ASC, source_id ASC"

	rows, err := db.Query(statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]model.AssetFingerprint, 0)
	for rows.Next() {
		var fingerprint model.AssetFingerprint
		var evidenceJSON string
		if err := rows.Scan(
			&fingerprint.IP,
			&fingerprint.Port,
			&fingerprint.Protocol,
			&fingerprint.RuleID,
			&fingerprint.SourceID,
			&fingerprint.Vendor,
			&fingerprint.Product,
			&fingerprint.Version,
			&fingerprint.CPE,
			&fingerprint.Confidence,
			&evidenceJSON,
			&fingerprint.FirstSeen,
			&fingerprint.LastSeen,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(evidenceJSON), &fingerprint.Evidence); err != nil {
			return nil, fmt.Errorf("decode fingerprint %s evidence: %w", fingerprint.RuleID, err)
		}
		results = append(results, fingerprint)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func normalizeAssetFingerprint(fingerprint model.AssetFingerprint) (model.AssetFingerprint, error) {
	fingerprint.IP = strings.TrimSpace(fingerprint.IP)
	fingerprint.Protocol = strings.ToLower(strings.TrimSpace(fingerprint.Protocol))
	fingerprint.RuleID = strings.ToLower(strings.TrimSpace(fingerprint.RuleID))
	fingerprint.SourceID = strings.ToLower(strings.TrimSpace(fingerprint.SourceID))
	fingerprint.Vendor = strings.TrimSpace(fingerprint.Vendor)
	fingerprint.Product = strings.TrimSpace(fingerprint.Product)
	fingerprint.Version = strings.TrimSpace(fingerprint.Version)
	fingerprint.CPE = strings.TrimSpace(fingerprint.CPE)
	for index := range fingerprint.Evidence {
		evidence := &fingerprint.Evidence[index]
		evidence.Target = strings.TrimSpace(evidence.Target)
		evidence.HeaderName = strings.ToLower(strings.TrimSpace(evidence.HeaderName))
		evidence.Operator = strings.TrimSpace(evidence.Operator)
		evidence.Summary = strings.TrimSpace(evidence.Summary)
		if evidence.Target == "" || evidence.Operator == "" || strings.TrimSpace(evidence.Pattern) == "" || evidence.Summary == "" {
			return model.AssetFingerprint{}, errors.New("fingerprint evidence requires target, operator, pattern and summary")
		}
	}
	if !fingerprint.Valid() || net.ParseIP(fingerprint.IP) == nil {
		return model.AssetFingerprint{}, errors.New("invalid asset fingerprint")
	}
	return fingerprint, nil
}

func normalizeAssetFingerprintQuery(query AssetFingerprintQuery) (AssetFingerprintQuery, error) {
	query.IP = strings.TrimSpace(query.IP)
	query.Protocol = strings.ToLower(strings.TrimSpace(query.Protocol))
	query.RuleID = strings.ToLower(strings.TrimSpace(query.RuleID))
	query.SourceID = strings.ToLower(strings.TrimSpace(query.SourceID))
	if query.IP != "" && net.ParseIP(query.IP) == nil {
		return AssetFingerprintQuery{}, errors.New("invalid asset fingerprint IP filter")
	}
	if query.Port < 0 || query.Port > 65535 {
		return AssetFingerprintQuery{}, errors.New("invalid asset fingerprint port filter")
	}
	if query.Protocol != "" && query.Protocol != "http" && query.Protocol != "https" && query.Protocol != "tcp" && query.Protocol != "tls" {
		return AssetFingerprintQuery{}, errors.New("invalid asset fingerprint protocol filter")
	}
	return query, nil
}
