package storage

import (
	"testing"

	"golandproject/yscan/internal/model"
)

func TestAssetFingerprintMigrationAndUpsert(t *testing.T) {
	db := openTestDB(t)
	if _, err := db.Exec(`CREATE TABLE legacy_scan_history (id INTEGER PRIMARY KEY, target TEXT NOT NULL)`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("migrate legacy schema: %v", err)
	}
	var tableName string
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'asset_fingerprints'`).Scan(&tableName); err != nil || tableName != "asset_fingerprints" {
		t.Fatalf("asset_fingerprints migration = %q, %v", tableName, err)
	}

	record := model.AssetFingerprint{
		IP:         "192.168.10.10",
		Port:       443,
		Protocol:   "HTTPS",
		RuleID:     "fingerprinthub/acme-gateway",
		SourceID:   "FingerprintHub",
		Vendor:     "acme",
		Product:    "gateway",
		Version:    "1.0",
		Confidence: 80,
		Evidence: []model.FingerprintEvidence{{
			Target:   "header",
			Operator: "contains",
			Pattern:  " acme ",
			Summary:  `header server contains "acme"`,
		}},
	}
	if err := UpsertAssetFingerprints(db, []model.AssetFingerprint{record}); err != nil {
		t.Fatalf("insert fingerprint: %v", err)
	}
	record.Confidence = 95
	record.Version = "1.1"
	record.Evidence[0].Summary = `header server contains "acme gateway"`
	if err := UpsertAssetFingerprints(db, []model.AssetFingerprint{record}); err != nil {
		t.Fatalf("update fingerprint: %v", err)
	}

	results, err := ListAssetFingerprints(db, AssetFingerprintQuery{IP: record.IP, Port: record.Port, Protocol: "https"})
	if err != nil {
		t.Fatalf("list fingerprints: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("fingerprints = %#v", results)
	}
	got := results[0]
	if got.RuleID != record.RuleID || got.SourceID != "fingerprinthub" || got.Version != "1.1" || got.Confidence != 95 || len(got.Evidence) != 1 || got.Evidence[0].Pattern != record.Evidence[0].Pattern || got.Evidence[0].Summary != record.Evidence[0].Summary || got.FirstSeen == "" || got.LastSeen == "" {
		t.Fatalf("stored fingerprint = %#v", got)
	}
}

func TestAssetFingerprintStorageRejectsInvalidRecordsAndFilters(t *testing.T) {
	db := openTestDB(t)
	if err := initSQLiteSchema(db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	invalid := model.AssetFingerprint{IP: "invalid", Port: 443, Protocol: "https", RuleID: "rule", SourceID: "source", Product: "product", Confidence: 50, Evidence: []model.FingerprintEvidence{{Target: "body", Operator: "contains", Pattern: "a", Summary: "body contains a"}}}
	if err := UpsertAssetFingerprints(db, []model.AssetFingerprint{invalid}); err == nil {
		t.Fatal("invalid fingerprint must be rejected")
	}
	if _, err := ListAssetFingerprints(db, AssetFingerprintQuery{Protocol: "udp"}); err == nil {
		t.Fatal("invalid protocol filter must be rejected")
	}
}
