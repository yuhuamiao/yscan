DELETE FROM schema_migrations WHERE name = 't320-frozen-product-roles-v2';

INSERT INTO fingerprint_sources (id, source_key, repository_url, status)
VALUES (9100, 'm11-v2-role-fixture', 'https://example.invalid/m11-v2-role-fixture', 'enabled');

INSERT INTO fingerprint_imports
    (id, fingerprint_source_id, commit_hash, content_sha256, upstream_content_sha256,
     adapter_version, projection_sha256, manifest_json, rule_total, executable_total, is_active)
VALUES
    (9200, 9100, 'm11-v2', 'm11-v2-content', 'm11-v2-content',
     'adapter-before-t320', 'm11-v2-projection', '{}', 3, 3, 1);

UPDATE fingerprint_products
SET product_role = 'application', exclusive_group = ''
WHERE canonical_name IN ('nginx', 'openssh', 'redis');

INSERT INTO fingerprint_source_rules
    (id, fingerprint_import_id, source_rule_id, source_path, content_sha256, raw_content, import_status)
VALUES
    (9400, 9200, 'nginx', 'fixture/nginx.json', 'nginx-sha', '{}', 'executable'),
    (9401, 9200, 'openssh', 'fixture/openssh.json', 'openssh-sha', '{}', 'executable'),
    (9402, 9200, 'redis', 'fixture/redis.json', 'redis-sha', '{}', 'executable');

INSERT INTO fingerprint_rules
    (id, fingerprint_source_rule_id, fingerprint_product_id, source_product_name, protocol,
     tags_json, product_role, exclusive_group, status)
VALUES
    (9500, 9400, (SELECT id FROM fingerprint_products WHERE canonical_name = 'nginx'), 'nginx', 'http', '["web"]', 'application', '', 'executable'),
    (9501, 9401, (SELECT id FROM fingerprint_products WHERE canonical_name = 'openssh'), 'OpenSSH', 'tcp', '["service"]', 'application', '', 'executable'),
    (9502, 9402, (SELECT id FROM fingerprint_products WHERE canonical_name = 'redis'), 'Redis', 'tcp', '["database"]', 'application', '', 'executable');

INSERT INTO fingerprint_match_groups (id, fingerprint_rule_id, operator, position)
VALUES (9600, 9500, 'all', 0), (9601, 9501, 'all', 0), (9602, 9502, 'all', 0);

INSERT INTO fingerprint_matchers
    (id, fingerprint_match_group_id, evidence_type, target, operator, value, position)
VALUES
    (9700, 9600, 'http_header', 'headers', 'contains_ci', 'nginx', 0),
    (9701, 9601, 'tcp_banner', 'banner', 'contains_ci', 'openssh', 0),
    (9702, 9602, 'tcp_banner', 'banner', 'contains_ci', 'redis', 0);

INSERT INTO scan_tasks
    (id, target, scan_type, mode, status, config_json, config_hash)
VALUES (9800, '192.0.2.10', 'ip', 'scheduled', 'enabled', '{}', 'm11-v2-config');

INSERT INTO scan_task_runs
    (id, scan_task_id, sequence, scheduled_for, status, target, scan_type, config_json, config_hash)
VALUES (9900, 9800, 1, '2026-08-01T00:00:00Z', 'success', '192.0.2.10', 'ip', '{}', 'm11-v2-config');

INSERT INTO scan_task_run_fingerprint_imports (scan_task_run_id, fingerprint_import_id)
VALUES (9900, 9200);

INSERT INTO asset_fingerprint_matches
    (id, scan_task_run_id, fingerprint_import_id, fingerprint_source_rule_id, ip, port, protocol,
     product_key, source_product_name, product_role, exclusive_group, tags_json, evidence_summary)
VALUES
    (9910, 9900, 9200, 9400, '192.0.2.10', 80, 'http', 'nginx', 'nginx', 'application', '', '["web"]', 'nginx header'),
    (9911, 9900, 9200, 9401, '192.0.2.10', 22, 'tcp', 'openssh', 'OpenSSH', 'application', '', '["service"]', 'openssh banner'),
    (9912, 9900, 9200, 9402, '192.0.2.10', 6379, 'tcp', 'redis', 'Redis', 'application', '', '["database"]', 'redis banner');

INSERT INTO asset_fingerprint_conclusions
    (id, scan_task_run_id, ip, port, protocol, product_key, product_role, exclusive_group,
     tags_json, conclusion_status, product_status, product_source_count)
VALUES
    (9920, 9900, '192.0.2.10', 80, 'http', 'nginx', 'application', '', '["web"]', 'matched', 'matched', 1),
    (9921, 9900, '192.0.2.10', 22, 'tcp', 'openssh', 'application', '', '["service"]', 'matched', 'matched', 1),
    (9922, 9900, '192.0.2.10', 6379, 'tcp', 'redis', 'application', '', '["database"]', 'matched', 'matched', 1);
