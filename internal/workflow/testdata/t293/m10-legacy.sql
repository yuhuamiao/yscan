PRAGMA foreign_keys = OFF;

CREATE TABLE banner (
    id INTEGER PRIMARY KEY,
    service_name TEXT NOT NULL,
    banner_pattern TEXT NOT NULL,
    description TEXT
);

CREATE TABLE domain_info (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    subdomain TEXT NOT NULL UNIQUE,
    is_wildcard INTEGER NOT NULL DEFAULT 0,
    title TEXT,
    first_seen DATETIME NOT NULL,
    last_scan DATETIME,
    source TEXT
);

CREATE TABLE domain_ips (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    ip TEXT NOT NULL,
    ports TEXT,
    UNIQUE(domain_id, ip)
);

CREATE TABLE host_inventory (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL UNIQUE,
    source TEXT,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    last_scan DATETIME,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE scan_results (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    service_id INTEGER,
    service_type TEXT NOT NULL,
    scan_time DATETIME,
    UNIQUE(ip, port)
);

CREATE TABLE tasks (
    id INTEGER PRIMARY KEY,
    task_type TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    progress INTEGER NOT NULL DEFAULT 0,
    error_msg TEXT,
    started_at DATETIME,
    finished_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE scan_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    cron TEXT,
    timezone TEXT,
    config_json TEXT NOT NULL DEFAULT '{}',
    config_hash TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
    archived_at DATETIME
);

CREATE TABLE scan_task_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_task_id INTEGER NOT NULL REFERENCES scan_tasks(id),
    sequence INTEGER NOT NULL,
    scheduled_for DATETIME NOT NULL,
    status TEXT NOT NULL,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    config_hash TEXT NOT NULL DEFAULT '',
    error_message TEXT,
    report_path TEXT,
    started_at DATETIME,
    finished_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now')),
    UNIQUE(scan_task_id, sequence),
    UNIQUE(scan_task_id, scheduled_for)
);

CREATE TABLE scan_task_run_hosts (
    scan_task_run_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (scan_task_run_id, ip)
);

CREATE TABLE scan_task_run_ports (
    scan_task_run_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    service_type TEXT NOT NULL,
    product TEXT,
    banner TEXT,
    PRIMARY KEY (scan_task_run_id, ip, port)
);

CREATE TABLE scan_task_run_vulnerabilities (
    scan_task_run_id INTEGER NOT NULL,
    finding_key TEXT NOT NULL,
    template_id TEXT,
    name TEXT,
    severity TEXT,
    target TEXT NOT NULL,
    target_ip TEXT,
    target_port INTEGER,
    matched_at TEXT,
    evidence TEXT,
    PRIMARY KEY (scan_task_run_id, finding_key)
);

CREATE TABLE scan_task_run_template_candidates (
    scan_task_run_id INTEGER NOT NULL,
    template_id TEXT NOT NULL,
    path TEXT NOT NULL,
    source TEXT NOT NULL,
    reason TEXT NOT NULL,
    PRIMARY KEY (scan_task_run_id, template_id, path)
);

INSERT INTO banner (id, service_name, banner_pattern, description)
VALUES (9001, 'legacy-t293-ssh', 'OpenSSH_9.6', 'synthetic v1 fixture rule');

INSERT INTO scan_tasks (id, target, scan_type, mode, status, config_json, config_hash)
VALUES (1, '127.0.0.1', 'ip', 'scheduled', 'enabled', '{"port_spec":"22"}', 'm10-fixture-config');

INSERT INTO scan_task_runs (
    id, scan_task_id, sequence, scheduled_for, status, target, scan_type,
    config_json, config_hash, started_at, finished_at
) VALUES (
    1, 1, 1, '2026-07-01T00:00:00Z', 'success', '127.0.0.1', 'ip',
    '{"port_spec":"22"}', 'm10-fixture-config', '2026-07-01T00:00:00Z', '2026-07-01T00:00:01Z'
);

INSERT INTO scan_task_run_hosts (scan_task_run_id, ip, is_active)
VALUES (1, '127.0.0.1', 1);

INSERT INTO scan_task_run_ports (scan_task_run_id, ip, port, service_type, product, banner)
VALUES (1, '127.0.0.1', 22, 'ssh', 'legacy', 'SSH-2.0-legacy');
