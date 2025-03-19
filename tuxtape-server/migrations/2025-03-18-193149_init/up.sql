-- Initializes the TuxTape database

CREATE TABLE vulnerability (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    description TEXT
);

CREATE TABLE vulnerability_instance (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,
    description TEXT,
    mainline_kernel_release_introduced_id INTEGER,
    mainline_kernel_release_fixed_id INTEGER,
    fixed_commit TEXT,
    patch_diff TEXT,
    FOREIGN KEY(vulnerability_id) REFERENCES vulnerability(id),
    FOREIGN KEY(mainline_kernel_release_introduced_id) REFERENCES mainline_kernel_release(id),
    FOREIGN KEY(mainline_kernel_release_fixed_id) REFERENCES mainline_kernel_release(id)
);

CREATE TABLE vulnerability_instance_affected_file (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    vulnerability_instance_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    FOREIGN KEY(vulnerability_instance_id) REFERENCES vulnerability_instance(id)
);

CREATE TABLE cve (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    vulnerability_id INTEGER NOT NULL,
    base_score REAL,
    attack_vector TEXT,
    attack_complexity TEXT,
    privileges_required TEXT,
    user_interaction TEXT,
    scope TEXT,
    confidentiality_impact TEXT,
    integrity_impact TEXT,
    availability_impact TEXT,
    description TEXT,
    FOREIGN KEY(vulnerability_id) REFERENCES vulnerability(id)
);

CREATE TABLE mainline_kernel_release (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    version_major INTEGER NOT NULL,
    version_minor INTEGER NOT NULL,
    version_patch INTEGER NOT NULL,
    version_extra TEXT NOT NULL,
    UNIQUE (version_major, version_minor, version_patch, version_extra)
);

CREATE TABLE kernel_release (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    mainline_kernel_release_id INTEGER NOT NULL,
    version_local TEXT,
    FOREIGN KEY(mainline_kernel_release_id) REFERENCES mainline_kernel_release(id),
    UNIQUE (version_local)
);

CREATE TABLE kernel_source (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    kernel_release_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    FOREIGN KEY(kernel_release_id) REFERENCES kernel_release(id),
    UNIQUE (kernel_release_id, url)
);

CREATE TABLE kernel_file (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    kernel_release_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    FOREIGN KEY(kernel_release_id) REFERENCES kernel_release(id)
);

CREATE TABLE meta (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT CHECK (id = 1),
    based_on_vulns_commit TEXT NOT NULL,
    last_run_unix_time INTEGER NOT NULL
);
