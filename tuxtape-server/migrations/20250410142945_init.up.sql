-- Initializes the TuxTape database
CREATE TABLE
    cve (
        id SERIAL PRIMARY KEY,
        cve_id TEXT NOT NULL UNIQUE,
        base_score REAL,
        attack_vector TEXT,
        attack_complexity TEXT,
        privileges_required TEXT,
        user_interaction TEXT,
        scope TEXT,
        confidentiality_impact TEXT,
        integrity_impact TEXT,
        availability_impact TEXT,
        description TEXT
    );

CREATE TABLE
    vulnerability (
        id SERIAL PRIMARY KEY,
        cve_id INTEGER REFERENCES cve UNIQUE,
        description TEXT
    );

CREATE TABLE
    mainline_kernel_release (
        id SERIAL PRIMARY KEY,
        major_version INTEGER NOT NULL,
        minor_version INTEGER NOT NULL,
        patch_version INTEGER NOT NULL,
        extra_version TEXT NOT NULL,
        UNIQUE (
            major_version,
            minor_version,
            patch_version,
            extra_version
        )
    );

CREATE TABLE
    kernel_release (
        id SERIAL PRIMARY KEY,
        mainline_kernel_release_id INTEGER NOT NULL REFERENCES mainline_kernel_release,
        local_version TEXT NOT NULL,
        UNIQUE (mainline_kernel_release_id, local_version)
    );

CREATE TABLE
    vulnerability_instance (
        id SERIAL PRIMARY KEY,
        vulnerability_id INTEGER NOT NULL REFERENCES vulnerability,
        mainline_kernel_release_introduced_id INTEGER NOT NULL REFERENCES mainline_kernel_release,
        mainline_kernel_release_fixed_id INTEGER REFERENCES mainline_kernel_release,
        fixed_commit TEXT,
        patch_diff TEXT,
        UNIQUE NULLS NOT DISTINCT (
            vulnerability_id,
            mainline_kernel_release_introduced_id,
            mainline_kernel_release_fixed_id
        )
    );

CREATE TABLE
    kernel_file (
        id SERIAL PRIMARY KEY,
        file_path TEXT NOT NULL UNIQUE
    );

CREATE TABLE
    kernel_release_file (
        id SERIAL PRIMARY KEY,
        kernel_release_id INTEGER NOT NULL REFERENCES kernel_release,
        kernel_file_id INTEGER NOT NULL REFERENCES kernel_file
    );

CREATE TABLE
    vulnerability_instance_affected_file (
        id SERIAL PRIMARY KEY,
        vulnerability_instance_id INTEGER NOT NULL REFERENCES vulnerability_instance,
        kernel_file_id INTEGER NOT NULL REFERENCES kernel_file
    );

CREATE TABLE
    kernel_source (
        id SERIAL PRIMARY KEY,
        kernel_release_id INTEGER NOT NULL REFERENCES kernel_release UNIQUE,
        url TEXT NOT NULL UNIQUE
    );

CREATE TABLE
    kernel_patch (
        id SERIAL PRIMARY KEY,
        vulnerability_instance_id INTEGER NOT NULL REFERENCES vulnerability_instance,
        kernel_release_id INTEGER NOT NULL REFERENCES kernel_release,
        url TEXT NOT NULL UNIQUE,
        UNIQUE (vulnerability_instance_id, kernel_release_id)
    );

CREATE TABLE
    meta (
        id SERIAL PRIMARY KEY CHECK (id = 1),
        based_on_vulns_commit TEXT NOT NULL,
        last_run_unix_time INTEGER NOT NULL
    );