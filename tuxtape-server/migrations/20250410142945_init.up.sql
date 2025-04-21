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
        kernel_file_id INTEGER NOT NULL REFERENCES kernel_file,
        UNIQUE (vulnerability_instance_id, kernel_file_id)
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

CREATE OR REPLACE FUNCTION mainline_kernel_release_gteq(
    lhs mainline_kernel_release,
    rhs mainline_kernel_release
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN
        (lhs.major_version > rhs.major_version) OR
        (lhs.major_version = rhs.major_version AND lhs.minor_version > rhs.minor_version) OR
        (lhs.major_version = rhs.major_version AND lhs.minor_version = rhs.minor_version AND lhs.patch_version > rhs.patch_version) OR
        (lhs.major_version = rhs.major_version AND lhs.minor_version = rhs.minor_version AND lhs.patch_version = rhs.patch_version AND lhs.extra_version >= rhs.extra_version);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION mainline_kernel_release_lt(
    lhs mainline_kernel_release,
    rhs mainline_kernel_release
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN
        (lhs.major_version < rhs.major_version) OR
        (lhs.major_version = rhs.major_version AND lhs.minor_version < rhs.minor_version) OR
        (lhs.major_version = rhs.major_version AND lhs.minor_version = rhs.minor_version AND lhs.patch_version < rhs.patch_version) OR
        (lhs.major_version = rhs.major_version AND lhs.minor_version = rhs.minor_version AND lhs.patch_version = rhs.patch_version AND lhs.extra_version < rhs.extra_version);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION kernel_release_is_affected_by_vulnerability_instance(
    kernel_release_id INTEGER,
    vulnerability_instance_id INTEGER
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN (
        WITH kernel_release_arg AS (
            SELECT * FROM kernel_release WHERE id = kernel_release_id
        ),
        vulnerability_instance_arg AS (
            SELECT * FROM vulnerability_instance WHERE id = vulnerability_instance_id
        )
        SELECT
            -- Check if the kernel_release's mainline_kernel_release is greater than or equal to the introduced version
            mainline_kernel_release_gteq(
                (SELECT * FROM mainline_kernel_release WHERE id = (SELECT mainline_kernel_release_id FROM kernel_release_arg)),
                (SELECT * FROM mainline_kernel_release WHERE id = (SELECT mainline_kernel_release_introduced_id FROM vulnerability_instance_arg))
            )
            AND
            -- Check if the kernel_release's mainline_kernel_release is less than the fixed version (if fixed version exists)
            (
                (SELECT mainline_kernel_release_fixed_id FROM vulnerability_instance_arg) IS NULL
                OR mainline_kernel_release_lt(
                    (SELECT * FROM mainline_kernel_release WHERE id = (SELECT mainline_kernel_release_id FROM kernel_release_arg)),
                    (SELECT * FROM mainline_kernel_release WHERE id = (SELECT mainline_kernel_release_fixed_id FROM vulnerability_instance_arg))
                )
            )
            AND
            -- Check if the kernel_release contains at least one affected file
            EXISTS (
                SELECT 1
                FROM kernel_release_file krf
                JOIN vulnerability_instance_affected_file viaf
                ON krf.kernel_file_id = viaf.kernel_file_id
                WHERE krf.kernel_release_id = (SELECT id FROM kernel_release_arg)
                AND viaf.vulnerability_instance_id = (SELECT id FROM vulnerability_instance_arg)
            )
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;
