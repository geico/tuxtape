DROP TABLE IF EXISTS cve CASCADE;

DROP TABLE IF EXISTS vulnerability CASCADE;

DROP TABLE IF EXISTS mainline_kernel_release CASCADE;

DROP TABLE IF EXISTS kernel_release CASCADE;

DROP TABLE IF EXISTS vulnerability_instance CASCADE;

DROP TABLE IF EXISTS kernel_file CASCADE;

DROP TABLE IF EXISTS kernel_release_file CASCADE;

DROP TABLE IF EXISTS vulnerability_instance_affected_file CASCADE;

DROP TABLE IF EXISTS kernel_source CASCADE;

DROP TABLE IF EXISTS kernel_patch CASCADE;

DROP TABLE IF EXISTS meta CASCADE;

DROP FUNCTION IF EXISTS mainline_kernel_release_gteq CASCADE;

DROP FUNCTION IF EXISTS mainline_kernel_release_lt CASCADE;

DROP FUNCTION IF EXISTS kernel_release_is_affected_by_vulnerability_instance CASCADE;