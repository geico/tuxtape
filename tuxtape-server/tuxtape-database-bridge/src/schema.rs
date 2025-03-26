// @generated automatically by Diesel CLI.

diesel::table! {
    cve (id) {
        id -> Integer,
        cve_id -> Text,
        vulnerability_id -> Integer,
        base_score -> Nullable<Float>,
        attack_vector -> Nullable<Text>,
        attack_complexity -> Nullable<Text>,
        privileges_required -> Nullable<Text>,
        user_interaction -> Nullable<Text>,
        scope -> Nullable<Text>,
        confidentiality_impact -> Nullable<Text>,
        integrity_impact -> Nullable<Text>,
        availability_impact -> Nullable<Text>,
        description -> Nullable<Text>,
    }
}

diesel::table! {
    kernel_file (id) {
        id -> Integer,
        kernel_release_id -> Integer,
        file_path -> Text,
    }
}

diesel::table! {
    kernel_release (id) {
        id -> Integer,
        mainline_kernel_release_id -> Integer,
        version_local -> Nullable<Text>,
    }
}

diesel::table! {
    kernel_source (id) {
        id -> Integer,
        kernel_release_id -> Integer,
        url -> Text,
    }
}

diesel::table! {
    mainline_kernel_release (id) {
        id -> Integer,
        version_major -> Integer,
        version_minor -> Integer,
        version_patch -> Integer,
        version_extra -> Text,
    }
}

diesel::table! {
    meta (id) {
        id -> Integer,
        based_on_vulns_commit -> Text,
        last_run_unix_time -> Integer,
    }
}

diesel::table! {
    vulnerability (id) {
        id -> Integer,
        description -> Nullable<Text>,
    }
}

diesel::table! {
    vulnerability_instance (id) {
        id -> Integer,
        vulnerability_id -> Integer,
        description -> Nullable<Text>,
        mainline_kernel_release_introduced_id -> Nullable<Integer>,
        mainline_kernel_release_fixed_id -> Nullable<Integer>,
        fixed_commit -> Nullable<Text>,
        patch_diff -> Nullable<Text>,
    }
}

diesel::table! {
    vulnerability_instance_affected_file (id) {
        id -> Integer,
        vulnerability_instance_id -> Integer,
        file_path -> Text,
    }
}

diesel::joinable!(cve -> vulnerability (vulnerability_id));
diesel::joinable!(kernel_file -> kernel_release (kernel_release_id));
diesel::joinable!(kernel_release -> mainline_kernel_release (mainline_kernel_release_id));
diesel::joinable!(kernel_source -> kernel_release (kernel_release_id));
diesel::joinable!(vulnerability_instance -> vulnerability (vulnerability_id));
diesel::joinable!(vulnerability_instance_affected_file -> vulnerability_instance (vulnerability_instance_id));

diesel::allow_tables_to_appear_in_same_query!(
    cve,
    kernel_file,
    kernel_release,
    kernel_source,
    mainline_kernel_release,
    meta,
    vulnerability,
    vulnerability_instance,
    vulnerability_instance_affected_file,
);
