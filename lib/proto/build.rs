use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace_dir = Path::new(env!("CARGO_WORKSPACE_DIR"));
    let proto_include_dir = workspace_dir.join("proto");
    let proto_tuxtape_dir = proto_include_dir.join("tuxtape");
    let proto_src_out_dir = Path::new("generated/src");
    let proto_file_descriptor_set_path = Path::new("generated/bin/descriptor.bin");
    let generated_include_file = Path::new("include.rs");

    let v1_protos = fetch_proto_dirs(&proto_tuxtape_dir, 1, &["common"]);

    let mut config = tonic_build::Config::default();
    config.out_dir(proto_src_out_dir);
    config.include_file(generated_include_file);
    config.file_descriptor_set_path(proto_file_descriptor_set_path);

    tonic_build::configure().compile_protos_with_config(
        config,
        &v1_protos,
        &[proto_include_dir],
    )?;

    Ok(())
}

fn fetch_proto_dirs(
    proto_package_dir: &Path,
    proto_version: usize,
    ignore_modules: &[&str],
) -> Vec<PathBuf> {
    let version_str = format!("v{proto_version}");
    WalkDir::new(proto_package_dir)
        .into_iter()
        // Remove all files that don't have read permission
        .filter_map(|e| e.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "proto"))
        .filter(|entry| {
            entry
                .path()
                .components()
                .filter_map(|comp| comp.as_os_str().to_str())
                .any(|comp| comp == version_str)
        })
        .filter(|entry| {
            !entry
                .path()
                .components()
                .filter_map(|comp| comp.as_os_str().to_str())
                .any(|comp| ignore_modules.contains(&comp))
        })
        .map(|entry| entry.path().to_path_buf())
        .collect()
}
