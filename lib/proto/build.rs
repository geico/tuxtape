use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace_dir = Path::new(env!("CARGO_WORKSPACE_DIR"));
    let proto_include_dir = workspace_dir.join("proto");
    let proto_tuxtape_dir = proto_include_dir.join("tuxtape");
    let proto_src_out_dir = Path::new("generated/src");
    let proto_file_descriptor_set_path = Path::new("generated/bin/descriptor.bin");
    let generated_include_file = Path::new("include.rs");

    let v1_protos = [
        proto_tuxtape_dir.join("server/database/v1/database.proto"),
        proto_tuxtape_dir.join("server/registrar/v1/registrar.proto"),
        proto_tuxtape_dir.join("server/fleet_client/v1/fleet_client.proto"),
        proto_tuxtape_dir.join("kernel_builder/v1/kernel_builder.proto"),
        proto_tuxtape_dir.join("patch_builder/v1/patch_builder.proto"),
    ];

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
