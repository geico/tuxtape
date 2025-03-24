fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace_dir = std::env::var("CARGO_WORKSPACE_DIR")?;
    let proto_include_dir = format!("{workspace_dir}proto");
    let proto_tuxtape_dir = format!("{proto_include_dir}/tuxtape");
    let proto_src_out_dir = "src";

    let v1_protos = [
        format!("{proto_tuxtape_dir}/server/database/v1/database.proto"),
        format!("{proto_tuxtape_dir}/server/registrar/v1/registrar.proto"),
        format!("{proto_tuxtape_dir}/server/fleet_client/v1/fleet_client.proto"),
        format!("{proto_tuxtape_dir}/kernel_builder/v1/kernel_builder.proto"),
        format!("{proto_tuxtape_dir}/patch_builder/v1/patch_builder.proto"),
    ];

    let mut config = tonic_build::Config::default();
    config.out_dir(proto_src_out_dir);
    config.include_file("include.rs");

    tonic_build::configure().compile_protos_with_config(
        config,
        &v1_protos,
        &[proto_include_dir],
    )?;

    Ok(())
}
