use tonic_build::Config;
use vergen_gix::{BuildBuilder, CargoBuilder, Emitter, GixBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let build = BuildBuilder::all_build()?;
    let gix = GixBuilder::all_git()?;
    let cargo = CargoBuilder::all_cargo()?;
    Emitter::default()
        .add_instructions(&build)?
        .add_instructions(&gix)?
        .add_instructions(&cargo)?
        .emit()?;

    let mut config = Config::new();
    config.type_attribute(
        ".",
        "#[derive(serde::Serialize, serde::Deserialize)] #[serde(rename_all = \"snake_case\")]",
    );
    let descriptor_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap())
        .join("tuxtape_server_descriptor.bin");
    tonic_build::configure()
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos_with_config(config, &["proto/tuxtape_server.proto"], &["proto/"])?;

    Ok(())
}
