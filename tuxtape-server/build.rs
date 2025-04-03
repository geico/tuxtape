use dsync::{GenerationConfig, GenerationConfigOpts, TableOptions};
use std::path::Path;

/// Generates model code into src/models
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tuxtape_database_bridge_path = cargo_manifest_path.join("src/tuxtape_database_bridge");
    let input_diesel_schema_file_path = tuxtape_database_bridge_path.join("schema.rs");
    let generated_models_path = tuxtape_database_bridge_path.join("models");

    dsync::generate_files(
        &input_diesel_schema_file_path,
        &generated_models_path,
        GenerationConfig {
            connection_type: "crate::connection::AnyConnection".to_string(),
            options: GenerationConfigOpts {
                default_table_options: TableOptions::default().disable_serde(),
                once_common_structs: true,
                once_connection_type: true,
                ..Default::default()
            },
        },
    )?;

    Ok(())
}
