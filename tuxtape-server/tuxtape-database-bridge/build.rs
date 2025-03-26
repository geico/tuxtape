use dsync::{GenerationConfig, GenerationConfigOpts, TableOptions};
use std::path::PathBuf;
include!("src/connection.rs");

/// Generates model code into src/models
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = env!("CARGO_MANIFEST_DIR");

    dsync::generate_files(
        &PathBuf::from_iter([dir, "src/schema.rs"]),
        &PathBuf::from_iter([dir, "src/models"]),
        GenerationConfig {
            connection_type: "crate::connection::AnyConnection".to_string(),
            options: GenerationConfigOpts {
                default_table_options: TableOptions::default().disable_serde(),
                ..Default::default()
            },
        },
    )?;

    Ok(())
}
