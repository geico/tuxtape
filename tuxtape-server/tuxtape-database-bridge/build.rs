use dsync::{GenerationConfig, GenerationConfigOpts, TableOptions};
use std::{
    fs::{File, read_to_string},
    io::{Read, Write},
    path::Path,
};
include!("src/connection.rs");

/// Generates model code into src/models
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let input_diesel_schema_file_path = cargo_manifest_path.join("src/schema.rs");
    let generated_models_path = cargo_manifest_path.join("src/generated");
    let generated_models_mod_path = generated_models_path.join("mod.rs");

    dsync::generate_files(
        &input_diesel_schema_file_path,
        &generated_models_path,
        GenerationConfig {
            connection_type: "crate::connection::AnyConnection".to_string(),
            options: GenerationConfigOpts {
                default_table_options: TableOptions::default().disable_serde(),
                ..Default::default()
            },
        },
    )?;

    // `dsync` is a bit domain-specific and seems to not expect generated models
    // to be extended. If we want to publicly expose the generated models via
    // a manually-written `models` module, `cargo` shows warnings for unused
    // code.
    // The following prepends the generated `src/generated/mod.rs` with a flag
    // to disable this warning.
    if let Some(mod_first_line) = read_to_string(&generated_models_mod_path)?.lines().next() {
        if mod_first_line != "#![allow(dead_code)]" {
            prepend_allow_dead_code(&generated_models_mod_path)?
        }
    }

    Ok(())
}

// Based on https://stackoverflow.com/a/72947912
fn prepend_allow_dead_code<P: AsRef<Path> + ?Sized>(
    path: &P,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = b"#![allow(dead_code)]\n".to_vec();

    let mut f = File::open(path)?;
    let mut content = data.to_owned();
    f.read_to_end(&mut content)?;

    let mut f = File::create(path)?;
    f.write_all(content.as_slice())?;

    Ok(())
}
