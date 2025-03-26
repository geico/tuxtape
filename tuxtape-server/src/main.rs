use clap::Parser;
use cli::Cli;
use color_eyre::{Result, eyre::eyre};

mod cli;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    // Attempt to connect to database and exit early and loudly if failed.
    let mut conn = tuxtape_database_bridge::connection::establish_connection(
        args.db_backend.into(),
        &args.db_url,
    )?;

    // Run any pending database migrations before proceeding.
    tuxtape_database_bridge::migration::run_pending_migrations(&mut conn).map_err(|e| eyre!(e))?;

    Ok(())
}
