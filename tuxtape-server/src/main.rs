use clap::Parser;
use cli::Cli;
use color_eyre::{Result, eyre::eyre};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

mod cli;
mod database;

// Embed all migrations into the binary
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    {
        // Attempt to connect to database and exit early and loudly if failed.
        let mut conn = database::connection::establish_connection(args.db_backend, &args.db_url)?;

        // Run any pending database migrations before proceeding.
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| eyre!(e))?;
    }

    Ok(())
}
