use clap::Parser;
use cli::Cli;
use color_eyre::Result;
use database::connection;

mod cli;
mod database;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    // Attempt to connect to database and exit early and loudly if failed.
    connection::establish_connection(args.db_backend, &args.db_url)?;

    Ok(())
}
