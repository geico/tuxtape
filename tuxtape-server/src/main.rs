use clap::Parser;
use cli::Cli;
use color_eyre::{Result, eyre::eyre};
use grpc::server;
use std::sync::Arc;
use tuxtape_database_bridge::connection::DatabaseConnectionDetails;

mod cli;
mod grpc;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    // Attempt to connect to database and exit early and loudly if failed.
    let db_conn_details = Arc::new(DatabaseConnectionDetails::new(
        args.db_backend.into(),
        &args.db_url,
    ));

    let mut conn =
        tuxtape_database_bridge::connection::establish_connection(&db_conn_details.clone())?;

    // Run any pending database migrations before proceeding.
    tuxtape_database_bridge::migration::run_pending_migrations(&mut conn).map_err(|e| eyre!(e))?;

    loop {
        println!("Starting gRPC server at {}", args.grpc_addr);

        let _ = server::start_server(
            args.grpc_addr,
            args.tls.clone().map(|cmd| cmd.into()),
            db_conn_details.clone(),
        )
        .await
        .map_err(|e| eprintln!("gRPC server crashed: {e}"));

        // TODO - improve logging upon crash
    }
}
