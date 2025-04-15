use clap::Parser;
use cli::Cli;
use color_eyre::Result;
use grpc::server;
use sqlx::{PgPool, migrate::Migrator};

// Embed all migrations into the binary
static MIGRATOR: Migrator = sqlx::migrate!();

mod cli;
mod grpc;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    // Attempt to connect to database and exit early and loudly if failed
    // Note: The Pool type is wrapped in an Arc, so cloning this only increases
    // the ref count.
    let db_pool = PgPool::connect(&args.db_url).await?;

    // Run pending migrations
    MIGRATOR.run(&db_pool).await?;

    loop {
        println!("Starting gRPC server at {}", args.grpc_addr);

        let _ = server::start_server(
            args.grpc_addr,
            args.tls.clone().map(|cmd| cmd.into()),
            &db_pool,
        )
        .await
        .map_err(|e| eprintln!("gRPC server crashed: {e}"));

        // TODO - improve logging upon crash
    }
}
