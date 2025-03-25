use clap::Parser;
use std::net::SocketAddr;
use tonic::transport::{Identity, ServerTlsConfig};
use tuxtape_database_bridge::connection::DatabaseBackend;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// The URL to the database. If Postgres, this should be a web URL. If SQLite, this should be a
    /// path to the database file, either relative or absolute.
    #[arg(short('d'), long, default_value = concat!(env!("HOME"), "/.cache/tuxtape-server/db.db3"))]
    pub db_url: String,
    /// The database backend. If Postgres, this should "pg". If SQLite, this should be "sqlite".
    #[arg(short('b'), long, default_value = "sqlite")]
    pub db_backend: CliDatabaseBackend,
    /// The socket address for the gRPC server, either IPv4 or IPv6.
    #[arg(short('a'), long, default_value = "127.0.0.1:50051")]
    pub grpc_addr: SocketAddr,
    /// Enables TLS support.
    #[command(subcommand)]
    pub tls: Option<TlsCommand>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum CliDatabaseBackend {
    Pg,
    Sqlite,
}

impl From<CliDatabaseBackend> for DatabaseBackend {
    fn from(val: CliDatabaseBackend) -> Self {
        match val {
            CliDatabaseBackend::Pg => DatabaseBackend::Pg,
            CliDatabaseBackend::Sqlite => DatabaseBackend::Sqlite,
        }
    }
}

#[derive(clap::Subcommand, Clone, Debug)]
pub enum TlsCommand {
    UseTls(TlsArgs),
}

#[derive(clap::Args, Clone, Debug)]
pub struct TlsArgs {
    #[arg(long)]
    ca_path: String,
    #[arg(long)]
    cert_path: String,
    #[arg(long)]
    key_path: String,
}

impl From<TlsCommand> for ServerTlsConfig {
    fn from(value: TlsCommand) -> Self {
        match value {
            TlsCommand::UseTls(args) => {
                let identity = Identity::from_pem(args.cert_path, args.key_path);
                ServerTlsConfig::new().identity(identity)
            }
        }
    }
}
