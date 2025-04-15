use clap::Parser;
use std::net::SocketAddr;
use tonic::transport::{Identity, ServerTlsConfig};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// The URL to the Postgres database.
    /// This should be in the format:
    /// "postgres://user:pass@host/database"
    #[arg(short('d'), long, env = "DATABASE_URL", required = true)]
    pub db_url: String,
    /// The socket address for the gRPC server, either IPv4 or IPv6.
    #[arg(short('a'), long, default_value = "127.0.0.1:50051")]
    pub grpc_addr: SocketAddr,
    /// Enables TLS support.
    #[command(subcommand)]
    pub tls: Option<TlsCommand>,
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
