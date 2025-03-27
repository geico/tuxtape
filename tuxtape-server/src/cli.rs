use clap::Parser;
use tuxtape_database_bridge::connection::DatabaseBackend;

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
}
