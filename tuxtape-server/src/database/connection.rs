use diesel::prelude::*;
use diesel::{Connection, MultiConnection, PgConnection, SqliteConnection};

/// The allowed database backends
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum DatabaseBackend {
    Pg,
    Sqlite,
}

/// A wrapper to support multiple database backends.
#[derive(MultiConnection)]
pub enum AnyConnection {
    Pg(diesel::PgConnection),
    Sqlite(diesel::SqliteConnection),
}

/// Establish a connection to a database backend.
pub fn establish_connection(
    backend: DatabaseBackend,
    database_url: &str,
) -> ConnectionResult<AnyConnection> {
    match backend {
        DatabaseBackend::Sqlite => {
            let sqlite_connection = SqliteConnection::establish(database_url)?;
            Ok(AnyConnection::Sqlite(sqlite_connection))
        }
        DatabaseBackend::Pg => {
            let pg_connection = PgConnection::establish(database_url)?;
            Ok(AnyConnection::Pg(pg_connection))
        }
    }
}
