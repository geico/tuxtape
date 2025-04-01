use diesel::prelude::*;
use diesel::{Connection, MultiConnection, PgConnection, SqliteConnection};

/// The allowed database backends
#[derive(Clone, Debug)]
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

/// The arguments required to form a database connection.
pub struct DatabaseConnectionDetails {
    pub backend: DatabaseBackend,
    pub db_url: String,
}

impl DatabaseConnectionDetails {
    pub fn new(backend: DatabaseBackend, db_url: &str) -> Self {
        DatabaseConnectionDetails {
            backend,
            db_url: db_url.to_string(),
        }
    }
}

/// Establish a connection to a database backend.
pub fn establish_connection(
    conn_details: &DatabaseConnectionDetails,
) -> ConnectionResult<AnyConnection> {
    match conn_details.backend {
        DatabaseBackend::Sqlite => {
            let sqlite_connection = SqliteConnection::establish(&conn_details.db_url)?;
            Ok(AnyConnection::Sqlite(sqlite_connection))
        }
        DatabaseBackend::Pg => {
            let pg_connection = PgConnection::establish(&conn_details.db_url)?;
            Ok(AnyConnection::Pg(pg_connection))
        }
    }
}
