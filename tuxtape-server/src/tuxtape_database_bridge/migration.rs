use crate::connection::AnyConnection;
use diesel::migration::MigrationVersion;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

// Embed all migrations into the binary
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub type MigrationError =
    std::boxed::Box<(dyn std::error::Error + std::marker::Send + std::marker::Sync + 'static)>;

pub fn run_pending_migrations(
    conn: &mut AnyConnection,
) -> Result<Vec<MigrationVersion<'_>>, MigrationError> {
    conn.run_pending_migrations(MIGRATIONS)
}
