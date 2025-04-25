use sqlx::PgConnection;

mod cve;
mod kernel_release;
mod mainline_kernel_release;
mod vulnerability;
mod vulnerability_instance;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

trait TestExt {
    // Create a Vec of unique instances of the type implementing this trait and
    // insert them into the database.
    // Note: If called more than once, the overlap of amount `n` will be
    // the same.
    // e.g. Calling `create_and_insert(1)` and `create_and_insert(2)`
    // will be identical for the first value.
    async fn create_and_insert(amount: usize, conn: &mut PgConnection) -> Result<Vec<Self>>
    where
        Self: std::marker::Sized;
}
