pub mod database;
pub mod fleet_client;
pub mod registrar;

use sqlx::{PgPool, Postgres, pool::PoolConnection};
use tonic::Result;

pub async fn get_connection(pool: &PgPool) -> Result<PoolConnection<Postgres>> {
    pool.acquire().await.map_err(|e| {
        tonic::Status::internal(format!(
            "Failed to acquire connection from database pool: {}",
            e
        ))
    })
}
