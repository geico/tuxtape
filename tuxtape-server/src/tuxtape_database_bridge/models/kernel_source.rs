use crate::error::{DatabaseBridgeError, Result};
use sqlx::PgConnection;

#[derive(Debug)]
pub struct KernelSourceRow {
    pub id: i32,
    pub kernel_release_id: i32,
    pub url: String,
}

impl KernelSourceRow {
    pub async fn fetch_one(id: i32, conn: &mut PgConnection) -> Result<Self> {
        sqlx::query_as!(
            KernelSourceRow,
            r#"
            SELECT id, kernel_release_id, url
            FROM kernel_source
            WHERE id = $1
            "#,
            id
        )
        .fetch_one(conn)
        .await
        .map_err(DatabaseBridgeError::from)
    }
}
