use crate::error::{DatabaseBridgeError, Result};
use sqlx::PgTransaction;

#[derive(Debug)]
pub struct KernelReleaseFileRow {
    pub id: i32,
    pub kernel_release_id: i32,
    pub kernel_file_id: i32,
}

impl KernelReleaseFileRow {
    pub async fn fetch_one(id: i32, tx: &mut PgTransaction<'_>) -> Result<Self> {
        sqlx::query_as!(
            KernelReleaseFileRow,
            r#"
            SELECT id, kernel_release_id, kernel_file_id
            FROM kernel_release_file
            WHERE id = $1
            "#,
            id
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(DatabaseBridgeError::from)
    }

    pub async fn fetch_all_by_kernel_release_id(
        kernel_release_id: i32,
        tx: &mut PgTransaction<'_>,
    ) -> Result<Vec<Self>> {
        sqlx::query_as!(
            KernelReleaseFileRow,
            r#"
            SELECT id, kernel_release_id, kernel_file_id
            FROM kernel_release_file
            WHERE kernel_release_id = $1
            "#,
            kernel_release_id
        )
        .fetch_all(&mut **tx)
        .await
        .map_err(DatabaseBridgeError::from)
    }

    pub async fn fetch_all_by_kernel_file_id(
        kernel_file_id: i32,
        tx: &mut PgTransaction<'_>,
    ) -> Result<Vec<Self>> {
        sqlx::query_as!(
            KernelReleaseFileRow,
            r#"
            SELECT id, kernel_release_id, kernel_file_id
            FROM kernel_release_file
            WHERE kernel_file_id = $1
            "#,
            kernel_file_id
        )
        .fetch_all(&mut **tx)
        .await
        .map_err(DatabaseBridgeError::from)
    }
}
