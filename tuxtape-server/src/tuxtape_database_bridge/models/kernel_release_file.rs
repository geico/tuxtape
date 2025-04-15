use sqlx::{FromRow, PgConnection, Result, Type};

#[derive(FromRow, Type)]
pub struct KernelReleaseFileRow {
    pub id: i32,
    pub kernel_release_id: i32,
    pub kernel_file_id: i32,
}

impl KernelReleaseFileRow {
    pub async fn fetch_one(id: i32, conn: &mut PgConnection) -> Result<Self> {
        sqlx::query_as!(
            KernelReleaseFileRow,
            r#"
            SELECT id, kernel_release_id, kernel_file_id
            FROM kernel_release_file
            WHERE id = $1
            "#,
            id
        )
        .fetch_one(conn)
        .await
    }
}
