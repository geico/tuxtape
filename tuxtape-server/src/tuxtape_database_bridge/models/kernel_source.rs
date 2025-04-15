use super::kernel_file::KernelFile;
use sqlx::{Acquire, FromRow, PgConnection, Result, Type};

pub struct KernelSource {
    pub url: String,
    pub files: Vec<KernelFile>,
}

impl KernelSource {
    pub async fn insert(&self, conn: &mut PgConnection) -> Result<i32> {
        let mut tx = conn.begin().await?;

        // TODO - add batch inserts (COPY) if performance lacking
        for file in self.files.iter() {
            file.insert(&mut tx).await?;
        }

        let kernel_source_id = sqlx::query!(
            r#"
            INSERT INTO kernel_source (url)
            VALUES ($1)
            RETURNING id
            "#,
            self.url
        )
        .fetch_one(&mut *tx)
        .await?
        .id;

        tx.commit().await?;

        Ok(kernel_source_id)
    }
}

#[derive(FromRow, Type)]
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
    }
}
