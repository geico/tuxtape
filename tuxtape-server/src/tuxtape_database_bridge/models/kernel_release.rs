use super::{kernel_source::KernelSource, mainline_kernel_release::MainlineKernelRelease};
use sqlx::{Acquire, FromRow, PgConnection, Result, Type};

pub struct KernelRelease {
    pub mainline_kernel_release: MainlineKernelRelease,
    pub version_local: String,
    pub kernel_source: KernelSource,
}

impl KernelRelease {
    pub async fn insert(&self, conn: &mut PgConnection) -> Result<i32> {
        let mut tx = conn.begin().await?;

        let mainline_kernel_release_id = self.mainline_kernel_release.insert(&mut tx).await?;

        let id = sqlx::query!(
            r#"
            INSERT INTO kernel_release (mainline_kernel_release_id, version_local)
            VALUES ($1, $2)
            ON CONFLICT (mainline_kernel_release_id, version_local) DO UPDATE
                SET mainline_kernel_release_id = excluded.mainline_kernel_release_id
            RETURNING id
            "#,
            mainline_kernel_release_id,
            self.version_local
        )
        .fetch_one(&mut *tx)
        .await?
        .id;

        tx.commit().await?;

        Ok(id)
    }
}

#[derive(FromRow, Type)]
pub struct KernelReleaseRow {
    pub id: i32,
    pub mainline_kernel_release_id: i32,
    pub version_local: String,
}

impl KernelReleaseRow {
    pub async fn fetch_one(id: i32, conn: &mut PgConnection) -> Result<Self> {
        sqlx::query_as!(
            KernelReleaseRow,
            r#"
            SELECT id, mainline_kernel_release_id, version_local
            FROM kernel_release
            WHERE id = $1
            "#,
            id
        )
        .fetch_one(conn)
        .await
    }
}
