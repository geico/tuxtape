use crate::{error::Result, handlers::kernel_release};
use proto::tuxtape::common::v1::{KernelRelease, KernelSource};
use sqlx::{Acquire, PgConnection};

pub async fn create_kernel(
    kernel_release: &KernelRelease,
    kernel_source: &KernelSource,
    conn: &mut PgConnection,
) -> Result<()> {
    let mut tx = conn.begin().await?;

    let kernel_release_id = kernel_release::insert_or_fetch(kernel_release, &mut tx).await?;

    sqlx::query!(
        r#"
            INSERT INTO kernel_source (kernel_release_id, url)
            VALUES ($1, $2)
        "#,
        kernel_release_id,
        kernel_source.kernel_source_url,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(())
}
