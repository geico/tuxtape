use crate::error::Result;
use proto::tuxtape::common::v1::KernelSource;
use sqlx::PgConnection;

pub async fn get_kernel_source(
    kernel_release_id: i32,
    conn: &mut PgConnection,
) -> Result<KernelSource> {
    let row = sqlx::query_as!(
        KernelSourceRow,
        r#"
        SELECT
            kr.id AS kernel_release_id,
            ks.url AS url
        FROM kernel_source ks
        JOIN kernel_release kr ON ks.kernel_release_id = kr.id
        WHERE kr.id = $1
        "#,
        kernel_release_id
    )
    .fetch_one(conn)
    .await?;

    Ok(KernelSource {
        kernel_release_id: Some(row.kernel_release_id),
        kernel_source_url: row.url,
    })
}

#[derive(sqlx::Decode)]
pub struct KernelSourceRow {
    kernel_release_id: i32,
    url: String,
}
