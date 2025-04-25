use crate::error::Result;
use proto::tuxtape::common::v1::MainlineKernelRelease;
use sqlx::PgConnection;

pub async fn insert_proto(proto: &MainlineKernelRelease, conn: &mut PgConnection) -> Result<i32> {
    let mainline_kernel_release_id = sqlx::query!(
        r#"
        INSERT INTO mainline_kernel_release (major_version, minor_version, patch_version, extra_version)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (major_version, minor_version, patch_version, extra_version) DO UPDATE
            SET major_version = excluded.major_version
        RETURNING id
        "#,
        proto.major_version as i32,
        proto.minor_version as i32,
        proto.patch_version as i32,
        proto.extra_version
    )
    .fetch_one(conn)
    .await?
    .id;

    Ok(mainline_kernel_release_id)
}
