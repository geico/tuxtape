use crate::error::Result;
use proto::tuxtape::common::v1::MainlineKernelRelease;
use sqlx::PgConnection;

pub async fn insert_or_fetch(
    proto: &MainlineKernelRelease,
    conn: &mut PgConnection,
) -> Result<i32> {
    let mainline_kernel_release_id = sqlx::query!(
        r#"
        WITH ins AS (
            INSERT INTO mainline_kernel_release (major_version, minor_version, patch_version, extra_version)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (major_version, minor_version, patch_version, extra_version) DO NOTHING
            RETURNING id
        )
        SELECT * FROM ins
        UNION
            SELECT id FROM mainline_kernel_release WHERE major_version=$1 AND minor_version=$2 AND patch_version=$3 AND extra_version=$4
        "#,
        proto.major_version as i32,
        proto.minor_version as i32,
        proto.patch_version as i32,
        proto.extra_version
    )
    .fetch_one(conn)
    .await?
    .id.expect("id will always exist in this case");

    Ok(mainline_kernel_release_id)
}

#[derive(sqlx::Decode)]
pub struct MainlineKernelReleaseRow {
    pub id: i32,
    pub major_version: i32,
    pub minor_version: i32,
    pub patch_version: i32,
    pub extra_version: String,
}

impl From<MainlineKernelReleaseRow> for MainlineKernelRelease {
    fn from(value: MainlineKernelReleaseRow) -> Self {
        MainlineKernelRelease {
            id: Some(value.id),
            major_version: value.major_version as u32,
            minor_version: value.minor_version as u32,
            patch_version: value.patch_version as u32,
            extra_version: value.extra_version,
        }
    }
}
