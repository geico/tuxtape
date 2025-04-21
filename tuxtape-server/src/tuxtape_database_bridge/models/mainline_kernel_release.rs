use crate::error::{DatabaseBridgeError, Result};
use proto::tuxtape::common::v1::MainlineKernelRelease as MainlineKernelReleaseProto;
use sqlx::PgConnection;

#[derive(Debug)]
pub struct MainlineKernelReleaseRow {
    pub id: i32,
    pub major_version: i32,
    pub minor_version: i32,
    pub patch_version: i32,
    pub extra_version: String,
}

impl MainlineKernelReleaseRow {
    pub async fn insert_or_fetch(
        proto: &MainlineKernelReleaseProto,
        conn: &mut PgConnection,
    ) -> Result<Self> {
        sqlx::query_as!(
            MainlineKernelReleaseRow,
            r#"
            INSERT INTO mainline_kernel_release (major_version, minor_version, patch_version, extra_version)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (major_version, minor_version, patch_version, extra_version) DO UPDATE
                SET major_version = excluded.major_version
            RETURNING *
            "#,
            proto.major_version as i32,
            proto.minor_version as i32,
            proto.patch_version as i32,
            proto.extra_version
        )
        .fetch_one(conn)
        .await
        .map_err(DatabaseBridgeError::from)
    }

    pub async fn fetch_one(id: i32, conn: &mut PgConnection) -> Result<Self> {
        sqlx::query_as!(
            MainlineKernelReleaseRow,
            r#"
            SELECT id, major_version, minor_version, patch_version, extra_version
            FROM mainline_kernel_release
            WHERE id = $1
            "#,
            id
        )
        .fetch_one(conn)
        .await
        .map_err(DatabaseBridgeError::from)
    }

    pub async fn fetch_from_proto(
        proto: &MainlineKernelReleaseProto,
        conn: &mut PgConnection,
    ) -> Result<Self> {
        sqlx::query_as!(
            MainlineKernelReleaseRow,
            r#"
            SELECT id, major_version, minor_version, patch_version, extra_version
            FROM mainline_kernel_release 
            WHERE major_version = $1
                AND minor_version = $2
                AND patch_version = $3
                AND extra_version = $4
            "#,
            proto.major_version as i32,
            proto.minor_version as i32,
            proto.patch_version as i32,
            proto.extra_version
        )
        .fetch_one(conn)
        .await
        .map_err(DatabaseBridgeError::from)
    }
}
