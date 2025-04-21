use crate::error::{DatabaseBridgeError, Result};
use proto::tuxtape::common::v1::KernelRelease as KernelReleaseProto;
use sqlx::PgConnection;

use super::mainline_kernel_release::MainlineKernelReleaseRow;

#[derive(Debug)]
pub struct KernelReleaseRow {
    pub id: i32,
    pub mainline_kernel_release_id: i32,
    pub local_version: String,
}

impl KernelReleaseRow {
    pub async fn fetch_one(id: i32, conn: &mut PgConnection) -> Result<Self> {
        sqlx::query_as!(
            KernelReleaseRow,
            r#"
            SELECT id, mainline_kernel_release_id, local_version
            FROM kernel_release
            WHERE id = $1
            "#,
            id
        )
        .fetch_one(conn)
        .await
        .map_err(DatabaseBridgeError::from)
    }

    pub async fn fetch_many(ids: &[i32], conn: &mut PgConnection) -> Result<Vec<Self>> {
        sqlx::query_as!(
            KernelReleaseRow,
            r#"
            SELECT id, mainline_kernel_release_id, local_version
            FROM kernel_release
            WHERE id = ANY($1)
            "#,
            ids
        )
        .fetch_all(conn)
        .await
        .map_err(DatabaseBridgeError::from)
    }

    pub async fn fetch_affected_by_vulnerability_instance(
        vulnerability_instance_id: i32,
        conn: &mut PgConnection,
    ) -> Result<Vec<Self>> {
        sqlx::query_as!(
            KernelReleaseRow,
            r#"
            SELECT *
            FROM kernel_release
            WHERE kernel_release_is_affected_by_vulnerability_instance(kernel_release.id, $1)
            "#,
            vulnerability_instance_id
        )
        .fetch_all(conn)
        .await
        .map_err(DatabaseBridgeError::from)
    }

    pub async fn fetch_from_protos(
        protos: &[KernelReleaseProto],
        conn: &mut PgConnection,
    ) -> Result<Vec<Self>> {
        let mut kernel_release_rows = Vec::with_capacity(protos.len());

        for proto in protos {
            let mainline_kernel_release_proto =
                if let Some(mainline_kernel_release) = &proto.mainline_kernel_release {
                    mainline_kernel_release
                } else {
                    return Err(DatabaseBridgeError::proto_missing_field(
                        "mainline_kernel_release",
                    ));
                };

            let mainline_kernel_release = MainlineKernelReleaseRow::fetch_from_proto(
                mainline_kernel_release_proto,
                &mut *conn,
            )
            .await?;

            let kernel_release_row = sqlx::query_as!(
                KernelReleaseRow,
                r#"
                SELECT id, mainline_kernel_release_id, local_version
                FROM kernel_release
                WHERE mainline_kernel_release_id = $1 AND local_version = $2
                "#,
                mainline_kernel_release.id,
                proto.local_version
            )
            .fetch_one(&mut *conn)
            .await?;

            kernel_release_rows.push(kernel_release_row);
        }

        Ok(kernel_release_rows)
    }
}
