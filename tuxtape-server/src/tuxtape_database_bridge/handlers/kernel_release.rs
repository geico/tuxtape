use crate::{
    error::{DatabaseBridgeError, Result},
    handlers::mainline_kernel_release,
};
use proto::tuxtape::{
    common::v1::{KernelRelease, MainlineKernelRelease},
    server::database::v1::get_affected_kernel_releases_response::AffectedKernelRelease,
};
use sqlx::{Acquire, PgConnection};
use std::collections::HashMap;

pub async fn get_affected_kernel_releases(
    vulnerability_instance_ids: &[i32],
    conn: &mut PgConnection,
) -> Result<Vec<AffectedKernelRelease>> {
    let rows = sqlx::query_as!(
        KernelReleaseRow,
        r#"
        SELECT
            kr.id,
            vi_id AS "vi_id!: i32",
            mkr.id AS mainline_kernel_release_id,
            mkr.major_version,
            mkr.minor_version,
            mkr.patch_version,
            mkr.extra_version,
            kr.local_version
        FROM kernel_release kr
        LEFT JOIN mainline_kernel_release mkr ON mkr.id = kr.mainline_kernel_release_id
        JOIN unnest($1::int[]) AS vi_id ON kernel_release_is_affected_by_vulnerability_instance(kr.id, vi_id)
        GROUP BY vi_id, mkr.id, kr.id
        "#,
        vulnerability_instance_ids
    )
    .fetch_all(conn)
    .await?;

    // Create mutable HashMap with all provided VulnerabilityInstance IDs to write
    // the affected kernel releases from the returned rows into.
    let mut affected_kernel_releases_map: HashMap<i32, Option<KernelRelease>> =
        vulnerability_instance_ids
            .iter()
            .map(|id| (*id, None))
            .collect();

    rows.into_iter().for_each(|row: KernelReleaseRow| {
        // Check if the row's vi_id is in the HashMap.
        if let Some(kr) = affected_kernel_releases_map.get_mut(&row.vi_id) {
            // If it is, set the value to the KernelRelease.
            kr.replace(KernelRelease::from(row));
        }
        // Else, the value remains None.
    });

    let affected_kernel_releases = affected_kernel_releases_map
        .iter()
        .map(|item| {
            let (vi_id, kernel_release) = item;
            AffectedKernelRelease {
                vulnerability_instance_id: *vi_id,
                kernel_release: kernel_release.clone(),
            }
        })
        .collect::<Vec<_>>();

    Ok(affected_kernel_releases)
}

pub async fn insert_or_fetch(
    kernel_release: &KernelRelease,
    conn: &mut PgConnection,
) -> Result<i32> {
    let mut tx = conn.begin().await?;

    let mainline_kernel_release_id =
        if let Some(mainline_kernel_release) = &kernel_release.mainline_kernel_release {
            mainline_kernel_release::insert_or_fetch(mainline_kernel_release, &mut tx).await?
        } else {
            return Err(DatabaseBridgeError::proto_missing_field(
                "mainline_kernel_release",
            ));
        };

    let id = sqlx::query!(
        r#"
        WITH ins AS (
            INSERT INTO kernel_release (mainline_kernel_release_id, local_version)
            VALUES ($1, $2)
            ON CONFLICT (mainline_kernel_release_id, local_version) DO NOTHING
            RETURNING id
        )
        SELECT * FROM ins
        UNION
            SELECT id FROM kernel_release WHERE mainline_kernel_release_id=$1 AND local_version=$2
        "#,
        mainline_kernel_release_id,
        kernel_release.local_version,
    )
    .fetch_one(&mut *tx)
    .await?
    .id
    .expect("id will always exist in this case");

    tx.commit().await?;

    Ok(id)
}

pub struct KernelReleaseRow {
    id: i32,
    vi_id: i32,
    mainline_kernel_release_id: i32,
    major_version: i32,
    minor_version: i32,
    patch_version: i32,
    extra_version: String,
    local_version: String,
}

impl From<KernelReleaseRow> for KernelRelease {
    fn from(value: KernelReleaseRow) -> Self {
        let mainline_kernel_release = Some(MainlineKernelRelease {
            id: Some(value.mainline_kernel_release_id),
            major_version: value.major_version as u32,
            minor_version: value.minor_version as u32,
            patch_version: value.patch_version as u32,
            extra_version: value.extra_version,
        });

        KernelRelease {
            id: Some(value.id),
            mainline_kernel_release,
            local_version: value.local_version,
        }
    }
}
