use crate::{
    error::Result,
    models::{kernel_release::KernelReleaseRow, mainline_kernel_release::MainlineKernelReleaseRow},
};
use proto::tuxtape::common::v1::KernelRelease;
use sqlx::PgTransaction;

pub async fn fetch_from_row(
    kernel_release_row: &KernelReleaseRow,
    tx: &mut PgTransaction<'_>,
) -> Result<KernelRelease> {
    let mainline_kernel_release = Some(
        MainlineKernelReleaseRow::fetch_one(kernel_release_row.mainline_kernel_release_id, tx)
            .await?
            .into(),
    );

    Ok(KernelRelease {
        mainline_kernel_release,
        local_version: kernel_release_row.local_version.clone(),
    })
}
