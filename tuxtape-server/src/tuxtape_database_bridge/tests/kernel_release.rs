use super::{Result, TestExt};
use crate::handlers;
use proto::tuxtape::common::v1::{KernelRelease, MainlineKernelRelease};
use sqlx::PgConnection;

impl TestExt for KernelRelease {
    async fn create_and_insert(amount: usize, conn: &mut PgConnection) -> Result<Vec<Self>> {
        let mainline_kernel_releases =
            MainlineKernelRelease::create_and_insert(amount, conn).await?;

        let mut kernel_releases = Vec::with_capacity(amount);
        for i in 0..amount {
            let mut kernel_release = KernelRelease {
                id: None,
                mainline_kernel_release: mainline_kernel_releases.get(i).cloned(),
                local_version: format!("release-{}", i),
            };

            let id = handlers::kernel_release::insert_or_fetch(&kernel_release, conn).await?;
            kernel_release.id = Some(id);

            kernel_releases.push(kernel_release);
        }

        Ok(kernel_releases)
    }
}
