use super::{Result, TestExt};
use crate::handlers;
use proto::tuxtape::common::v1::MainlineKernelRelease;
use sqlx::PgConnection;

impl TestExt for MainlineKernelRelease {
    async fn create_and_insert(amount: usize, conn: &mut PgConnection) -> Result<Vec<Self>> {
        let mut mainline_kernel_releases = (0..amount)
            .map(|i| {
                let major_version = (i % 3 + 5) as u32;
                let is_even = i % 2 == 0;

                MainlineKernelRelease {
                    id: None,
                    major_version,
                    minor_version: (i % 10) as u32,
                    patch_version: i as u32,
                    extra_version: if is_even {
                        format!("-rc{}", i % 10)
                    } else {
                        "".to_string()
                    },
                }
            })
            .collect::<Vec<_>>();

        for release in mainline_kernel_releases.iter_mut() {
            let id = handlers::mainline_kernel_release::insert_or_fetch(release, conn).await?;
            release.id = Some(id);
        }

        Ok(mainline_kernel_releases)
    }
}
