use crate::models::mainline_kernel_release::MainlineKernelReleaseRow;
use proto::tuxtape::common::v1::MainlineKernelRelease;

impl From<MainlineKernelReleaseRow> for MainlineKernelRelease {
    fn from(row: MainlineKernelReleaseRow) -> Self {
        Self {
            major_version: row.major_version as u32,
            minor_version: row.minor_version as u32,
            patch_version: row.patch_version as u32,
            extra_version: row.extra_version,
        }
    }
}
