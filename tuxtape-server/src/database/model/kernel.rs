use crate::database::schema;
use diesel::prelude::*;
use diesel_attributes::*;

#[diesel_model_fetch(schema::kernel_file)]
#[diesel(belongs_to(KernelRelease))]
pub struct KernelFile {
    pub id: i32,
    pub kernel_release_id: i32,
    pub file_path: String,
}

#[diesel_model_insert(schema::kernel_file)]
pub struct InsertKernelFile<'a> {
    pub kernel_release_id: i32,
    pub file_path: &'a str,
}

#[diesel_model_update(schema::kernel_file)]
pub struct UpdateKernelFile<'a> {
    pub kernel_release_id: Option<i32>,
    pub file_path: Option<&'a str>,
}

#[diesel_model_fetch(schema::kernel_release)]
#[diesel(belongs_to(MainlineKernelRelease))]
pub struct KernelRelease {
    pub id: i32,
    pub mainline_kernel_release_id: i32,
    pub version_local: Option<String>,
}

#[diesel_model_insert(schema::kernel_release)]
pub struct InsertKernelRelease<'a> {
    pub mainline_kernel_release_id: i32,
    pub version_local: Option<&'a str>,
}

#[diesel_model_update(schema::kernel_release)]
pub struct UpdateKernelRelease<'a> {
    pub mainline_kernel_release_id: Option<i32>,
    pub version_local: Option<Option<&'a str>>,
}

#[diesel_model_fetch(schema::mainline_kernel_release)]
pub struct MainlineKernelRelease {
    pub id: i32,
    pub version_major: i32,
    pub version_minor: i32,
    pub version_patch: i32,
    pub version_extra: String,
}

#[diesel_model_insert(schema::mainline_kernel_release)]
pub struct InsertMainlineKernelRelease<'a> {
    pub version_major: i32,
    pub version_minor: i32,
    pub version_patch: i32,
    pub version_extra: &'a str,
}

#[diesel_model_update(schema::mainline_kernel_release)]
pub struct UpdateMainlineKernelRelease<'a> {
    pub version_major: Option<i32>,
    pub version_minor: Option<i32>,
    pub version_patch: Option<i32>,
    pub version_extra: Option<&'a str>,
}

#[diesel_model_fetch(schema::kernel_source)]
#[diesel(belongs_to(KernelRelease))]
pub struct KernelSource {
    pub id: i32,
    pub kernel_release_id: i32,
    pub url: String,
}

#[diesel_model_insert(schema::kernel_source)]
pub struct InsertKernelSource<'a> {
    pub kernel_release_id: i32,
    pub url: &'a str,
}

#[diesel_model_update(schema::kernel_source)]
pub struct UpdateKernelSource<'a> {
    pub kernel_release_id: Option<i32>,
    pub url: Option<&'a str>,
}
