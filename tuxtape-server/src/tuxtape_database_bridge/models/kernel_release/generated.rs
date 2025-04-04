/* @generated and managed by dsync */

#[allow(unused)]
use crate::diesel::*;
use crate::models::mainline_kernel_release::MainlineKernelRelease;
use crate::schema::*;
use crate::models::common::*;

/// Struct representing a row in table `kernel_release`
#[derive(Debug, Clone, diesel::Queryable, diesel::Selectable, diesel::QueryableByName, diesel::Associations, diesel::Identifiable)]
#[diesel(table_name=kernel_release, primary_key(id), belongs_to(MainlineKernelRelease, foreign_key=mainline_kernel_release_id))]
pub struct KernelRelease {
    /// Field representing column `id`
    pub id: i32,
    /// Field representing column `mainline_kernel_release_id`
    pub mainline_kernel_release_id: i32,
    /// Field representing column `version_local`
    pub version_local: Option<String>,
}

/// Create Struct for a row in table `kernel_release` for [`KernelRelease`]
#[derive(Debug, Clone, diesel::Insertable)]
#[diesel(table_name=kernel_release)]
pub struct CreateKernelRelease {
    /// Field representing column `mainline_kernel_release_id`
    pub mainline_kernel_release_id: i32,
    /// Field representing column `version_local`
    pub version_local: Option<String>,
}

/// Update Struct for a row in table `kernel_release` for [`KernelRelease`]
#[derive(Debug, Clone, diesel::AsChangeset, PartialEq, Default)]
#[diesel(table_name=kernel_release)]
pub struct UpdateKernelRelease {
    /// Field representing column `mainline_kernel_release_id`
    pub mainline_kernel_release_id: Option<i32>,
    /// Field representing column `version_local`
    pub version_local: Option<Option<String>>,
}

impl KernelRelease {
    /// Insert a new row into `kernel_release` with a given [`CreateKernelRelease`]
    pub fn create(db: &mut ConnectionType, item: &CreateKernelRelease) -> diesel::QueryResult<Self> {
        use crate::schema::kernel_release::dsl::*;

        diesel::insert_into(kernel_release).values(item).get_result::<Self>(db)
    }

    /// Get a row from `kernel_release`, identified by the primary key
    pub fn read(db: &mut ConnectionType, param_id: i32) -> diesel::QueryResult<Self> {
        use crate::schema::kernel_release::dsl::*;

        kernel_release.filter(id.eq(param_id)).first::<Self>(db)
    }

    /// Update a row in `kernel_release`, identified by the primary key with [`UpdateKernelRelease`]
    pub fn update(db: &mut ConnectionType, param_id: i32, item: &UpdateKernelRelease) -> diesel::QueryResult<Self> {
        use crate::schema::kernel_release::dsl::*;

        diesel::update(kernel_release.filter(id.eq(param_id))).set(item).get_result(db)
    }

    /// Delete a row in `kernel_release`, identified by the primary key
    pub fn delete(db: &mut ConnectionType, param_id: i32) -> diesel::QueryResult<usize> {
        use crate::schema::kernel_release::dsl::*;

        diesel::delete(kernel_release.filter(id.eq(param_id))).execute(db)
    }
}
