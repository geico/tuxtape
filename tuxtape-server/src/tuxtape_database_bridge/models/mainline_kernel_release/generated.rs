/* @generated and managed by dsync */

#[allow(unused)]
use crate::diesel::*;
use crate::schema::*;
use crate::models::common::*;

/// Struct representing a row in table `mainline_kernel_release`
#[derive(Debug, Clone, diesel::Queryable, diesel::Selectable, diesel::QueryableByName, diesel::Identifiable)]
#[diesel(table_name=mainline_kernel_release, primary_key(id))]
pub struct MainlineKernelRelease {
    /// Field representing column `id`
    pub id: i32,
    /// Field representing column `version_major`
    pub version_major: i32,
    /// Field representing column `version_minor`
    pub version_minor: i32,
    /// Field representing column `version_patch`
    pub version_patch: i32,
    /// Field representing column `version_extra`
    pub version_extra: String,
}

/// Create Struct for a row in table `mainline_kernel_release` for [`MainlineKernelRelease`]
#[derive(Debug, Clone, diesel::Insertable)]
#[diesel(table_name=mainline_kernel_release)]
pub struct CreateMainlineKernelRelease {
    /// Field representing column `version_major`
    pub version_major: i32,
    /// Field representing column `version_minor`
    pub version_minor: i32,
    /// Field representing column `version_patch`
    pub version_patch: i32,
    /// Field representing column `version_extra`
    pub version_extra: String,
}

/// Update Struct for a row in table `mainline_kernel_release` for [`MainlineKernelRelease`]
#[derive(Debug, Clone, diesel::AsChangeset, PartialEq, Default)]
#[diesel(table_name=mainline_kernel_release)]
pub struct UpdateMainlineKernelRelease {
    /// Field representing column `version_major`
    pub version_major: Option<i32>,
    /// Field representing column `version_minor`
    pub version_minor: Option<i32>,
    /// Field representing column `version_patch`
    pub version_patch: Option<i32>,
    /// Field representing column `version_extra`
    pub version_extra: Option<String>,
}

impl MainlineKernelRelease {
    /// Insert a new row into `mainline_kernel_release` with a given [`CreateMainlineKernelRelease`]
    pub fn create(db: &mut ConnectionType, item: &CreateMainlineKernelRelease) -> diesel::QueryResult<Self> {
        use crate::schema::mainline_kernel_release::dsl::*;

        diesel::insert_into(mainline_kernel_release).values(item).get_result::<Self>(db)
    }

    /// Get a row from `mainline_kernel_release`, identified by the primary key
    pub fn read(db: &mut ConnectionType, param_id: i32) -> diesel::QueryResult<Self> {
        use crate::schema::mainline_kernel_release::dsl::*;

        mainline_kernel_release.filter(id.eq(param_id)).first::<Self>(db)
    }

    /// Update a row in `mainline_kernel_release`, identified by the primary key with [`UpdateMainlineKernelRelease`]
    pub fn update(db: &mut ConnectionType, param_id: i32, item: &UpdateMainlineKernelRelease) -> diesel::QueryResult<Self> {
        use crate::schema::mainline_kernel_release::dsl::*;

        diesel::update(mainline_kernel_release.filter(id.eq(param_id))).set(item).get_result(db)
    }

    /// Delete a row in `mainline_kernel_release`, identified by the primary key
    pub fn delete(db: &mut ConnectionType, param_id: i32) -> diesel::QueryResult<usize> {
        use crate::schema::mainline_kernel_release::dsl::*;

        diesel::delete(mainline_kernel_release.filter(id.eq(param_id))).execute(db)
    }
}
