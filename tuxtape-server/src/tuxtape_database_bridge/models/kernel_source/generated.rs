/* @generated and managed by dsync */

#[allow(unused)]
use crate::diesel::*;
use crate::models::kernel_release::KernelRelease;
use crate::schema::*;
use crate::models::common::*;

/// Struct representing a row in table `kernel_source`
#[derive(Debug, Clone, diesel::Queryable, diesel::Selectable, diesel::QueryableByName, diesel::Associations, diesel::Identifiable)]
#[diesel(table_name=kernel_source, primary_key(id), belongs_to(KernelRelease, foreign_key=kernel_release_id))]
pub struct KernelSource {
    /// Field representing column `id`
    pub id: i32,
    /// Field representing column `kernel_release_id`
    pub kernel_release_id: i32,
    /// Field representing column `url`
    pub url: String,
}

/// Create Struct for a row in table `kernel_source` for [`KernelSource`]
#[derive(Debug, Clone, diesel::Insertable)]
#[diesel(table_name=kernel_source)]
pub struct CreateKernelSource {
    /// Field representing column `id`
    pub id: i32,
    /// Field representing column `kernel_release_id`
    pub kernel_release_id: i32,
    /// Field representing column `url`
    pub url: String,
}

/// Update Struct for a row in table `kernel_source` for [`KernelSource`]
#[derive(Debug, Clone, diesel::AsChangeset, PartialEq, Default)]
#[diesel(table_name=kernel_source)]
pub struct UpdateKernelSource {
    /// Field representing column `kernel_release_id`
    pub kernel_release_id: Option<i32>,
    /// Field representing column `url`
    pub url: Option<String>,
}

impl KernelSource {
    /// Insert a new row into `kernel_source` with a given [`CreateKernelSource`]
    pub fn create(db: &mut ConnectionType, item: &CreateKernelSource) -> diesel::QueryResult<Self> {
        use crate::schema::kernel_source::dsl::*;

        diesel::insert_into(kernel_source).values(item).get_result::<Self>(db)
    }

    /// Get a row from `kernel_source`, identified by the primary key
    pub fn read(db: &mut ConnectionType, param_id: i32) -> diesel::QueryResult<Self> {
        use crate::schema::kernel_source::dsl::*;

        kernel_source.filter(id.eq(param_id)).first::<Self>(db)
    }

    /// Update a row in `kernel_source`, identified by the primary key with [`UpdateKernelSource`]
    pub fn update(db: &mut ConnectionType, param_id: i32, item: &UpdateKernelSource) -> diesel::QueryResult<Self> {
        use crate::schema::kernel_source::dsl::*;

        diesel::update(kernel_source.filter(id.eq(param_id))).set(item).get_result(db)
    }

    /// Delete a row in `kernel_source`, identified by the primary key
    pub fn delete(db: &mut ConnectionType, param_id: i32) -> diesel::QueryResult<usize> {
        use crate::schema::kernel_source::dsl::*;

        diesel::delete(kernel_source.filter(id.eq(param_id))).execute(db)
    }
}
