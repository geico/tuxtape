/* @generated and managed by dsync */

#[allow(unused)]
use crate::diesel::*;
use crate::models::kernel_release::KernelRelease;
use crate::schema::*;
use crate::models::common::*;

/// Struct representing a row in table `kernel_file`
#[derive(Debug, Clone, diesel::Queryable, diesel::Selectable, diesel::QueryableByName, diesel::Associations, diesel::Identifiable)]
#[diesel(table_name=kernel_file, primary_key(id), belongs_to(KernelRelease, foreign_key=kernel_release_id))]
pub struct KernelFile {
    /// Field representing column `id`
    pub id: i32,
    /// Field representing column `kernel_release_id`
    pub kernel_release_id: i32,
    /// Field representing column `file_path`
    pub file_path: String,
}

/// Create Struct for a row in table `kernel_file` for [`KernelFile`]
#[derive(Debug, Clone, diesel::Insertable)]
#[diesel(table_name=kernel_file)]
pub struct CreateKernelFile {
    /// Field representing column `kernel_release_id`
    pub kernel_release_id: i32,
    /// Field representing column `file_path`
    pub file_path: String,
}

/// Update Struct for a row in table `kernel_file` for [`KernelFile`]
#[derive(Debug, Clone, diesel::AsChangeset, PartialEq, Default)]
#[diesel(table_name=kernel_file)]
pub struct UpdateKernelFile {
    /// Field representing column `kernel_release_id`
    pub kernel_release_id: Option<i32>,
    /// Field representing column `file_path`
    pub file_path: Option<String>,
}

impl KernelFile {
    /// Insert a new row into `kernel_file` with a given [`CreateKernelFile`]
    pub fn create(db: &mut ConnectionType, item: &CreateKernelFile) -> diesel::QueryResult<Self> {
        use crate::schema::kernel_file::dsl::*;

        diesel::insert_into(kernel_file).values(item).get_result::<Self>(db)
    }

    /// Get a row from `kernel_file`, identified by the primary key
    pub fn read(db: &mut ConnectionType, param_id: i32) -> diesel::QueryResult<Self> {
        use crate::schema::kernel_file::dsl::*;

        kernel_file.filter(id.eq(param_id)).first::<Self>(db)
    }

    /// Update a row in `kernel_file`, identified by the primary key with [`UpdateKernelFile`]
    pub fn update(db: &mut ConnectionType, param_id: i32, item: &UpdateKernelFile) -> diesel::QueryResult<Self> {
        use crate::schema::kernel_file::dsl::*;

        diesel::update(kernel_file.filter(id.eq(param_id))).set(item).get_result(db)
    }

    /// Delete a row in `kernel_file`, identified by the primary key
    pub fn delete(db: &mut ConnectionType, param_id: i32) -> diesel::QueryResult<usize> {
        use crate::schema::kernel_file::dsl::*;

        diesel::delete(kernel_file.filter(id.eq(param_id))).execute(db)
    }
}
