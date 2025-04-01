/* @generated and managed by dsync */

#[allow(unused)]
use crate::diesel::*;
use crate::schema::*;
use crate::models::common::*;

/// Struct representing a row in table `meta`
#[derive(Debug, Clone, diesel::Queryable, diesel::Selectable, diesel::QueryableByName, diesel::Identifiable)]
#[diesel(table_name=meta, primary_key(id))]
pub struct Meta {
    /// Field representing column `id`
    pub id: i32,
    /// Field representing column `based_on_vulns_commit`
    pub based_on_vulns_commit: String,
    /// Field representing column `last_run_unix_time`
    pub last_run_unix_time: i32,
}

/// Create Struct for a row in table `meta` for [`Meta`]
#[derive(Debug, Clone, diesel::Insertable)]
#[diesel(table_name=meta)]
pub struct CreateMeta {
    /// Field representing column `id`
    pub id: i32,
    /// Field representing column `based_on_vulns_commit`
    pub based_on_vulns_commit: String,
    /// Field representing column `last_run_unix_time`
    pub last_run_unix_time: i32,
}

/// Update Struct for a row in table `meta` for [`Meta`]
#[derive(Debug, Clone, diesel::AsChangeset, PartialEq, Default)]
#[diesel(table_name=meta)]
pub struct UpdateMeta {
    /// Field representing column `based_on_vulns_commit`
    pub based_on_vulns_commit: Option<String>,
    /// Field representing column `last_run_unix_time`
    pub last_run_unix_time: Option<i32>,
}

impl Meta {
    /// Insert a new row into `meta` with a given [`CreateMeta`]
    pub fn create(db: &mut ConnectionType, item: &CreateMeta) -> diesel::QueryResult<Self> {
        use crate::schema::meta::dsl::*;

        diesel::insert_into(meta).values(item).get_result::<Self>(db)
    }

    /// Get a row from `meta`, identified by the primary key
    pub fn read(db: &mut ConnectionType, param_id: i32) -> diesel::QueryResult<Self> {
        use crate::schema::meta::dsl::*;

        meta.filter(id.eq(param_id)).first::<Self>(db)
    }

    /// Update a row in `meta`, identified by the primary key with [`UpdateMeta`]
    pub fn update(db: &mut ConnectionType, param_id: i32, item: &UpdateMeta) -> diesel::QueryResult<Self> {
        use crate::schema::meta::dsl::*;

        diesel::update(meta.filter(id.eq(param_id))).set(item).get_result(db)
    }

    /// Delete a row in `meta`, identified by the primary key
    pub fn delete(db: &mut ConnectionType, param_id: i32) -> diesel::QueryResult<usize> {
        use crate::schema::meta::dsl::*;

        diesel::delete(meta.filter(id.eq(param_id))).execute(db)
    }
}
