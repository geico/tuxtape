/* @generated and managed by dsync */

#[allow(unused)]
use crate::diesel::*;
use crate::models::vulnerability::Vulnerability;
use crate::schema::*;
use crate::models::common::*;

/// Struct representing a row in table `cve`
#[derive(Debug, Clone, diesel::Queryable, diesel::Selectable, diesel::QueryableByName, diesel::Associations, diesel::Identifiable)]
#[diesel(table_name=cve, primary_key(id), belongs_to(Vulnerability, foreign_key=vulnerability_id))]
pub struct Cve {
    /// Field representing column `id`
    pub id: i32,
    /// Field representing column `cve_id`
    pub cve_id: String,
    /// Field representing column `vulnerability_id`
    pub vulnerability_id: i32,
    /// Field representing column `base_score`
    pub base_score: Option<f32>,
    /// Field representing column `attack_vector`
    pub attack_vector: Option<String>,
    /// Field representing column `attack_complexity`
    pub attack_complexity: Option<String>,
    /// Field representing column `privileges_required`
    pub privileges_required: Option<String>,
    /// Field representing column `user_interaction`
    pub user_interaction: Option<String>,
    /// Field representing column `scope`
    pub scope: Option<String>,
    /// Field representing column `confidentiality_impact`
    pub confidentiality_impact: Option<String>,
    /// Field representing column `integrity_impact`
    pub integrity_impact: Option<String>,
    /// Field representing column `availability_impact`
    pub availability_impact: Option<String>,
    /// Field representing column `description`
    pub description: Option<String>,
}

/// Create Struct for a row in table `cve` for [`Cve`]
#[derive(Debug, Clone, diesel::Insertable)]
#[diesel(table_name=cve)]
pub struct CreateCve {
    /// Field representing column `id`
    pub id: i32,
    /// Field representing column `cve_id`
    pub cve_id: String,
    /// Field representing column `vulnerability_id`
    pub vulnerability_id: i32,
    /// Field representing column `base_score`
    pub base_score: Option<f32>,
    /// Field representing column `attack_vector`
    pub attack_vector: Option<String>,
    /// Field representing column `attack_complexity`
    pub attack_complexity: Option<String>,
    /// Field representing column `privileges_required`
    pub privileges_required: Option<String>,
    /// Field representing column `user_interaction`
    pub user_interaction: Option<String>,
    /// Field representing column `scope`
    pub scope: Option<String>,
    /// Field representing column `confidentiality_impact`
    pub confidentiality_impact: Option<String>,
    /// Field representing column `integrity_impact`
    pub integrity_impact: Option<String>,
    /// Field representing column `availability_impact`
    pub availability_impact: Option<String>,
    /// Field representing column `description`
    pub description: Option<String>,
}

/// Update Struct for a row in table `cve` for [`Cve`]
#[derive(Debug, Clone, diesel::AsChangeset, PartialEq, Default)]
#[diesel(table_name=cve)]
pub struct UpdateCve {
    /// Field representing column `cve_id`
    pub cve_id: Option<String>,
    /// Field representing column `vulnerability_id`
    pub vulnerability_id: Option<i32>,
    /// Field representing column `base_score`
    pub base_score: Option<Option<f32>>,
    /// Field representing column `attack_vector`
    pub attack_vector: Option<Option<String>>,
    /// Field representing column `attack_complexity`
    pub attack_complexity: Option<Option<String>>,
    /// Field representing column `privileges_required`
    pub privileges_required: Option<Option<String>>,
    /// Field representing column `user_interaction`
    pub user_interaction: Option<Option<String>>,
    /// Field representing column `scope`
    pub scope: Option<Option<String>>,
    /// Field representing column `confidentiality_impact`
    pub confidentiality_impact: Option<Option<String>>,
    /// Field representing column `integrity_impact`
    pub integrity_impact: Option<Option<String>>,
    /// Field representing column `availability_impact`
    pub availability_impact: Option<Option<String>>,
    /// Field representing column `description`
    pub description: Option<Option<String>>,
}

impl Cve {
    /// Insert a new row into `cve` with a given [`CreateCve`]
    pub fn create(db: &mut ConnectionType, item: &CreateCve) -> diesel::QueryResult<Self> {
        use crate::schema::cve::dsl::*;

        diesel::insert_into(cve).values(item).get_result::<Self>(db)
    }

    /// Get a row from `cve`, identified by the primary key
    pub fn read(db: &mut ConnectionType, param_id: i32) -> diesel::QueryResult<Self> {
        use crate::schema::cve::dsl::*;

        cve.filter(id.eq(param_id)).first::<Self>(db)
    }

    /// Update a row in `cve`, identified by the primary key with [`UpdateCve`]
    pub fn update(db: &mut ConnectionType, param_id: i32, item: &UpdateCve) -> diesel::QueryResult<Self> {
        use crate::schema::cve::dsl::*;

        diesel::update(cve.filter(id.eq(param_id))).set(item).get_result(db)
    }

    /// Delete a row in `cve`, identified by the primary key
    pub fn delete(db: &mut ConnectionType, param_id: i32) -> diesel::QueryResult<usize> {
        use crate::schema::cve::dsl::*;

        diesel::delete(cve.filter(id.eq(param_id))).execute(db)
    }
}
