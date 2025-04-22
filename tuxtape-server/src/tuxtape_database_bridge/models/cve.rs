use crate::error::{DatabaseBridgeError, Result};
use proto::tuxtape::common::v1::Cve as CveProto;
use sqlx::PgTransaction;

#[derive(Debug)]
pub struct CveRow {
    pub id: i32,
    pub cve_id: String,
    pub base_score: Option<f32>,
    pub attack_vector: Option<String>,
    pub attack_complexity: Option<String>,
    pub privileges_required: Option<String>,
    pub user_interaction: Option<String>,
    pub scope: Option<String>,
    pub confidentiality_impact: Option<String>,
    pub integrity_impact: Option<String>,
    pub availability_impact: Option<String>,
    pub description: Option<String>,
}

impl CveRow {
    pub async fn insert_or_fetch(proto: &CveProto, tx: &mut PgTransaction<'_>) -> Result<Self> {
        sqlx::query_as!(
            CveRow,
            r#"
            INSERT INTO cve (cve_id, base_score, attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact, description)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (cve_id) DO UPDATE
                SET cve_id = excluded.cve_id
            RETURNING *
            "#,
            proto.id,
            proto.base_score,
            proto.attack_vector,
            proto.attack_complexity,
            proto.privileges_required,
            proto.user_interaction,
            proto.scope,
            proto.confidentiality_impact,
            proto.integrity_impact,
            proto.availability_impact,
            proto.description
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(DatabaseBridgeError::from)
    }

    pub async fn fetch_one(id: i32, tx: &mut PgTransaction<'_>) -> Result<Self> {
        sqlx::query_as!(
            CveRow,
            r#"
            SELECT * FROM cve WHERE id = $1
            "#,
            id
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(DatabaseBridgeError::from)
    }
}
