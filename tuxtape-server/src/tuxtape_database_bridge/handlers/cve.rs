use crate::error::Result;
use proto::tuxtape::common::v1::Cve;
use sqlx::PgConnection;

pub async fn insert_or_fetch(cve: &Cve, conn: &mut PgConnection) -> Result<i32> {
    let cve_id = sqlx::query!(
        r#"
            WITH ins AS (
                INSERT INTO cve (cve_id, base_score, attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact, description)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (cve_id) DO NOTHING
                RETURNING id
            )
            SELECT * FROM ins
            UNION
                SELECT id FROM cve WHERE cve_id=$1
        "#,
        cve.cve_id,
        cve.base_score,
        cve.attack_vector,
        cve.attack_complexity,
        cve.privileges_required,
        cve.user_interaction,
        cve.scope,
        cve.confidentiality_impact,
        cve.integrity_impact,
        cve.availability_impact,
        cve.description
    )
    .fetch_one(conn)
    .await?
    .id
    .expect("id will always exist in this case");

    Ok(cve_id)
}

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

impl From<CveRow> for Cve {
    fn from(value: CveRow) -> Self {
        Cve {
            id: Some(value.id),
            cve_id: value.cve_id,
            base_score: value.base_score,
            attack_vector: value.attack_vector,
            attack_complexity: value.attack_complexity,
            privileges_required: value.privileges_required,
            user_interaction: value.user_interaction,
            scope: value.scope,
            confidentiality_impact: value.confidentiality_impact,
            integrity_impact: value.integrity_impact,
            availability_impact: value.availability_impact,
            description: value.description,
        }
    }
}
