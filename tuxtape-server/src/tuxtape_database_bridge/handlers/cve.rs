use crate::error::Result;
use proto::tuxtape::common::v1::Cve;
use sqlx::PgConnection;

pub async fn insert_proto(proto: &Cve, conn: &mut PgConnection) -> Result<i32> {
    let cve_id = sqlx::query!(
        r#"
            INSERT INTO cve (cve_id, base_score, attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact, description)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (cve_id) DO UPDATE
                SET cve_id = excluded.cve_id
            RETURNING id
        "#,
        proto.cve_id,
        proto.base_score,
        proto.attack_vector,
        proto.attack_complexity,
        proto.privileges_required,
        proto.user_interaction,
        proto.scope,
        proto.confidentiality_impact,
        proto.integrity_impact,
        proto.availability_impact,
        proto.description,
    )
    .fetch_one(conn)
    .await?
    .id;

    Ok(cve_id)
}
