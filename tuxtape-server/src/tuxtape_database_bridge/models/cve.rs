use sqlx::{FromRow, PgConnection, Postgres, QueryBuilder, Result, Type, query::Query};

#[derive(Debug)]
pub struct Cve {
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

impl Cve {
    pub async fn insert(&self, conn: &mut PgConnection) -> Result<i32> {
        let cve_id = sqlx::query!(
            r#"
            INSERT INTO cve (cve_id, base_score, attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact, description)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (cve_id) DO UPDATE
                SET cve_id = excluded.cve_id
            RETURNING id
            "#,
            self.cve_id,
            self.base_score,
            self.attack_vector,
            self.attack_complexity,
            self.privileges_required,
            self.user_interaction,
            self.scope,
            self.confidentiality_impact,
            self.integrity_impact,
            self.availability_impact,
            self.description
        )
        .fetch_one(conn)
        .await?
        .id;

        Ok(cve_id)
    }
}

#[derive(FromRow, Type, Debug)]
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
    pub async fn fetch_one(id: i32, conn: &mut PgConnection) -> Result<Self> {
        sqlx::query_as!(
            CveRow,
            r#"
            SELECT * FROM cve WHERE id = $1
            "#,
            id
        )
        .fetch_one(conn)
        .await
    }
}

impl From<CveRow> for Cve {
    fn from(row: CveRow) -> Self {
        Self {
            cve_id: row.cve_id,
            base_score: row.base_score,
            attack_vector: row.attack_vector,
            attack_complexity: row.attack_complexity,
            privileges_required: row.privileges_required,
            user_interaction: row.user_interaction,
            scope: row.scope,
            confidentiality_impact: row.confidentiality_impact,
            integrity_impact: row.integrity_impact,
            availability_impact: row.availability_impact,
            description: row.description,
        }
    }
}
