use crate::error::{DatabaseBridgeError, Result};
use sqlx::PgConnection;

#[derive(Debug)]
pub struct MetaRow {
    pub id: i32,
    pub based_on_vulns_commit: String,
    pub last_run_unix_time: i32,
}

impl MetaRow {
    pub async fn fetch_one(id: i32, conn: &mut PgConnection) -> Result<Self> {
        sqlx::query_as!(
            MetaRow,
            r#"
            SELECT id, based_on_vulns_commit, last_run_unix_time
            FROM meta
            WHERE id = $1
            "#,
            id
        )
        .fetch_one(conn)
        .await
        .map_err(DatabaseBridgeError::from)
    }
}

pub struct Meta {
    pub based_on_vulns_commit: String,
    pub last_run_unix_time: i32,
}

impl Meta {
    pub async fn insert(&self, conn: &mut PgConnection) -> Result<i32> {
        let meta_id = sqlx::query!(
            r#"
            INSERT INTO meta (based_on_vulns_commit, last_run_unix_time)
            VALUES ($1, $2)
            RETURNING id
            "#,
            self.based_on_vulns_commit,
            self.last_run_unix_time
        )
        .fetch_one(conn)
        .await?
        .id;

        Ok(meta_id)
    }
}
