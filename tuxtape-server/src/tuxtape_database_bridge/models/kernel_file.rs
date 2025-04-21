use crate::error::{DatabaseBridgeError, Result};
use sqlx::PgConnection;

#[derive(Debug)]
pub struct KernelFileRow {
    pub id: i32,
    pub file_path: String,
}

impl KernelFileRow {
    pub async fn insert_or_fetch(file_path: &str, conn: &mut PgConnection) -> Result<Self> {
        sqlx::query_as!(
            KernelFileRow,
            r#"
            INSERT INTO kernel_file (file_path)
            VALUES ($1)
            ON CONFLICT (file_path) DO UPDATE
                SET file_path = excluded.file_path
            RETURNING *
            "#,
            file_path
        )
        .fetch_one(conn)
        .await
        .map_err(DatabaseBridgeError::from)
    }

    pub async fn fetch_one(id: i32, conn: &mut PgConnection) -> Result<Self> {
        sqlx::query_as!(
            KernelFileRow,
            r#"
            SELECT id, file_path
            FROM kernel_file
            WHERE id = $1
            "#,
            id
        )
        .fetch_one(conn)
        .await
        .map_err(DatabaseBridgeError::from)
    }

    pub async fn fetch_many(ids: &[i32], conn: &mut PgConnection) -> Result<Vec<Self>> {
        sqlx::query_as!(
            KernelFileRow,
            r#"
            SELECT id, file_path
            FROM kernel_file
            WHERE id = ANY($1)
            "#,
            ids
        )
        .fetch_all(conn)
        .await
        .map_err(DatabaseBridgeError::from)
    }

    pub async fn fetch_by_file_path(file_path: &str, conn: &mut PgConnection) -> Result<Self> {
        sqlx::query_as!(
            KernelFileRow,
            r#"
            SELECT id, file_path
            FROM kernel_file
            WHERE file_path = $1
            "#,
            file_path
        )
        .fetch_one(conn)
        .await
        .map_err(DatabaseBridgeError::from)
    }
}
