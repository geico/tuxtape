use sqlx::{FromRow, PgConnection, Result, Type};

use super::vulnerability_instance_affected_file::VulnerabilityInstanceAffectedFileRow;

#[derive(Debug, Type)]
pub struct KernelFile {
    pub file_path: String,
}

impl KernelFile {
    pub async fn insert(&self, conn: &mut PgConnection) -> Result<i32> {
        let kernel_file_id = sqlx::query!(
            r#"
            INSERT INTO kernel_file (file_path)
            VALUES ($1)
            ON CONFLICT (file_path) DO UPDATE
                SET file_path = excluded.file_path
            RETURNING id
            "#,
            self.file_path
        )
        .fetch_one(conn)
        .await?
        .id;

        Ok(kernel_file_id)
    }
}

impl From<KernelFileRow> for KernelFile {
    fn from(row: KernelFileRow) -> Self {
        KernelFile {
            file_path: row.file_path,
        }
    }
}

#[derive(FromRow, Type)]
pub struct KernelFileRow {
    pub id: i32,
    pub file_path: String,
}

impl KernelFileRow {
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
    }
}
