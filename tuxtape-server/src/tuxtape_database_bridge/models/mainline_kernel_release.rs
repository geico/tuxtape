use sqlx::{FromRow, PgConnection, Result, Type};

#[derive(Debug, Type)]
pub struct MainlineKernelRelease {
    pub version_major: i32,
    pub version_minor: i32,
    pub version_patch: i32,
    pub version_extra: String,
}

impl MainlineKernelRelease {
    pub async fn insert(&self, conn: &mut PgConnection) -> Result<i32> {
        let mainline_kernel_release_id = sqlx::query!(
            r#"
            INSERT INTO mainline_kernel_release (version_major, version_minor, version_patch, version_extra)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (version_major, version_minor, version_patch, version_extra) DO UPDATE
                SET version_major = excluded.version_major
            RETURNING id
            "#,
            self.version_major,
            self.version_minor,
            self.version_patch,
            self.version_extra
        )
        .fetch_one(conn)
        .await?.id;

        Ok(mainline_kernel_release_id)
    }
}

#[derive(FromRow, Type)]
pub struct MainlineKernelReleaseRow {
    pub id: i32,
    pub version_major: i32,
    pub version_minor: i32,
    pub version_patch: i32,
    pub version_extra: String,
}

impl MainlineKernelReleaseRow {
    pub async fn fetch_one(id: i32, conn: &mut PgConnection) -> Result<Self> {
        sqlx::query_as!(
            MainlineKernelReleaseRow,
            r#"
            SELECT id, version_major, version_minor, version_patch, version_extra
            FROM mainline_kernel_release
            WHERE id = $1
            "#,
            id
        )
        .fetch_one(conn)
        .await
    }
}

impl From<MainlineKernelReleaseRow> for MainlineKernelRelease {
    fn from(row: MainlineKernelReleaseRow) -> Self {
        Self {
            version_major: row.version_major,
            version_minor: row.version_minor,
            version_patch: row.version_patch,
            version_extra: row.version_extra,
        }
    }
}
