// SPDX-License-Identifier: AGPL-3.0-or-later
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{path::Path, str::FromStr};

pub async fn open(path: &Path) -> anyhow::Result<SqlitePool> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if !path.exists() {
        let _ = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await?;
    migrate(&pool).await?;
    Ok(pool)
}

async fn migrate(pool: &SqlitePool) -> anyhow::Result<()> {
    let version = sqlx::query_scalar::<_, i64>("PRAGMA user_version")
        .fetch_one(pool)
        .await?;
    if version > 3 {
        anyhow::bail!("database schema is newer than this mb-print-cloud binary");
    }
    if version == 0 {
        let mut transaction = pool.begin().await?;
        for statement in SCHEMA.split(";\n").map(str::trim).filter(|s| !s.is_empty()) {
            sqlx::query(statement).execute(&mut *transaction).await?;
        }
        sqlx::query("PRAGMA user_version=1")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
    }
    if version < 2 {
        let mut transaction = pool.begin().await?;
        sqlx::query(
            "ALTER TABLE print_jobs ADD COLUMN last_completed_action INTEGER NOT NULL DEFAULT -1",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query("ALTER TABLE print_jobs ADD COLUMN action_count INTEGER NOT NULL DEFAULT 0")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("PRAGMA user_version=2")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
    }
    if version < 3 {
        let mut transaction = pool.begin().await?;
        for statement in [
            "ALTER TABLE print_jobs ADD COLUMN batch_item INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE print_jobs ADD COLUMN batch_items INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE print_jobs ADD COLUMN batch_copy INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE print_jobs ADD COLUMN batch_copies INTEGER NOT NULL DEFAULT 1",
        ] {
            sqlx::query(statement).execute(&mut *transaction).await?;
        }
        sqlx::query("PRAGMA user_version=3")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
    }
    Ok(())
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS printer_agents (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, display_name TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','active','revoked')),
 enrollment_hash BLOB, enrollment_expires_at INTEGER, enrollment_consumed_at INTEGER,
 created_by TEXT NOT NULL, protocol_version INTEGER, software_version TEXT,
 created_at INTEGER NOT NULL, last_connected_at INTEGER, last_heartbeat_at INTEGER,
 revoked_at INTEGER, last_error_code TEXT
);
CREATE TABLE IF NOT EXISTS agent_tokens (
 agent_id TEXT PRIMARY KEY REFERENCES printer_agents(id) ON DELETE CASCADE,
 tenant_id TEXT NOT NULL, token_hash BLOB NOT NULL, created_at INTEGER NOT NULL,
 last_used_at INTEGER, revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS printers (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, agent_id TEXT NOT NULL REFERENCES printer_agents(id) ON DELETE CASCADE,
 display_name TEXT NOT NULL, model TEXT NOT NULL, capabilities TEXT NOT NULL DEFAULT '{}',
 enabled INTEGER NOT NULL, online INTEGER NOT NULL, created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL, last_seen_at INTEGER
);
CREATE TABLE IF NOT EXISTS print_jobs (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, submitted_by TEXT NOT NULL, source TEXT NOT NULL,
 agent_id TEXT NOT NULL REFERENCES printer_agents(id), printer_id TEXT NOT NULL REFERENCES printers(id),
 request BLOB, payload_digest BLOB NOT NULL, idempotency_key TEXT NOT NULL, request_digest BLOB NOT NULL,
 state TEXT NOT NULL, terminal_outcome TEXT, progress INTEGER, action TEXT, bytes_sent INTEGER NOT NULL DEFAULT 0,
 total_bytes INTEGER NOT NULL DEFAULT 0, write_may_have_occurred INTEGER NOT NULL DEFAULT 0,
 cancellation_requested_at INTEGER, cancellation_requested_by TEXT, error_code TEXT,
 created_at INTEGER NOT NULL, delivered_at INTEGER, started_at INTEGER, terminal_at INTEGER,
 delete_payload_at INTEGER NOT NULL, UNIQUE(tenant_id,submitted_by,idempotency_key)
);
CREATE INDEX IF NOT EXISTS print_jobs_agent_pending ON print_jobs(agent_id,created_at)
 WHERE state IN ('queued','delivered','running')
"#;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn database_is_versioned_and_reopens_without_losing_rows() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cloud.sqlite3");
        let pool = super::open(&path).await.unwrap();
        sqlx::query("INSERT INTO printer_agents(id,tenant_id,display_name,state,enrollment_hash,enrollment_expires_at,created_by,created_at) VALUES('a','t','agent','pending',X'00',1,'user',1)")
            .execute(&pool).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA user_version")
                .fetch_one(&pool)
                .await
                .unwrap(),
            3
        );
        pool.close().await;
        let reopened = super::open(&path).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM printer_agents")
                .fetch_one(&reopened)
                .await
                .unwrap(),
            1
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o077,
                0
            );
        }
    }
}
