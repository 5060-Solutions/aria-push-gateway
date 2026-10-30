use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};

use crate::sip::SipAccountConfig;

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DeviceRecord {
    pub id: String,
    pub user_id: String,
    pub platform: String, // "ios" or "android"
    pub push_token: String,
    pub bundle_id: Option<String>,

    // SIP credentials (encrypted at rest in production)
    pub sip_username: String,
    pub sip_password: String,
    pub sip_domain: String,
    pub sip_registrar: Option<String>,
    pub sip_transport: String,
    pub sip_port: i64,
    pub sip_auth_username: Option<String>,
    pub sip_display_name: String,

    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_register_at: Option<DateTime<Utc>>,
}

impl DeviceRecord {
    pub fn sip_config(&self) -> SipAccountConfig {
        SipAccountConfig {
            username: self.sip_username.clone(),
            password: self.sip_password.clone(),
            domain: self.sip_domain.clone(),
            registrar: self.sip_registrar.clone(),
            transport: self.sip_transport.clone(),
            port: self.sip_port as u16,
            auth_username: self.sip_auth_username.clone(),
            display_name: self.sip_display_name.clone(),
        }
    }
}

impl Database {
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(url)
            .await?;
        Ok(Self { pool })
    }

    /// A private in-memory database (single connection, so it isn't lost).
    #[cfg(test)]
    pub async fn connect_in_memory() -> anyhow::Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect("sqlite::memory:")
            .await?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                platform TEXT NOT NULL CHECK(platform IN ('ios', 'android')),
                push_token TEXT NOT NULL,
                bundle_id TEXT,

                sip_username TEXT NOT NULL,
                sip_password TEXT NOT NULL,
                sip_domain TEXT NOT NULL,
                sip_registrar TEXT,
                sip_transport TEXT NOT NULL DEFAULT 'udp',
                sip_port INTEGER NOT NULL DEFAULT 5060,
                sip_auth_username TEXT,
                sip_display_name TEXT NOT NULL DEFAULT '',

                active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_register_at TIMESTAMP
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn upsert_device(&self, device: &DeviceRecord) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO devices (
                id, user_id, platform, push_token, bundle_id,
                sip_username, sip_password, sip_domain, sip_registrar,
                sip_transport, sip_port, sip_auth_username, sip_display_name,
                active, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                push_token = excluded.push_token,
                sip_username = excluded.sip_username,
                sip_password = excluded.sip_password,
                sip_domain = excluded.sip_domain,
                sip_registrar = excluded.sip_registrar,
                sip_transport = excluded.sip_transport,
                sip_port = excluded.sip_port,
                sip_auth_username = excluded.sip_auth_username,
                sip_display_name = excluded.sip_display_name,
                active = excluded.active,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&device.id)
        .bind(&device.user_id)
        .bind(&device.platform)
        .bind(&device.push_token)
        .bind(&device.bundle_id)
        .bind(&device.sip_username)
        .bind(&device.sip_password)
        .bind(&device.sip_domain)
        .bind(&device.sip_registrar)
        .bind(&device.sip_transport)
        .bind(device.sip_port)
        .bind(&device.sip_auth_username)
        .bind(&device.sip_display_name)
        .bind(device.active)
        .bind(device.created_at)
        .bind(device.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_device(&self, id: &str) -> anyhow::Result<Option<DeviceRecord>> {
        Ok(
            sqlx::query_as::<_, DeviceRecord>("SELECT * FROM devices WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// The caller's most recently updated active device registered for this
    /// SIP account (`sip_username` exact, `sip_domain` case-insensitive).
    pub async fn find_active_device_for_account(
        &self,
        user_id: &str,
        sip_username: &str,
        sip_domain: &str,
    ) -> anyhow::Result<Option<DeviceRecord>> {
        Ok(sqlx::query_as::<_, DeviceRecord>(
            "SELECT * FROM devices \
             WHERE user_id = ? AND sip_username = ? AND sip_domain = ? COLLATE NOCASE \
               AND active = TRUE \
             ORDER BY updated_at DESC LIMIT 1",
        )
        .bind(user_id)
        .bind(sip_username)
        .bind(sip_domain)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn list_active_devices(&self) -> anyhow::Result<Vec<DeviceRecord>> {
        Ok(
            sqlx::query_as::<_, DeviceRecord>("SELECT * FROM devices WHERE active = TRUE")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn deactivate_device(&self, id: &str) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE devices SET active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Update last_register_at timestamp for a device (heartbeat/keepalive).
    pub async fn touch_device(&self, id: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE devices SET last_register_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Deactivate `user_id`'s active devices with this push token, so one
    /// physical device isn't registered as several of the user's extensions.
    /// Other users' devices are never touched.
    pub async fn deactivate_user_devices_for_token(
        &self,
        user_id: &str,
        push_token: &str,
    ) -> anyhow::Result<u64> {
        if push_token.is_empty() {
            return Ok(0);
        }
        let rows = sqlx::query(
            "UPDATE devices SET active = FALSE, updated_at = CURRENT_TIMESTAMP \
             WHERE user_id = ? AND push_token = ? AND active = TRUE",
        )
        .bind(user_id)
        .bind(push_token)
        .execute(&self.pool)
        .await?;
        if rows.rows_affected() > 0 {
            tracing::info!(
                user = %user_id,
                deactivated = rows.rows_affected(),
                "deactivated old device registrations by push token"
            );
        }
        Ok(rows.rows_affected())
    }

    /// Deactivate `user_id`'s active devices for a SIP username. Called before
    /// registering a new device to prevent stale registrations. Other users'
    /// devices are never touched.
    pub async fn deactivate_user_devices_for_sip_user(
        &self,
        user_id: &str,
        sip_username: &str,
    ) -> anyhow::Result<u64> {
        let rows = sqlx::query(
            "UPDATE devices SET active = FALSE, updated_at = CURRENT_TIMESTAMP \
             WHERE user_id = ? AND sip_username = ? AND active = TRUE",
        )
        .bind(user_id)
        .bind(sip_username)
        .execute(&self.pool)
        .await?;
        if rows.rows_affected() > 0 {
            tracing::info!(
                user = %user_id,
                sip_user = %sip_username,
                deactivated = rows.rows_affected(),
                "deactivated old device registrations"
            );
        }
        Ok(rows.rows_affected())
    }

    /// How many active devices of users other than `user_id` carry this push
    /// token.
    pub async fn count_other_users_devices_for_token(
        &self,
        user_id: &str,
        push_token: &str,
    ) -> anyhow::Result<i64> {
        if push_token.is_empty() {
            return Ok(0);
        }
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM devices WHERE user_id <> ? AND push_token = ? AND active = TRUE",
        )
        .bind(user_id)
        .bind(push_token)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }
}
