use crate::{
    into_sn_err, sn_err, SNDeviceInfo, SNUserInfo, SnClearStateResult, SnDB, SnDBFactory, SnDBRef,
    SnErrorCode, SnResult, SnV2AuthInfo, UserState,
};
use cyfs_gateway_lib::{into_server_err, ServerErrorCode, ServerResult};
use rand::Rng;
use serde::Deserialize;
use sfo_sql::mysql::sql_query;
use sfo_sql::sqlite::{SqlPool, SqliteJournalMode};
use sfo_sql::Row;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SqliteSnDB {
    pool: SqlPool,
}

impl SqliteSnDB {
    const USER_DOMAIN_BINDING_LOCK: &'static str = "sn_user_domain_binding";

    pub async fn new() -> SnResult<SqliteSnDB> {
        //获得当前可执行文件所在的目录
        let base_dir = PathBuf::from(std::env::current_exe().unwrap().parent().unwrap());
        let db_path = base_dir.join("sn_db.sqlite3");

        Self::new_by_path(db_path.to_string_lossy().to_string().as_str()).await
    }

    pub async fn new_by_path(path: &str) -> SnResult<SqliteSnDB> {
        let pool = SqlPool::open(
            format!("sqlite://{}", path).as_str(),
            8,
            Some(SqliteJournalMode::Wal),
        )
        .await
        .map_err(into_sn_err!(SnErrorCode::DBError, "open file: {:?}", path))?;
        Ok(SqliteSnDB { pool })
    }

    pub async fn initialize_database(&self) -> SnResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(sql_query(
            "CREATE TABLE IF NOT EXISTS activation_codes (code TEXT PRIMARY KEY, used INTEGER)",
        ))
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create activation_codes table failed"
        ))?;
        conn.execute_sql(sql_query("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, state TEXT, public_key TEXT, activation_code TEXT, zone_config TEXT, self_cert boolean, user_domain TEXT, sn_ips TEXT)")).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "create users table failed"))?;
        conn.execute_sql(sql_query("CREATE TABLE IF NOT EXISTS user_auth_v2 (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, password_algo TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_login_at INTEGER NULL)")).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "create user_auth_v2 table failed"))?;
        conn.execute_sql(sql_query("CREATE TABLE IF NOT EXISTS devices (owner TEXT, device_name TEXT, did TEXT PRIMARY KEY, ip TEXT, description TEXT, mini_config_jwt TEXT, created_at INTEGER, updated_at INTEGER)")).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "create devices table failed"))?;
        conn.execute_sql(sql_query("DELETE FROM devices WHERE rowid NOT IN (SELECT rowid FROM devices d1 WHERE rowid = (SELECT rowid FROM devices d2 WHERE d2.owner = d1.owner AND d2.device_name = d1.device_name ORDER BY d2.updated_at DESC, d2.created_at DESC, d2.rowid DESC LIMIT 1))")).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "deduplicate devices by owner and device_name failed"))?;
        conn.execute_sql(sql_query("CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_owner_device_name ON devices (owner, device_name)")).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "create unique index on devices owner and device_name failed"))?;
        conn.execute_sql(sql_query("CREATE TABLE IF NOT EXISTS user_dns_records (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, domain TEXT, record_type TEXT, record TEXT, ttl INTEGER, created_at INTEGER, updated_at INTEGER)")).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "create user_dns_records table failed"))?;
        conn.execute_sql(sql_query("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_domain_record_type ON user_dns_records (owner, domain, record_type)")).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "create unique index on user_dns_records failed"))?;
        conn.execute_sql(sql_query("CREATE INDEX IF NOT EXISTS user_dns_records_domain_index ON user_dns_records (domain, id)")).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "create user_dns_records_domain_index failed"))?;
        conn.execute_sql(sql_query("CREATE TABLE IF NOT EXISTS user_domain_history (domain TEXT PRIMARY KEY, owner TEXT NOT NULL, created_at INTEGER NOT NULL)")).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "create user_domain_history table failed"))?;
        conn.execute_sql(sql_query("CREATE TABLE IF NOT EXISTS did_documents (id INTEGER PRIMARY KEY AUTOINCREMENT, obj_id TEXT, owner_user TEXT, obj_name TEXT, did_document TEXT, doc_type TEXT, update_time INTEGER)")).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "create did_documents table failed"))?;
        conn.execute_sql(sql_query("CREATE INDEX IF NOT EXISTS idx_did_documents_owner_obj ON did_documents (owner_user, obj_name, update_time)")).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "create did_documents index failed"))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let rows = conn
            .query_all(sql_query(
                "SELECT username, user_domain FROM users WHERE user_domain IS NOT NULL",
            ))
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "query existing user_domain history failed"
            ))?;
        for row in rows {
            let username: String = row.get(0);
            let user_domain: String = row.get(1);
            if let Some(canonical_domain) = Self::canonical_user_domain(user_domain.as_str()) {
                conn.execute_sql(
                    sql_query("INSERT OR IGNORE INTO user_domain_history (domain, owner, created_at) VALUES (?1, ?2, ?3)")
                        .bind(canonical_domain)
                        .bind(username)
                        .bind(now),
                )
                .await
                .map_err(into_sn_err!(
                    SnErrorCode::DBError,
                    "backfill user_domain_history failed"
                ))?;
            }
        }
        Ok(())
    }

    fn canonical_user_domain(domain: &str) -> Option<String> {
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            return None;
        }

        Some(
            normalized
                .strip_prefix("*.")
                .unwrap_or(normalized.as_str())
                .to_string(),
        )
    }
}

#[async_trait::async_trait]
impl SnDB for SqliteSnDB {
    async fn get_activation_codes(&self) -> SnResult<Vec<String>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        let rows = conn
            .query_all(sql_query(
                "SELECT code FROM activation_codes WHERE used = 0",
            ))
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "query activation_codes failed"
            ))?;

        let codes: Vec<String> = rows.into_iter().map(|row| row.get(0)).collect();
        Ok(codes)
    }

    async fn insert_activation_code(&self, code: &str) -> SnResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(
            sql_query("INSERT INTO activation_codes (code, used) VALUES (?1, 0)").bind(code),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "insert activation_codes failed"
        ))?;
        Ok(())
    }

    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>> {
        let mut codes: Vec<String> = Vec::new();
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        for _ in 0..count {
            let code: String = rand::rng().random_range(0..1000000).to_string();
            codes.push(code.clone());
            conn.execute_sql(
                sql_query("INSERT INTO activation_codes (code, used) VALUES (?1, 0)").bind(code),
            )
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "insert activation_codes failed"
            ))?;
        }
        Ok(codes)
    }

    async fn check_active_code(&self, active_code: &str) -> SnResult<bool> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        match conn
            .query_one(
                sql_query("SELECT used FROM activation_codes WHERE code = ?1").bind(active_code),
            )
            .await
        {
            Ok(row) => {
                let used: i32 = row.get(0);
                Ok(used == 0)
            }
            Err(_) => Ok(false),
        }
    }

    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        conn.begin_transaction().await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "begin transaction failed"
        ))?;

        let user_count: i64 = conn
            .query_one(
                sql_query("SELECT COUNT(*) FROM users WHERE activation_code = ?1")
                    .bind(active_code),
            )
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "count users failed"))?
            .get(0);

        let device_count: i64 = conn
            .query_one(
                sql_query(
                    "SELECT COUNT(*) FROM devices WHERE owner IN (SELECT username FROM users WHERE activation_code = ?1)",
                )
                .bind(active_code),
            )
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "count devices failed"))?
            .get(0);

        let domain_record_count: i64 = conn
            .query_one(
                sql_query(
                    "SELECT COUNT(*) FROM user_dns_records WHERE owner IN (SELECT username FROM users WHERE activation_code = ?1)",
                )
                .bind(active_code),
            )
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "count user_dns_records failed"))?
            .get(0);

        let did_doc_count: i64 = conn
            .query_one(
                sql_query(
                    "SELECT COUNT(*) FROM did_documents WHERE owner_user IN (SELECT username FROM users WHERE activation_code = ?1)",
                )
                .bind(active_code),
            )
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "count did_documents failed"))?
            .get(0);

        conn.execute_sql(
            sql_query("DELETE FROM devices WHERE owner IN (SELECT username FROM users WHERE activation_code = ?1)")
                .bind(active_code),
        )
        .await
        .map_err(into_sn_err!(SnErrorCode::DBError, "delete devices failed"))?;

        conn.execute_sql(
            sql_query("DELETE FROM user_dns_records WHERE owner IN (SELECT username FROM users WHERE activation_code = ?1)")
                .bind(active_code),
        )
        .await
        .map_err(into_sn_err!(SnErrorCode::DBError, "delete user dns records failed"))?;

        conn.execute_sql(
            sql_query("DELETE FROM did_documents WHERE owner_user IN (SELECT username FROM users WHERE activation_code = ?1)")
                .bind(active_code),
        )
        .await
        .map_err(into_sn_err!(SnErrorCode::DBError, "delete did documents failed"))?;

        conn.execute_sql(
            sql_query("DELETE FROM user_auth_v2 WHERE username IN (SELECT username FROM users WHERE activation_code = ?1)")
                .bind(active_code),
        )
        .await
        .map_err(into_sn_err!(SnErrorCode::DBError, "delete user auth v2 failed"))?;

        conn.execute_sql(
            sql_query("DELETE FROM users WHERE activation_code = ?1").bind(active_code),
        )
        .await
        .map_err(into_sn_err!(SnErrorCode::DBError, "delete users failed"))?;

        conn.execute_sql(
            sql_query(
                "INSERT INTO activation_codes (code, used) VALUES (?1, 0) ON CONFLICT(code) DO UPDATE SET used = 0",
            )
            .bind(active_code),
        )
        .await
        .map_err(into_sn_err!(SnErrorCode::DBError, "reset activation code failed"))?;

        conn.commit_transaction().await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "commit transaction failed"
        ))?;

        Ok(SnClearStateResult {
            deleted_users: user_count.max(0) as u64,
            deleted_devices: device_count.max(0) as u64,
            deleted_domain_records: domain_record_count.max(0) as u64,
            deleted_did_documents: did_doc_count.max(0) as u64,
            activation_code_reset: true,
        })
    }

    async fn register_user(
        &self,
        active_code: &str,
        username: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
    ) -> SnResult<bool> {
        self.register_user_with_sn_ips(
            active_code,
            username,
            public_key,
            zone_config,
            user_domain,
            None,
        )
        .await
    }

    async fn register_user_with_sn_ips(
        &self,
        active_code: &str,
        username: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> SnResult<bool> {
        let _locker =
            async_named_locker::Locker::get_locker(format!("active_code_{}", active_code)).await;
        let _user_domain_locker = if user_domain.is_some() {
            Some(
                async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                    .await,
            )
        } else {
            None
        };
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        conn.begin_transaction().await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "begin transaction failed"
        ))?;
        // 检查激活码是否未使用
        match conn
            .query_one(
                sql_query("SELECT used FROM activation_codes WHERE code = ?1").bind(active_code),
            )
            .await
        {
            Ok(row) => {
                let used: i32 = row.get(0);
                if used == 0 {
                    if let Some(user_domain) = user_domain.as_ref() {
                        if let Some(canonical_domain) =
                            Self::canonical_user_domain(user_domain.as_str())
                        {
                            let descendant_pattern = format!("%.{}", canonical_domain);
                            let conflicts = conn
                                .query_all(
                                    sql_query("SELECT domain, owner FROM user_domain_history WHERE domain = ?1 OR domain LIKE ?2 OR ?1 LIKE '%.' || domain")
                                        .bind(canonical_domain.as_str())
                                        .bind(descendant_pattern),
                                )
                                .await
                                .map_err(into_sn_err!(
                                    SnErrorCode::DBError,
                                    "query user_domain history failed"
                                ))?;
                            for conflict in conflicts {
                                let conflict_domain: String = conflict.get(0);
                                let conflict_owner: String = conflict.get(1);
                                if conflict_owner != username {
                                    return Err(sn_err!(
                                        SnErrorCode::Failed,
                                        "user_domain {} conflicts with historical domain {} owned by {}",
                                        user_domain,
                                        conflict_domain,
                                        conflict_owner
                                    ));
                                }
                            }
                        }
                    }

                    // 插入用户记录
                    conn.execute_sql(sql_query("INSERT INTO users (username, state, public_key, activation_code, zone_config, user_domain, sn_ips) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)")
                        .bind(username)
                        .bind(UserState::Active.to_string())
                        .bind(public_key)
                        .bind(active_code)
                        .bind(zone_config)
                        .bind(user_domain.clone())
                        .bind(sn_ips)).await
                        .map_err(into_sn_err!(SnErrorCode::DBError, "insert user failed"))?;

                    if let Some(user_domain) = user_domain.as_ref() {
                        if let Some(canonical_domain) =
                            Self::canonical_user_domain(user_domain.as_str())
                        {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as i64;
                            conn.execute_sql(
                                sql_query("INSERT OR IGNORE INTO user_domain_history (domain, owner, created_at) VALUES (?1, ?2, ?3)")
                                    .bind(canonical_domain)
                                    .bind(username)
                                    .bind(now),
                            )
                            .await
                            .map_err(into_sn_err!(
                                SnErrorCode::DBError,
                                "insert user_domain history failed"
                            ))?;
                        }
                    }

                    // 更新激活码为已使用
                    conn.execute_sql(
                        sql_query("UPDATE activation_codes SET used = 1 WHERE code = ?1")
                            .bind(active_code),
                    )
                    .await
                    .map_err(into_sn_err!(
                        SnErrorCode::DBError,
                        "update activation code failed"
                    ))?;

                    conn.commit_transaction().await.map_err(into_sn_err!(
                        SnErrorCode::DBError,
                        "commit transaction failed"
                    ))?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }

    async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> SnResult<Option<(String, String, Option<String>)>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        match conn
            .query_one(
                sql_query("SELECT username, zone_config, sn_ips FROM users WHERE public_key = ?1")
                    .bind(public_key),
            )
            .await
        {
            Ok(row) => Ok(Some((row.get(0), row.get(1), row.get(2)))),
            Err(_) => Ok(None),
        }
    }

    async fn register_user_directly(
        &self,
        username: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
    ) -> SnResult<bool> {
        let _user_domain_locker = if user_domain.is_some() {
            Some(
                async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                    .await,
            )
        } else {
            None
        };
        let sn_ips: Option<String> = None;
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.begin_transaction().await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "begin transaction failed"
        ))?;

        if let Some(user_domain) = user_domain.as_ref() {
            if let Some(canonical_domain) = Self::canonical_user_domain(user_domain.as_str()) {
                let descendant_pattern = format!("%.{}", canonical_domain);
                let conflicts = conn
                    .query_all(
                        sql_query("SELECT domain, owner FROM user_domain_history WHERE domain = ?1 OR domain LIKE ?2 OR ?1 LIKE '%.' || domain")
                            .bind(canonical_domain.as_str())
                            .bind(descendant_pattern),
                    )
                    .await
                    .map_err(into_sn_err!(
                        SnErrorCode::DBError,
                        "query user_domain history failed"
                    ))?;
                for conflict in conflicts {
                    let conflict_domain: String = conflict.get(0);
                    let conflict_owner: String = conflict.get(1);
                    if conflict_owner != username {
                        return Err(sn_err!(
                            SnErrorCode::Failed,
                            "user_domain {} conflicts with historical domain {} owned by {}",
                            user_domain,
                            conflict_domain,
                            conflict_owner
                        ));
                    }
                }
            }
        }

        conn.execute_sql(sql_query("INSERT INTO users (username, state, public_key, activation_code, zone_config, user_domain, self_cert, sn_ips) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")
            .bind(username)
            .bind(UserState::Active.to_string())
            .bind(public_key)
            .bind("DIRECT")
            .bind(zone_config)
            .bind(user_domain.clone())
            .bind(true)
            .bind(sn_ips)).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "insert user failed"))?;

        if let Some(user_domain) = user_domain.as_ref() {
            if let Some(canonical_domain) = Self::canonical_user_domain(user_domain.as_str()) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                conn.execute_sql(
                    sql_query("INSERT OR IGNORE INTO user_domain_history (domain, owner, created_at) VALUES (?1, ?2, ?3)")
                        .bind(canonical_domain)
                        .bind(username)
                        .bind(now),
                )
                .await
                .map_err(into_sn_err!(
                    SnErrorCode::DBError,
                    "insert user_domain history failed"
                ))?;
            }
        }

        conn.commit_transaction().await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "commit transaction failed"
        ))?;
        Ok(true)
    }

    async fn register_user_v2(
        &self,
        active_code: &str,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        let _locker =
            async_named_locker::Locker::get_locker(format!("active_code_{}", active_code)).await;
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        conn.begin_transaction().await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "begin transaction failed"
        ))?;

        let active_code_row = conn
            .query_one(
                sql_query("SELECT used FROM activation_codes WHERE code = ?1").bind(active_code),
            )
            .await;
        let code_unused = match active_code_row {
            Ok(row) => row.get::<i32, _>(0) == 0,
            Err(_) => false,
        };
        if !code_unused {
            return Ok(false);
        }

        let user_count: i64 = conn
            .query_one(sql_query("SELECT COUNT(*) FROM users WHERE username = ?1").bind(username))
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "query user count failed"
            ))?
            .get(0);
        if user_count > 0 {
            return Ok(false);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let sn_ips: Option<String> = None;

        conn.execute_sql(sql_query("INSERT INTO users (username, state, public_key, activation_code, zone_config, user_domain, self_cert, sn_ips) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")
            .bind(username)
            .bind(UserState::Active.to_string())
            .bind("")
            .bind(active_code)
            .bind("")
            .bind(Option::<String>::None)
            .bind(false)
            .bind(sn_ips))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "insert v2 user failed"))?;

        conn.execute_sql(sql_query("INSERT INTO user_auth_v2 (username, password_hash, password_salt, password_algo, created_at, updated_at, last_login_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)")
            .bind(username)
            .bind(password_hash)
            .bind(password_salt)
            .bind(password_algo)
            .bind(now))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "insert v2 auth failed"))?;

        conn.execute_sql(
            sql_query("UPDATE activation_codes SET used = 1 WHERE code = ?1").bind(active_code),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "update activation code failed"
        ))?;

        conn.commit_transaction().await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "commit transaction failed"
        ))?;
        Ok(true)
    }

    async fn create_v2_auth(
        &self,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        let _locker =
            async_named_locker::Locker::get_locker(format!("username_{}", username)).await;
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        let user_count: i64 = conn
            .query_one(sql_query("SELECT COUNT(*) FROM users WHERE username = ?1").bind(username))
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "query user count failed"
            ))?
            .get(0);
        if user_count > 0 {
            return Ok(false);
        }

        let auth_count: i64 = conn
            .query_one(
                sql_query("SELECT COUNT(*) FROM user_auth_v2 WHERE username = ?1").bind(username),
            )
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "query user auth count failed"
            ))?
            .get(0);
        if auth_count > 0 {
            return Ok(false);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        conn.execute_sql(sql_query("INSERT INTO user_auth_v2 (username, password_hash, password_salt, password_algo, created_at, updated_at, last_login_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)")
            .bind(username)
            .bind(password_hash)
            .bind(password_salt)
            .bind(password_algo)
            .bind(now))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "insert v2 auth failed"))?;
        Ok(true)
    }

    async fn is_user_exist(&self, username: &str) -> SnResult<bool> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        let row = conn
            .query_one(sql_query("SELECT COUNT(*) FROM users WHERE username = ?1").bind(username))
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "query user failed"))?;
        let count: i64 = row.get(0);
        Ok(count > 0)
    }

    async fn update_user_public_key(&self, username: &str, public_key: &str) -> SnResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(
            sql_query("UPDATE users SET public_key = ?1 WHERE username = ?2")
                .bind(public_key)
                .bind(username),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "update user public key failed"
        ))?;
        Ok(())
    }

    async fn update_user_zone_config(&self, username: &str, zone_config: &str) -> SnResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(
            sql_query("UPDATE users SET zone_config = ?1 WHERE username = ?2")
                .bind(zone_config)
                .bind(username),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "update user zone_config failed"
        ))?;
        Ok(())
    }

    async fn update_user_sn_ips(&self, username: &str, sn_ips: &str) -> SnResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(
            sql_query("UPDATE users SET sn_ips = ?1 WHERE username = ?2")
                .bind(sn_ips)
                .bind(username),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "update user sn_ips failed"
        ))?;
        Ok(())
    }

    async fn update_user_self_cert(&self, username: &str, self_cert: bool) -> SnResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(
            sql_query("UPDATE users SET self_cert = ?1 WHERE username = ?2")
                .bind(self_cert)
                .bind(username),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "update user self_cert failed"
        ))?;
        Ok(())
    }

    async fn update_user_domain(
        &self,
        username: &str,
        user_domain: Option<String>,
    ) -> SnResult<()> {
        let _user_domain_locker =
            async_named_locker::Locker::get_locker(Self::USER_DOMAIN_BINDING_LOCK.to_string())
                .await;
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.begin_transaction().await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "begin transaction failed"
        ))?;

        if let Some(user_domain) = user_domain.as_ref() {
            if let Some(canonical_domain) = Self::canonical_user_domain(user_domain.as_str()) {
                let descendant_pattern = format!("%.{}", canonical_domain);
                let conflicts = conn
                    .query_all(
                        sql_query("SELECT domain, owner FROM user_domain_history WHERE domain = ?1 OR domain LIKE ?2 OR ?1 LIKE '%.' || domain")
                            .bind(canonical_domain.as_str())
                            .bind(descendant_pattern),
                    )
                    .await
                    .map_err(into_sn_err!(
                        SnErrorCode::DBError,
                        "query user_domain history failed"
                    ))?;
                for conflict in conflicts {
                    let conflict_domain: String = conflict.get(0);
                    let conflict_owner: String = conflict.get(1);
                    if conflict_owner != username {
                        return Err(sn_err!(
                            SnErrorCode::Failed,
                            "user_domain {} conflicts with historical domain {} owned by {}",
                            user_domain,
                            conflict_domain,
                            conflict_owner
                        ));
                    }
                }
            }
        }

        conn.execute_sql(
            sql_query("UPDATE users SET user_domain =?1 WHERE username =?2")
                .bind(user_domain.clone())
                .bind(username),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "update user user_domain failed"
        ))?;

        if let Some(user_domain) = user_domain.as_ref() {
            if let Some(canonical_domain) = Self::canonical_user_domain(user_domain.as_str()) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                conn.execute_sql(
                    sql_query("INSERT OR IGNORE INTO user_domain_history (domain, owner, created_at) VALUES (?1, ?2, ?3)")
                        .bind(canonical_domain)
                        .bind(username)
                        .bind(now),
                )
                .await
                .map_err(into_sn_err!(
                    SnErrorCode::DBError,
                    "insert user_domain history failed"
                ))?;
            }
        }

        conn.commit_transaction().await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "commit transaction failed"
        ))?;
        Ok(())
    }

    async fn get_user_sn_ips(&self, username: &str) -> SnResult<Option<String>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        match conn
            .query_one(sql_query("SELECT sn_ips FROM users WHERE username = ?1").bind(username))
            .await
        {
            Ok(row) => Ok(row.get(0)),
            Err(_) => Ok(None),
        }
    }

    async fn get_user_sn_ips_as_vec(&self, username: &str) -> SnResult<Option<Vec<String>>> {
        if let Some(sn_ips_str) = self.get_user_sn_ips(username).await? {
            if sn_ips_str.is_empty() {
                return Ok(Some(Vec::new()));
            }
            match serde_json::from_str::<Vec<String>>(&sn_ips_str) {
                Ok(ips) => Ok(Some(ips)),
                Err(_) => {
                    // 如果 JSON 解析失败，尝试作为逗号分隔的字符串解析
                    let ips: Vec<String> = sn_ips_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    Ok(Some(ips))
                }
            }
        } else {
            Ok(None)
        }
    }

    async fn set_user_sn_ips_from_vec(&self, username: &str, ips: &[String]) -> SnResult<()> {
        let sn_ips_json = serde_json::to_string(ips).map_err(|e| {
            sn_err!(
                SnErrorCode::DBError,
                "serialize sn_ips failed: {}",
                e.to_string()
            )
        })?;
        self.update_user_sn_ips(username, &sn_ips_json).await
    }

    async fn add_user_sn_ip(&self, username: &str, ip: &str) -> SnResult<()> {
        let mut current_ips = self
            .get_user_sn_ips_as_vec(username)
            .await?
            .unwrap_or_default();
        if !current_ips.contains(&ip.to_string()) {
            current_ips.push(ip.to_string());
            self.set_user_sn_ips_from_vec(username, &current_ips)
                .await?;
        }
        Ok(())
    }

    async fn remove_user_sn_ip(&self, username: &str, ip: &str) -> SnResult<()> {
        let mut current_ips = self
            .get_user_sn_ips_as_vec(username)
            .await?
            .unwrap_or_default();
        current_ips.retain(|x| x != ip);
        self.set_user_sn_ips_from_vec(username, &current_ips).await
    }

    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        match conn.query_one(sql_query("SELECT state, public_key, activation_code, zone_config, self_cert, user_domain, sn_ips FROM users WHERE username = ?1").bind(username)).await {
            Ok(row) => {
                let state_str: Option<String> = row.get(0);
                let self_cert: bool = row.get(4);
                Ok(Some(SNUserInfo {
                    username: None,
                    state: UserState::from_str(state_str.as_deref()),
                    public_key: row.get(1),
                    activation_code: row.get(2),
                    zone_config: row.get(3),
                    self_cert,
                    user_domain: row.get(5),
                    sn_ips: row.get(6),
                }))
            }
            Err(_) => Ok(None)
        }
    }

    async fn register_device(
        &self,
        username: &str,
        device_name: &str,
        did: &str,
        mini_config_jwt: &str,
        ip: &str,
        description: &str,
    ) -> SnResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(sql_query("INSERT INTO devices (owner, device_name, did, ip, description, mini_config_jwt, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT(owner, device_name) DO UPDATE SET did = excluded.did, ip = excluded.ip, description = excluded.description, mini_config_jwt = excluded.mini_config_jwt, updated_at = excluded.updated_at")
            .bind(username)
            .bind(device_name)
            .bind(did)
            .bind(ip)
            .bind(description)
            .bind(mini_config_jwt)
            .bind(now as i64)
            .bind(now as i64)).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "insert device failed"))?;
        Ok(())
    }

    async fn update_device_by_did(&self, did: &str, ip: &str, description: &str) -> SnResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(
            sql_query(
                "UPDATE devices SET ip = ?1, description = ?2, updated_at = ?3 WHERE did = ?4",
            )
            .bind(ip)
            .bind(description)
            .bind(now as i64)
            .bind(did),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "update device by did failed"
        ))?;
        Ok(())
    }

    async fn update_device_by_name(
        &self,
        username: &str,
        device_name: &str,
        did: &str,
        mini_config_jwt: &str,
        ip: &str,
        description: &str,
    ) -> SnResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(sql_query("UPDATE devices SET did = ?1, mini_config_jwt = ?2, ip = ?3, description = ?4, updated_at = ?5 WHERE device_name = ?6 AND owner = ?7")
            .bind(did)
            .bind(mini_config_jwt)
            .bind(ip)
            .bind(description)
            .bind(now as i64)
            .bind(device_name)
            .bind(username)).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "update device by name failed"))?;
        Ok(())
    }

    async fn update_device_info_by_name(
        &self,
        username: &str,
        device_name: &str,
        ip: &str,
        description: &str,
    ) -> SnResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(sql_query("UPDATE devices SET ip = ?1, description = ?2, updated_at = ?3 WHERE device_name = ?4 AND owner = ?5")
            .bind(ip)
            .bind(description)
            .bind(now as i64)
            .bind(device_name)
            .bind(username)).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "update device info by name failed"))?;
        Ok(())
    }

    async fn query_device_by_name(
        &self,
        username: &str,
        device_name: &str,
    ) -> SnResult<Option<SNDeviceInfo>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        match conn.query_one(sql_query("SELECT owner, device_name, mini_config_jwt, did, ip, description, created_at, updated_at FROM devices WHERE device_name = ?1 AND owner = ?2 ORDER BY updated_at DESC, created_at DESC LIMIT 1")
            .bind(device_name)
            .bind(username)).await {
            Ok(row) => {
                Ok(Some(SNDeviceInfo {
                    owner: row.get(0),
                    device_name: row.get(1),
                    mini_config_jwt: row.get(2),
                    did: row.get(3),
                    ip: row.get(4),
                    description: row.get(5),
                    created_at: row.get::<i64, _>(6) as u64,
                    updated_at: row.get::<i64, _>(7) as u64,
                }))
            }
            Err(e) => {
                log::error!("query device by name failed: {}", e);
                Ok(None)
            }
        }
    }

    async fn list_user_devices(&self, username: &str) -> SnResult<Vec<SNDeviceInfo>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        let rows = conn
            .query_all(
                sql_query("SELECT owner, device_name, mini_config_jwt, did, ip, description, created_at, updated_at FROM devices WHERE owner = ?1 ORDER BY device_name ASC")
                    .bind(username),
            )
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "list user devices failed"))?;
        Ok(rows
            .into_iter()
            .map(|row| SNDeviceInfo {
                owner: row.get(0),
                device_name: row.get(1),
                mini_config_jwt: row.get(2),
                did: row.get(3),
                ip: row.get(4),
                description: row.get(5),
                created_at: row.get::<i64, _>(6) as u64,
                updated_at: row.get::<i64, _>(7) as u64,
            })
            .collect())
    }

    async fn query_device_by_did(&self, did: &str) -> SnResult<Option<SNDeviceInfo>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        match conn.query_one(sql_query("SELECT owner, device_name, mini_config_jwt, did, ip, description, created_at, updated_at FROM devices WHERE did = ?1").bind(did)).await {
            Ok(row) => {
                Ok(Some(SNDeviceInfo {
                    owner: row.get(0),
                    device_name: row.get(1),
                    mini_config_jwt: row.get(2),
                    did: row.get(3),
                    ip: row.get(4),
                    description: row.get(5),
                    created_at: row.get::<i64, _>(6) as u64,
                    updated_at: row.get::<i64, _>(7) as u64,
                }))
            }
            Err(_) => Ok(None)
        }
    }

    async fn get_user_info_by_domain(&self, domain: &str) -> SnResult<Option<SNUserInfo>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        match conn.query_one(sql_query("SELECT username, state, public_key, activation_code, zone_config, self_cert, user_domain, sn_ips FROM users WHERE ?1 = user_domain OR ?1 LIKE '%.' || user_domain")
            .bind(domain)).await {
            Ok(row) => {
                let state_str: Option<String> = row.get(1);
                let self_cert: bool = row.get(5);
                Ok(Some(SNUserInfo {
                    username: Some(row.get(0)),
                    state: UserState::from_str(state_str.as_deref()),
                    public_key: row.get(2),
                    activation_code: row.get(3),
                    zone_config: row.get(4),
                    self_cert,
                    user_domain: row.get(6),
                    sn_ips: row.get(7),
                }))
            }
            Err(_) => Ok(None)
        }
    }

    async fn query_device(&self, did: &str) -> SnResult<Option<SNDeviceInfo>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        match conn.query_one(sql_query("SELECT owner, device_name, mini_config_jwt, did, ip, description, created_at, updated_at FROM devices WHERE did = ?1").bind(did)).await {
            Ok(row) => {
                Ok(Some(SNDeviceInfo {
                    owner: row.get(0),
                    device_name: row.get(1),
                    mini_config_jwt: row.get(2),
                    did: row.get(3),
                    ip: row.get(4),
                    description: row.get(5),
                    created_at: row.get::<i64, _>(6) as u64,
                    updated_at: row.get::<i64, _>(7) as u64,
                }))
            }
            Err(_) => Ok(None)
        }
    }

    async fn add_user_domain(
        &self,
        username: &str,
        domain: &str,
        record_type: &str,
        record: &str,
        ttl: u32,
    ) -> SnResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 使用 INSERT ... ON CONFLICT 在单个 SQL 语句中完成：如果 (owner, domain, record_type) 组合已存在则更新，否则插入新记录
        conn.execute_sql(sql_query("INSERT INTO user_dns_records (owner, domain, record_type, record, ttl, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?6, ?5, ?5) ON CONFLICT(owner, domain, record_type) DO UPDATE SET record = ?4, updated_at = ?5")
            .bind(username)
            .bind(domain)
            .bind(record_type)
            .bind(record)
            .bind(now as i64)
            .bind(ttl as i64)).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "insert on conflict user dns record failed"))?;

        Ok(())
    }

    async fn remove_user_domain(
        &self,
        username: &str,
        domain: &str,
        record_type: &str,
    ) -> SnResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        conn.execute_sql(sql_query("DELETE FROM user_dns_records WHERE owner = ?1 AND domain = ?2 AND record_type = ?3")
            .bind(username)
            .bind(domain)
            .bind(record_type)).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "delete user dns record failed"))?;

        Ok(())
    }

    async fn query_domain_record(
        &self,
        domain: &str,
        record_type: &str,
    ) -> SnResult<Option<(String, u32)>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        match conn.query_one(sql_query("SELECT record, ttl FROM user_dns_records WHERE domain = ?1 AND record_type = ?2")
            .bind(domain)
            .bind(record_type)).await {
            Ok(row) => {
                let record: String = row.get(0);
                Ok(Some((record, row.get::<i64, _>(1) as u32)))
            }
            Err(_) => Ok(None)
        }
    }

    async fn query_domain_records(&self, domain: &str) -> SnResult<Vec<(String, String, u32)>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        let rows = conn
            .query_all(
                sql_query(
                    "SELECT record_type, record, ttl FROM user_dns_records WHERE domain = ?1",
                )
                .bind(domain),
            )
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "query user dns records failed"
            ))?;

        let records: Vec<(String, String, u32)> = rows
            .into_iter()
            .map(|row| (row.get(0), row.get(1), row.get::<i64, _>(2) as u32))
            .collect();

        Ok(records)
    }

    async fn query_user_domain_records(
        &self,
        username: &str,
    ) -> SnResult<Vec<(String, String, String, u32)>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        let rows = conn.query_all(sql_query("SELECT domain, record_type, record, ttl FROM user_dns_records WHERE owner = ?1")
            .bind(username)).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "query user dns records failed"))?;
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row.get(0),
                    row.get(1),
                    row.get(2),
                    row.get::<i64, _>(3) as u32,
                )
            })
            .collect())
    }

    async fn insert_user_did_document(
        &self,
        obj_id: &str,
        owner_user: &str,
        obj_name: &str,
        did_document: &str,
        doc_type: Option<&str>,
    ) -> SnResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        conn.execute_sql(sql_query("INSERT INTO did_documents (obj_id, owner_user, obj_name, did_document, doc_type, update_time) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
            .bind(obj_id)
            .bind(owner_user)
            .bind(obj_name)
            .bind(did_document)
            .bind(doc_type)
            .bind(now as i64)).await
            .map_err(into_sn_err!(SnErrorCode::DBError, "insert did document failed"))?;
        Ok(())
    }

    async fn query_user_did_document(
        &self,
        owner_user: &str,
        obj_name: &str,
        doc_type: Option<&str>,
    ) -> SnResult<Option<(String, String, Option<String>)>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        let rows = if let Some(doc_type) = doc_type {
            conn.query_all(sql_query("SELECT obj_id, did_document, doc_type FROM did_documents WHERE owner_user = ?1 AND obj_name = ?2 AND doc_type = ?3 ORDER BY update_time DESC LIMIT 1")
                .bind(owner_user)
                .bind(obj_name)
                .bind(doc_type)).await
        } else {
            conn.query_all(sql_query("SELECT obj_id, did_document, doc_type FROM did_documents WHERE owner_user = ?1 AND obj_name = ?2 ORDER BY update_time DESC LIMIT 1")
                .bind(owner_user)
                .bind(obj_name)).await
        };

        match rows {
            Ok(mut rows) => {
                if let Some(row) = rows.pop() {
                    Ok(Some((row.get(0), row.get(1), row.get(2))))
                } else {
                    Ok(None)
                }
            }
            Err(_) => Ok(None),
        }
    }

    async fn get_v2_auth(&self, username: &str) -> SnResult<Option<SnV2AuthInfo>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        match conn
            .query_one(
                sql_query("SELECT username, password_hash, password_salt, password_algo, created_at, updated_at, last_login_at FROM user_auth_v2 WHERE username = ?1")
                    .bind(username),
            )
            .await
        {
            Ok(row) => Ok(Some(SnV2AuthInfo {
                username: row.get(0),
                password_hash: row.get(1),
                password_salt: row.get(2),
                password_algo: row.get(3),
                created_at: row.get::<i64, _>(4) as u64,
                updated_at: row.get::<i64, _>(5) as u64,
                last_login_at: row.get::<Option<i64>, _>(6).map(|v| v as u64),
            })),
            Err(_) => Ok(None),
        }
    }

    async fn update_v2_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        conn.execute_sql(
            sql_query(
                "UPDATE user_auth_v2 SET last_login_at = ?1, updated_at = ?1 WHERE username = ?2",
            )
            .bind(last_login_at as i64)
            .bind(username),
        )
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "update v2 last login failed"
        ))?;
        Ok(())
    }
}

#[derive(Deserialize)]
struct SqliteDBConfig {
    db_path: Option<String>,
}

pub struct SqliteDBFactory {}

impl SqliteDBFactory {
    pub fn new() -> Self {
        SqliteDBFactory {}
    }
}

#[async_trait::async_trait]
impl SnDBFactory for SqliteDBFactory {
    async fn create(&self, config: serde_json::Value) -> ServerResult<SnDBRef> {
        let config: SqliteDBConfig =
            serde_json::from_value(config.clone()).map_err(into_sn_err!(
                ServerErrorCode::InvalidConfig,
                "invalid sn sqlite db config {}",
                config.to_string()
            ))?;
        let sqlite_db = if config.db_path.is_none() {
            Arc::new(
                SqliteSnDB::new()
                    .await
                    .map_err(into_server_err!(ServerErrorCode::InvalidConfig))?,
            )
        } else {
            Arc::new(
                SqliteSnDB::new_by_path(config.db_path.as_deref().unwrap())
                    .await
                    .map_err(into_server_err!(ServerErrorCode::InvalidConfig))?,
            )
        };
        sqlite_db
            .initialize_database()
            .await
            .map_err(into_server_err!(
                ServerErrorCode::InvalidConfig,
                "init sn db failed"
            ))?;
        Ok(sqlite_db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_main() -> SnResult<()> {
        //let tmp_dir = std::env::temp_dir();
        let base_dir = std::env::temp_dir();
        let db_path = base_dir.join("sn_db.sqlite3");
        let _ = std::fs::remove_file(db_path.clone());
        println!("db_path: {}", db_path.to_str().unwrap());
        //remove db file
        let db_path_str = db_path.to_str().unwrap();

        let db = SqliteSnDB::new_by_path(db_path_str).await?;
        db.initialize_database().await?;
        let codes = db.generate_activation_codes(100).await?;
        println!("codes: {:?}", codes);
        // Example usage
        println!("codes: {:?}", codes);
        let first_code = codes.first().unwrap();

        let registration_success = db.register_user(first_code.as_str(), "lzc", "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8",
                                                    "eyJhbGciOiJFZERTQSJ9.eyJkaWQiOiJkaWQ6ZW5zOmx6YyIsIm9vZHMiOlsib29kMSJdLCJzbiI6IndlYjMuYnVja3lvcy5pbyIsImV4cCI6MjA0NDgyMzMzNn0.Xqd-4FsDbqZt1YZOIfduzsJik5UZmuylknMiAxLToB2jBBzHHccn1KQptLhhyEL5_Y-89YihO9BX6wO7RoqABw",
                                                    Some("www.zhicong.me".to_string()),
        ).await?;
        if registration_success {
            println!("User registered successfully.");

            // 设置初始的 sn_ips
            db.set_user_sn_ips_from_vec("lzc", &vec!["70.221.32.12".to_string()])
                .await?;
            println!("Set initial sn_ips for user");
        } else {
            println!("Registration failed.");
        }

        let ret = db
            .add_user_domain("lzc", "example.com", "A", "192.168.1.100", 3600)
            .await;
        assert!(ret.is_ok());

        let ret = db.query_domain_record("example.com", "A").await;
        assert!(ret.is_ok());
        assert_eq!(ret.unwrap(), Some(("192.168.1.100".to_string(), 3600)));

        let ret = db.query_domain_record("example.com", "AAAA").await;
        assert!(ret.is_ok());
        assert_eq!(ret.unwrap(), None);

        let ret = db.query_domain_records("example.com").await;
        assert!(ret.is_ok());
        assert_eq!(
            ret.unwrap(),
            vec![("A".to_string(), "192.168.1.100".to_string(), 3600)]
        );

        let ret = db.query_user_domain_records("lzc").await;
        assert!(ret.is_ok());
        assert_eq!(
            ret.unwrap(),
            vec![(
                "example.com".to_string(),
                "A".to_string(),
                "192.168.1.100".to_string(),
                3600
            )]
        );

        let ret = db.remove_user_domain("lzc", "example.com", "A").await;
        assert!(ret.is_ok());

        let ret = db.query_domain_record("example.com", "A").await;
        assert!(ret.is_ok());
        assert_eq!(ret.unwrap(), None);

        let ret = db.query_domain_records("example.com").await;
        assert!(ret.is_ok());
        assert_eq!(ret.unwrap(), vec![]);

        let ret = db.query_user_domain_records("lzc").await;
        assert!(ret.is_ok());
        assert_eq!(ret.unwrap(), vec![]);

        // 测试 sn_ips 功能
        if let Some(sn_ips) = db.get_user_sn_ips("lzc").await? {
            println!("User sn_ips: {}", sn_ips);
        }

        if let Some(ips_vec) = db.get_user_sn_ips_as_vec("lzc").await? {
            println!("User sn_ips as vec: {:?}", ips_vec);
        }

        // 添加新的 IP
        db.add_user_sn_ip("lzc", "192.168.1.100").await?;
        println!("Added new IP to user");

        if let Some(ips_vec) = db.get_user_sn_ips_as_vec("lzc").await? {
            println!("User sn_ips after adding: {:?}", ips_vec);
        }

        // 移除 IP
        db.remove_user_sn_ip("lzc", "70.221.32.12").await?;
        println!("Removed IP from user");

        if let Some(ips_vec) = db.get_user_sn_ips_as_vec("lzc").await? {
            println!("User sn_ips after removing: {:?}", ips_vec);
        }

        // 测试更新用户 self_cert 字段
        println!("\n=== Test update_user_self_cert ===");
        db.update_user_self_cert("lzc", true).await?;
        println!("Updated user self_cert to true");

        if let Some(user_info) = db.get_user_info("lzc").await? {
            println!("Self cert after update: {}", user_info.self_cert);
            assert_eq!(user_info.self_cert, true, "self_cert should be true");
        }

        // 测试设备注册和查询
        let device_info_str = r#"{"hostname":"ood1","device_type":"ood","did":"did:dev:gubVIszw-u_d5PVTh-oc8CKAhM9C-ne5G_yUK5BDaXc","ip":"192.168.1.86","sys_hostname":"LZC-USWORK","base_os_info":"Ubuntu 22.04 5.15.153.1-microsoft-standard-WSL2","cpu_info":"AMD Ryzen 7 5800X 8-Core Processor @ 3800 MHz","cpu_usage":0.0,"total_mem":67392299008,"mem_usage":5.7286677}"#;
        println!("\ndevice_info_str: {}", device_info_str);
        let mini_config_jwt = "eyJhbGciOiJFZERTQSJ9.eyJkaWQiOiJkaWQ6ZGV2Om9vZDEiLCJvd25lciI6ImRpZDplbnM6bHpjIiwiZXhwIjoyMDQ0ODIzMzM2fQ.test_signature";
        db.register_device(
            "lzc",
            "ood1",
            "did:dev:gubVIszw-u_d5PVTh-oc8CKAhM9C-ne5G_yUK5BDaXc",
            mini_config_jwt,
            "192.168.1.188",
            device_info_str,
        )
        .await?;

        // 测试使用 SNDeviceInfo 结构体
        if let Some(device_info) = db
            .query_device("did:dev:gubVIszw-u_d5PVTh-oc8CKAhM9C-ne5G_yUK5BDaXc")
            .await?
        {
            println!("\n=== Device Info (by DID) ===");
            println!("Device info: {:?}", device_info);
            println!("Device owner: {}", device_info.owner);
            println!("Device name: {}", device_info.device_name);
            println!("Device DID: {}", device_info.did);
            println!("Device mini_config_jwt: {}", device_info.mini_config_jwt);
            println!("Device IP: {}", device_info.ip);
            println!("Device created_at: {}", device_info.created_at);
            println!("Device updated_at: {}", device_info.updated_at);
        } else {
            println!("Device not found.");
        }

        // 测试通过设备名查询
        if let Some(device_info) = db.query_device_by_name("lzc", "ood1").await? {
            println!("\n=== Device Info (by name) ===");
            println!(
                "Query device by name - owner: {}, did: {}",
                device_info.owner, device_info.did
            );
            println!("Mini config JWT: {}", device_info.mini_config_jwt);
        }

        // 测试更新设备信息（包括 did 和 mini_config_jwt）
        println!("\n=== Test update_device_by_name ===");
        let updated_device_info_str = r#"{"hostname":"ood1","device_type":"ood","did":"did:dev:gubVIszw-u_d5PVTh-oc8CKAhM9C-ne5G_yUK5BDaXc","ip":"192.168.1.100","sys_hostname":"LZC-USWORK-UPDATED","base_os_info":"Ubuntu 22.04","cpu_info":"AMD Ryzen 7 5800X","cpu_usage":1.5,"total_mem":67392299008,"mem_usage":6.0}"#;
        let updated_did = "did:dev:gubVIszw-u_d5PVTh-oc8CKAhM9C-ne5G_yUK5BDaXc-updated";
        let updated_mini_config_jwt = "eyJhbGciOiJFZERTQSJ9.eyJkaWQiOiJkaWQ6ZGV2Om9vZDEiLCJvd25lciI6ImRpZDplbnM6bHpjIiwiZXhwIjoyMDQ0ODIzMzM2fQ.updated_signature";
        db.update_device_by_name(
            "lzc",
            "ood1",
            updated_did,
            updated_mini_config_jwt,
            "192.168.1.200",
            updated_device_info_str,
        )
        .await?;
        println!("Updated device by name with new DID, mini_config_jwt, IP and description");

        if let Some(device_info) = db.query_device_by_name("lzc", "ood1").await? {
            println!("Updated device DID: {}", device_info.did);
            println!("Updated device IP: {}", device_info.ip);
            println!("Updated mini_config_jwt: {}", device_info.mini_config_jwt);
            assert_eq!(device_info.did, updated_did, "DID should be updated");
            assert_eq!(device_info.ip, "192.168.1.200", "IP should be updated");
            assert_eq!(
                device_info.mini_config_jwt, updated_mini_config_jwt,
                "mini_config_jwt should be updated"
            );
        }

        // 测试使用 SNUserInfo 结构体 - 验证所有字段都被正确填充
        if let Some(user_info) = db.get_user_info("lzc").await? {
            println!("\n=== User Info (by username) - Final State ===");
            println!("User info: {:?}", user_info);
            println!("State: {:?}", user_info.state);
            println!("Public key: {}", user_info.public_key);
            println!("Zone config: {}", user_info.zone_config);
            println!(
                "Self cert: {} (should be true after update)",
                user_info.self_cert
            );
            assert_eq!(
                user_info.self_cert, true,
                "self_cert should be true after update"
            );
            if let Some(domain) = &user_info.user_domain {
                println!("User domain: {}", domain);
            }
            if let Some(sn_ips) = &user_info.sn_ips {
                println!("SN IPs: {}", sn_ips);
            }
        }

        // 测试通过域名查询用户信息 - 验证所有字段都被正确填充
        if let Some(user_info) = db.get_user_info_by_domain("app1.www.zhicong.me").await? {
            println!("\n=== User Info (by domain) ===");
            println!("User info by domain: {:?}", user_info);
            if let Some(username) = &user_info.username {
                println!("Username from domain query: {}", username);
            }
            println!("State: {:?}", user_info.state);
            println!("Public key from domain query: {}", user_info.public_key);
            println!("Zone config: {}", user_info.zone_config);
            println!("Self cert: {} (should be true)", user_info.self_cert);
            assert_eq!(
                user_info.self_cert, true,
                "self_cert should be true in domain query"
            );
            if let Some(domain) = &user_info.user_domain {
                println!("User domain from query: {}", domain);
            }
            if let Some(sn_ips) = &user_info.sn_ips {
                println!("SN IPs from domain query: {}", sn_ips);
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_user_domain_history_blocks_overlapping_rebinds() -> SnResult<()> {
        let db_file = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let db = SqliteSnDB::new_by_path(db_file.path().to_str().unwrap()).await?;
        db.initialize_database().await?;

        db.register_user_directly("user_b", "pk_b", "", Some("bob.abc.com".to_string()))
            .await?;
        db.register_user_directly("user_a", "pk_a", "", None)
            .await?;

        db.update_user_domain("user_b", None).await?;

        let parent_err = db
            .update_user_domain("user_a", Some("abc.com".to_string()))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            parent_err.contains("conflicts with historical domain bob.abc.com"),
            "unexpected parent conflict error: {}",
            parent_err
        );

        let child_err = db
            .update_user_domain("user_a", Some("home.bob.abc.com".to_string()))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            child_err.contains("conflicts with historical domain bob.abc.com"),
            "unexpected child conflict error: {}",
            child_err
        );

        db.update_user_domain("user_a", Some("alice.abc.com".to_string()))
            .await?;

        db.update_user_domain("user_b", Some("bob.abc.com".to_string()))
            .await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_register_device_upserts_by_owner_and_device_name() -> SnResult<()> {
        let db_file = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let db = SqliteSnDB::new_by_path(db_file.path().to_str().unwrap()).await?;
        db.initialize_database().await?;

        db.register_device(
            "wugren004",
            "ood1",
            "did:dev:old",
            "old-mini-config-jwt",
            "127.0.0.1",
            r#"{"id":"did:dev:old","name":"ood1"}"#,
        )
        .await?;
        db.register_device(
            "wugren004",
            "ood1",
            "did:dev:new",
            "new-mini-config-jwt",
            "192.168.122.100",
            r#"{"id":"did:dev:new","name":"ood1"}"#,
        )
        .await?;

        let devices = db.list_user_devices("wugren004").await?;
        assert_eq!(devices.len(), 1);

        let device = db.query_device_by_name("wugren004", "ood1").await?.unwrap();
        assert_eq!(device.did, "did:dev:new");
        assert_eq!(device.ip, "192.168.122.100");
        assert_eq!(device.mini_config_jwt, "new-mini-config-jwt");
        assert!(db.query_device("did:dev:old").await?.is_none());

        Ok(())
    }
}
