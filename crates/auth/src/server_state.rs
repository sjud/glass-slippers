use axum::extract::FromRef;
use redis::Client as RedisClient;
use sqlx::SqlitePool;
use std::error::Error;

use super::{auth_session_db::AuthSessionDb, user_db::UserDatabase};

#[derive(Clone)]
pub struct AuthServerState<SessionDb: AuthSessionDb, UserDb: UserDatabase> {
    pub session_db: SessionDb,
    pub user_db: UserDb,
}
impl FromRef<AuthServerState<RedisClient, SqlitePool>> for RedisClient {
    fn from_ref(input: &AuthServerState<RedisClient, SqlitePool>) -> Self {
        input.session_db.clone()
    }
}
impl FromRef<AuthServerState<RedisClient, SqlitePool>> for SqlitePool {
    fn from_ref(input: &AuthServerState<RedisClient, SqlitePool>) -> Self {
        input.user_db.clone()
    }
}
impl AuthServerState<RedisClient, SqlitePool> {
    pub async fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            session_db: RedisClient::build().await?,
            user_db: SqlitePool::build().await?,
        })
    }
}
