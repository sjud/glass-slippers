use axum::async_trait;

use redis::{
    AsyncCommands, Client as RedisClient, ExistenceCheck, FromRedisValue, SetExpiry, SetOptions,
    ToRedisArgs,
};
use std::error::Error;
use tokio::process::Command;
use uuid::Uuid;

use super::data_model::{AntiCsrfToken, AuthorizationId, SessionId};

#[async_trait]
pub trait AuthSessionDb: Clone + Send + Sync + 'static {
    async fn build() -> Result<Self, Box<dyn Error + Send + Sync>>;
    async fn create_anti_csrf_token(
        &self,
        session_id: SessionId,
    ) -> Result<AntiCsrfToken, Box<dyn Error>>;
    async fn check_anti_csrf_token(
        &self,
        token: AntiCsrfToken,
        session_id: SessionId,
    ) -> Result<bool, Box<dyn Error>>;
    async fn invalidate_csrf_token(&self, token: AntiCsrfToken) -> Result<(), Box<dyn Error>>;
    // create a session for an authorization id. returns created session's session_id;
    async fn create_session(&self, auth_id: AuthorizationId) -> Result<SessionId, Box<dyn Error>>;
    /// Check session can return three possible states,
    /// None -> There is no Session
    /// Some(auth_id_is_empty) -> There was a session but no auth id
    /// Some(auth_id_valid) -> There was a session and the auth id exists.
    async fn check_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<AuthorizationId>, Box<dyn Error>>;
    async fn invalidate_session(&self, session_id: SessionId) -> Result<(), Box<dyn Error>>;
    async fn create_verification_code(
        &self,
        auth_id: AuthorizationId,
    ) -> Result<String, Box<dyn Error>>;
    async fn get_auth_id_from_verification_code(
        &self,
        code: String,
    ) -> Result<AuthorizationId, Box<dyn Error>>;

    async fn delete_verification_code(&self, code: String) -> Result<(), Box<dyn Error>>;
}

#[async_trait]
impl AuthSessionDb for RedisClient {
    #[tracing::instrument(err)]
    async fn build() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Command::new("redis-server")
            .arg("redis.conf")
            .spawn()?
            .wait()
            .await?;

        let client = redis::Client::open("redis+unix:///tmp/redis.sock")?;
        //tokio::spawn(handle);
        Ok(client)
    }
    #[tracing::instrument(skip(self), err)]
    async fn create_anti_csrf_token(
        &self,
        session_id: SessionId,
    ) -> Result<AntiCsrfToken, Box<dyn Error>> {
        let token = Uuid::new_v4();
        self.set(
            token,
            session_id,
            SetOptions::default()
                .conditional_set(redis::ExistenceCheck::NX)
                .with_expiration(redis::SetExpiry::EX(20)),
        )
        .await
        .map_err(|err| {
            tracing::error!("{err:?}");
            err
        })?;
        Ok(token)
    }
    #[tracing::instrument(skip(self), err)]
    async fn check_anti_csrf_token(
        &self,
        token: AntiCsrfToken,
        session_id: SessionId,
    ) -> Result<bool, Box<dyn Error>> {
        let stored_session_id = self.get::<AntiCsrfToken, SessionId>(token).await?;
        // refresh
        self.set(
            token,
            stored_session_id,
            SetOptions::default()
                .with_expiration(SetExpiry::EX(20))
                .conditional_set(ExistenceCheck::XX),
        )
        .await
        .map_err(|err| {
            tracing::error!("{err:?}");
            err
        })?;
        Ok(stored_session_id == session_id)
    }
    #[tracing::instrument(skip(self), err)]
    async fn invalidate_csrf_token(&self, token: AntiCsrfToken) -> Result<(), Box<dyn Error>> {
        self.del(token).await.map_err(|err| {
            tracing::error!("{err:?}");
            err
        })?;
        Ok(())
    }
    /// create a session for an OPTIONAL authorization id. returns created session's session_id.
    /// Will store a default uuid (all zeros) if the authorization_id is empty
    #[tracing::instrument(skip(self), err)]
    async fn create_session(&self, auth_id: AuthorizationId) -> Result<SessionId, Box<dyn Error>> {
        tracing::error!("set auth id {auth_id:#?}");
        let session_id = Uuid::new_v4();
        self.set(
            session_id,
            auth_id,
            SetOptions::default()
                .conditional_set(ExistenceCheck::NX)
                .with_expiration(SetExpiry::EX(20)),
        )
        .await
        .map_err(|err| {
            tracing::error!("{err:?}");
            err
        })?;

        Ok(session_id)
    }

    #[tracing::instrument(skip(self), err)]
    async fn check_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<AuthorizationId>, Box<dyn Error>> {
        if !self
            .get_multiplexed_async_connection()
            .await?
            .exists::<_, bool>(session_id)
            .await
            .map_err(|err| {
                tracing::error!("{err:?}");
                err
            })?
        {
            tracing::error!("session doesn't exist.");
            return Ok(None);
        }
        tracing::error!("session exists.");
        let auth_id = self
            .get::<SessionId, AuthorizationId>(session_id)
            .await
            .map_err(|err| {
                tracing::error!("{err:?}");
                err
            })?;
        // refresh
        self.set(
            session_id,
            auth_id,
            SetOptions::default()
                .conditional_set(ExistenceCheck::XX)
                .with_expiration(SetExpiry::EX(20)),
        )
        .await
        .map_err(|err| {
            tracing::error!("{err:?}");
            err
        })?;

        Ok(Some(auth_id))
    }
    #[tracing::instrument(skip(self), err)]
    async fn invalidate_session(&self, session_id: SessionId) -> Result<(), Box<dyn Error>> {
        self.del(session_id.as_bytes().as_slice())
            .await
            .map_err(|err| {
                tracing::error!("{err:?}");
                err
            })?;
        Ok(())
    }
    #[tracing::instrument(skip_all, err)]
    async fn create_verification_code(
        &self,
        auth_id: AuthorizationId,
    ) -> Result<String, Box<dyn Error>> {
        let code = generate_verification_code();
        self.set(
            &code,
            auth_id,
            SetOptions::default().with_expiration(SetExpiry::EX(60 * 60)),
        )
        .await
        .map_err(|err| {
            tracing::error!("{err:?}");
            err
        })?;
        Ok(code)
    }

    #[tracing::instrument(skip_all, err)]
    async fn get_auth_id_from_verification_code(
        &self,
        code: String,
    ) -> Result<AuthorizationId, Box<dyn Error>> {
        let auth_id = self
            .get::<String, AuthorizationId>(code)
            .await
            .map_err(|err| {
                tracing::error!("{err:?}");
                err
            })?;
        Ok(auth_id)
    }
    #[tracing::instrument(skip_all, err)]
    async fn delete_verification_code(&self, code: String) -> Result<(), Box<dyn Error>> {
        self.del(code).await.map_err(|err| {
            tracing::error!("{err:?}");
            err
        })?;
        Ok(())
    }
}

#[async_trait]
pub trait SimpleRedis {
    async fn get<K: ToRedisArgs + Send + Sync, V: FromRedisValue>(
        &self,
        key: K,
    ) -> Result<V, Box<dyn Error>>;
    async fn set<K: ToRedisArgs + Send + Sync, V: ToRedisArgs + Send + Sync>(
        &self,
        key: K,
        value: V,
        options: SetOptions,
    ) -> Result<(), Box<dyn Error>>;
    async fn del<K: ToRedisArgs + Send + Sync>(&self, key: K) -> Result<(), Box<dyn Error>>;
}

#[async_trait]
impl SimpleRedis for RedisClient {
    async fn get<K: ToRedisArgs + Send + Sync, V: FromRedisValue>(
        &self,
        key: K,
    ) -> Result<V, Box<dyn Error>> {
        let value = self
            .get_multiplexed_async_connection()
            .await?
            .get(key)
            .await?;
        Ok(value)
    }
    async fn set<K: ToRedisArgs + Send + Sync, V: ToRedisArgs + Send + Sync>(
        &self,
        key: K,
        value: V,
        options: SetOptions,
    ) -> Result<(), Box<dyn Error>> {
        self.get_multiplexed_async_connection()
            .await?
            .set_options(key, value, options)
            .await?;
        Ok(())
    }
    async fn del<K: ToRedisArgs + Send + Sync>(&self, key: K) -> Result<(), Box<dyn Error>> {
        self.get_multiplexed_async_connection()
            .await?
            .del(key)
            .await?;
        Ok(())
    }
}

fn generate_verification_code() -> String {
    use rand::{distributions::Slice, Rng};
    const CODE_LENGTH: usize = 6;
    const VALID_CHARACTERS: [char; 32] = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T',
        'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7', '8', '9',
    ]; // Excludes 0, O, 1, and I

    // Generate a cryptographically secure random alphanumeric code with the specified length
    let code: String = rand::rngs::OsRng
        .sample_iter(Slice::new(&VALID_CHARACTERS).unwrap())
        .take(CODE_LENGTH)
        .map(|&c| c as char)
        .collect();

    code
}
