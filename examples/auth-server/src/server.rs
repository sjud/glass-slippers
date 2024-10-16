use axum::{
    async_trait,
    body::Bytes,
    extract::{connect_info, State},
    http::Request,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use fred::{
    clients::RedisClient,
    prelude::{ClientLike as _, KeysInterface, RedisPool},
    types::{ReconnectPolicy, RedisConfig},
};
use http::StatusCode;
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server,
};
use sqlx::{Executor as _, SqlitePool};
use std::{
    convert::Infallible, error::Error, fs::OpenOptions, ops::Deref, path::PathBuf,
    process::Command, str::FromStr, sync::Arc, time::Duration,
};
use tokio::net::{unix::UCred, UnixListener, UnixStream};
use tower::Service;
use uuid::Uuid;

use crate::data_model::{AntiCsrfToken, AuthorizationId};
pub async fn server() {
    let path = PathBuf::from("/tmp/glass-slippers-auth-server.socket");

    let _ = tokio::fs::remove_file(&path).await;

    let uds = UnixListener::bind(path.clone()).unwrap();

    tokio::spawn(async move {
        let app = Router::new()
            .route("/create_anti_csrf_token", post(create_anti_csrf_token))
            .route("/check_anti_csrf_token", post(check_anti_csrf_token))
            .route("/authenticate", post(authenticate))
            .route("/verify", post(verify))
            .route(
                "/create_unverified_authentication",
                post(create_unverified_authentication),
            )
            .route("/create_recovery", post(create_recovery))
            .route("/recover", post(recover))
            .route("/contact_exists", post(contact_exists))
            .with_state(AuthServerState::new().await);

        #[derive(Clone, Debug)]
        #[allow(dead_code)]
        struct UdsConnectInfo {
            peer_addr: Arc<tokio::net::unix::SocketAddr>,
            peer_cred: UCred,
        }

        impl connect_info::Connected<&UnixStream> for UdsConnectInfo {
            fn connect_info(target: &UnixStream) -> Self {
                let peer_addr = target.peer_addr().unwrap();
                let peer_cred = target.peer_cred().unwrap();

                Self {
                    peer_addr: Arc::new(peer_addr),
                    peer_cred,
                }
            }
        }

        let mut make_service = app.into_make_service_with_connect_info::<UdsConnectInfo>();

        // See https://github.com/tokio-rs/axum/blob/main/examples/serve-with-hyper/src/main.rs for
        // more details about this setup
        loop {
            let (socket, _remote_addr) = uds.accept().await.unwrap();

            fn unwrap_infallible<T>(result: Result<T, Infallible>) -> T {
                match result {
                    Ok(value) => value,
                    Err(err) => match err {},
                }
            }

            let tower_service = unwrap_infallible(make_service.call(&socket).await);

            tokio::spawn(async move {
                let socket = TokioIo::new(socket);

                let hyper_service =
                    hyper::service::service_fn(move |request: Request<Incoming>| {
                        tower_service.clone().call(request)
                    });

                if let Err(err) = server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(socket, hyper_service)
                    .await
                {
                    eprintln!("failed to serve connection: {err:#}");
                }
            });
        }
    });
}
// handlers
async fn create_anti_csrf_token(
    State(state): State<AuthServerState>,
    body: Bytes,
) -> impl IntoResponse {
    let session_id = Uuid::from_slice(&body).map_err(|_| (StatusCode::BAD_REQUEST, ()))?;
    let token = state
        .reddis
        .create_anti_csrf_token(session_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?;
    // turbo fish is because compiler is confused about IntoResponse implementation
    Ok::<(StatusCode, _), (StatusCode, _)>((StatusCode::OK, token.as_bytes().clone()))
}
pub type CheckAntiCsrfTokenBody = (AntiCsrfToken, SessionId);

async fn check_anti_csrf_token(
    State(state): State<AuthServerState>,
    body: Bytes,
) -> impl IntoResponse {
    let (token, session_id) = bincode::deserialize::<CheckAntiCsrfTokenBody>(&body)
        .map_err(|_| (StatusCode::BAD_REQUEST, ()))?;
    let is_protected = state
        .reddis
        .check_anti_csrf_token(token, session_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?;
    Ok::<(StatusCode, _), (StatusCode, _)>((
        StatusCode::OK,
        bincode::serialize(&is_protected).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?,
    ))
}
async fn authenticate(State(state): State<AuthServerState>, body: Bytes) -> impl IntoResponse {
    let (username, password) = bincode::deserialize::<(String, String)>(&body)
        .map_err(|_| (StatusCode::BAD_REQUEST, ()))?;
    if let Some(auth_id) = state
        .sqlite
        .auth_id_by_username_password(username, password)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, ()))?
    {
        state
            .reddis
            .create_session(Some(auth_id))
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?;
    }
    Ok::<(StatusCode, _), (StatusCode, _)>((StatusCode::OK, ()))
}

async fn verify(State(state): State<AuthServerState>) -> impl IntoResponse {}

async fn create_unverified_authentication(
    State(state): State<AuthServerState>,
) -> impl IntoResponse {
}

async fn create_recovery(State(state): State<AuthServerState>) -> impl IntoResponse {}

async fn recover(State(state): State<AuthServerState>) -> impl IntoResponse {}

async fn contact_exists(State(state): State<AuthServerState>) -> impl IntoResponse {}

#[derive(Clone)]
pub struct AuthServerState {
    /// We use reddis for, csrf_tokens, sessions (does not persist)
    reddis: RedisPool,
    // We use sqlite for users, (persists between resets)
    sqlite: SqlitePool,
    /*
       When a user is created they are written to sqlite,
       when a user is authenticated we authenticate against sqlite,
       then we create a session,
       future authorizations i.e when we grab an x-auth-session-id header value
       are compared against the reddit db.
    */
}

impl AuthServerState {
    async fn new() -> Self {
        let reddis = build_reddis().await;
        let sqlite = build_sqlite().await;
        Self { reddis, sqlite }
    }
}
async fn build_sqlite() -> SqlitePool {
    let path = "auth.db";
    OpenOptions::new()
        .write(true)
        .create(true)
        .read(true)
        .truncate(false)
        .open(path)
        .unwrap();
    let conn = SqlitePool::connect(path).await.unwrap();
    conn.execute(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            auth_id TEXT PRIMARY KEY,  -- UUID stored as TEXT
            contact TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            verified INTEGER NOT NULL DEFAULT 0 -- 0 is not verified, 1 is verified.
        )
    "#,
    )
    .await
    .unwrap();

    // Unique columns are already indexed, otherwise we'd index it here.

    conn
}

type UnhashedPassword = String;
#[async_trait]
trait UserDatabase {
    /// Create a user in the database, the username must be unique. It will assign a Uuid ( AuthorizationId ) to the user.
    /// Make sure to hash the password before you insert into the database.
    async fn create_user(
        &self,
        contact: String,
        username: String,
        password: UnhashedPassword,
    ) -> Result<(), sqlx::Error>;
    /// Deletes a user given an authorization id.
    async fn delete_user(&self, auth_id: AuthorizationId) -> Result<(), sqlx::Error>;
    /// Finds a User based on their authorization id, and then for any Some(argument) will update the associated field.
    /// Verification is a one way operation, so this sets verified to 1 if verified is true, but if verified is false it does nothing.
    async fn edit_user(
        &self,
        auth_id: AuthorizationId,
        contact: Option<String>,
        username: Option<String>,
        password: Option<UnhashedPassword>,
        verified: bool,
    ) -> Result<(), sqlx::Error>;
    /// This will match the username + password against the database.
    /// It will return an Some(AuthorizationId) if matched, None if there was no match.
    async fn auth_id_by_username_password(
        &self,
        username: String,
        password: UnhashedPassword,
    ) -> Result<Option<AuthorizationId>, sqlx::Error>;
}

#[async_trait]
impl UserDatabase for SqlitePool {
    async fn create_user(
        &self,
        contact: String,
        username: String,
        password: UnhashedPassword,
    ) -> Result<(), sqlx::Error> {
        let auth_id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO users (auth_id, contact, username, password)
            VALUES ( ?1, ?2, ?3, ?4)
        "#,
        )
        .bind(auth_id)
        .bind(contact)
        .bind(username)
        .bind(&*HashedPassword::new(password))
        .execute(self)
        .await?;
        Ok(())
    }
    async fn delete_user(&self, auth_id: AuthorizationId) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            DELETE FROM users WHERE auth_id = ?;
        "#,
        )
        .bind(auth_id.to_string())
        .execute(self)
        .await?;
        Ok(())
    }
    async fn edit_user(
        &self,
        auth_id: AuthorizationId,
        contact: Option<String>,
        username: Option<String>,
        password: Option<UnhashedPassword>,
        verified: bool,
    ) -> Result<(), sqlx::Error> {
        // Create a vector to hold the query parts and parameters
        let mut set_clauses = Vec::new();
        let mut params = Vec::new();

        // Add fields to update if they are provided
        if let Some(contact) = contact {
            set_clauses.push("contact = ?");
            params.push(contact);
        }
        if let Some(username) = username {
            set_clauses.push("username = ?");
            params.push(username);
        }
        if let Some(password) = password {
            set_clauses.push("password = ?");
            params.push(HashedPassword::new(password).clone());
        }

        if verified {
            set_clauses.push("verified = ?");
            params.push(1.to_string());
        }
        // Return early if there's nothing to update
        if set_clauses.is_empty() {
            return Ok(()); // No fields to update, nothing to do
        }

        // Build the final query
        let query = format!(
            "UPDATE users SET {} WHERE auth_id = ?",
            set_clauses.join(", ")
        );

        // Prepare the query and bind the parameters
        let mut query_builder = sqlx::query(&query);
        for param in params {
            query_builder = query_builder.bind(param);
        }
        query_builder = query_builder.bind(auth_id.to_string());

        // Execute the query
        query_builder.execute(self).await?;

        Ok(())
    }

    async fn auth_id_by_username_password(
        &self,
        username: String,
        password: UnhashedPassword,
    ) -> Result<Option<AuthorizationId>, sqlx::Error> {
        if let Some((auth_id, db_password)) = sqlx::query_as::<_, (String, String)>(
            r#"
            SELECT auth_id, password
            FROM users
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(self)
        .await?
        {
            if HashedPassword(db_password).compare(&password) {
                Ok(Uuid::from_str(&auth_id).ok().and_then(AuthorizationId::new))
            } else {
                // wrong password error?
                Ok(None)
            }
        } else {
            // no user found error?
            Ok(None)
        }
    }
}
#[derive(sqlx::Type)]
pub struct HashedPassword(String);
impl Deref for HashedPassword {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl HashedPassword {
    /// Hashes the password.
    pub fn new(password: String) -> Self {
        Self(password_auth::generate_hash(password))
    }
    pub fn compare(&self, unhashed: &String) -> bool {
        let result = password_auth::verify_password(&self.0, unhashed);
        result.is_ok()
    }
}
async fn build_reddis() -> RedisPool {
    Command::new("redis-server")
        .arg("redis.conf")
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    let config = RedisConfig::from_url("redis+unix:///tmp/redis.sock")
        .expect("Failed to create redis config from url");
    let reddis = fred::types::Builder::from_config(config)
        .with_connection_config(|config| {
            config.connection_timeout = Duration::from_secs(10);
        })
        // use exponential backoff, starting at 100 ms and doubling on each failed attempt up to 30 sec
        .set_policy(ReconnectPolicy::new_exponential(0, 100, 30_000, 2))
        .build_pool(20)
        .expect("Failed to create redis pool");
    let handle = reddis.init().await.expect("Failed to connect to redis");
    tokio::spawn(handle);
    reddis
}

pub type SessionId = Uuid;
#[async_trait]
trait AuthSessionDb {
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
    async fn create_session(
        &self,
        auth_id: Option<AuthorizationId>,
    ) -> Result<SessionId, Box<dyn Error>>;
    // given a session_id return an authorization_id;
    async fn check_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<AuthorizationId>, Box<dyn Error>>;
    async fn invalidate_session(&self, session_id: SessionId) -> Result<(), Box<dyn Error>>;
}
#[async_trait]
impl AuthSessionDb for RedisPool {
    async fn create_anti_csrf_token(
        &self,
        session_id: SessionId,
    ) -> Result<AntiCsrfToken, Box<dyn Error>> {
        let token = Uuid::new_v4();
        self.set(
            token.as_bytes().as_slice(),
            session_id.as_bytes(),
            Some(fred::types::Expiration::EX(20)),
            Some(fred::types::SetOptions::NX),
            false,
        )
        .await?;
        Ok(token)
    }
    async fn check_anti_csrf_token(
        &self,
        token: AntiCsrfToken,
        session_id: SessionId,
    ) -> Result<bool, Box<dyn Error>> {
        let stored_session_id = self.get::<[u8; 16], _>(token.as_bytes().as_slice()).await?;
        // refresh
        self.set(
            token.as_bytes().as_slice(),
            stored_session_id.as_slice(),
            Some(fred::types::Expiration::EX(20)),
            Some(fred::types::SetOptions::XX),
            false,
        )
        .await?;
        Ok(Uuid::from_bytes(stored_session_id) == session_id)
    }
    async fn invalidate_csrf_token(&self, token: AntiCsrfToken) -> Result<(), Box<dyn Error>> {
        self.del(token.as_bytes().as_slice()).await?;
        Ok(())
    }
    /// create a session for an OPTIONAL authorization id. returns created session's session_id.
    /// Will store a default uuid (all zeros) if the authorization_id is empty
    async fn create_session(
        &self,
        auth_id: Option<AuthorizationId>,
    ) -> Result<SessionId, Box<dyn Error>> {
        let session_id = Uuid::new_v4();
        self.set(
            session_id.as_bytes().as_slice(),
            auth_id.unwrap_or_default().as_bytes().as_slice(),
            Some(fred::types::Expiration::EX(20)),
            Some(fred::types::SetOptions::NX),
            false,
        )
        .await?;
        Ok(session_id)
    }
    /// given a session_id return a potential authorization id. If the session does not exist, or if the authorization id is default (which is for unauthorized session)
    /// will return None
    async fn check_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<AuthorizationId>, Box<dyn Error>> {
        let auth_id = self
            .get::<[u8; 16], _>(session_id.as_bytes().as_slice())
            .await?;
        // refresh
        self.set(
            session_id.as_bytes().as_slice(),
            auth_id.as_slice(),
            Some(fred::types::Expiration::EX(20)),
            Some(fred::types::SetOptions::XX),
            false,
        )
        .await?;
        Ok(AuthorizationId::new(Uuid::from_bytes(auth_id)))
    }
    async fn invalidate_session(&self, session_id: SessionId) -> Result<(), Box<dyn Error>> {
        self.del(session_id.as_bytes().as_slice()).await?;
        Ok(())
    }
}
