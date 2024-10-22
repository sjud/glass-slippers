/*
    The proxy client is used by the proxy to communicate with the auth backend during request/response filters.
*/

use axum::async_trait;

use super::data_model::{
    AntiCsrfToken, AuthClientError, AuthClientUnixSocket, AuthorizationId, SessionId,
};
#[async_trait]
pub trait AuthProxyClient {
    async fn create_anti_csrf_token(
        &self,
        session_id: SessionId,
    ) -> Result<AntiCsrfToken, AuthClientError>;
    async fn check_anti_csrf_token(
        &self,
        token: AntiCsrfToken,
        session_id: SessionId,
    ) -> Result<bool, AuthClientError>;
    /// Returns an AuthorizationId Uuid
    async fn check_session(
        &self,
        session_id: SessionId,
    ) -> Result<Option<AuthorizationId>, AuthClientError>;
    async fn create_session(&self) -> Result<SessionId, AuthClientError>;
}

#[async_trait]
impl AuthProxyClient for AuthClientUnixSocket {
    #[tracing::instrument(skip_all, err)]
    async fn create_anti_csrf_token(
        &self,
        session_id: SessionId,
    ) -> Result<AntiCsrfToken, AuthClientError> {
        self.req("/create_anti_csrf_token", session_id).await
    }

    /// Will return true if the anti_csrf_token and the session_id are a valid combination.
    /// Remember that an anti_csrf_token is just a key to the session id except we store it in headers instead of a cookie.
    #[tracing::instrument(skip_all, err)]
    async fn check_anti_csrf_token(
        &self,
        token: AntiCsrfToken,
        session_id: SessionId,
    ) -> Result<bool, AuthClientError> {
        self.req("/check_anti_csrf_token", (token, session_id))
            .await
    }
    /// [`crate::auth::auth::AuthSessionDb::check_session`]
    #[tracing::instrument(skip_all, err)]
    async fn check_session(
        &self,
        session_id: SessionId,
    ) -> Result<Option<AuthorizationId>, AuthClientError> {
        self.req("/check_session", session_id).await
    }

    #[tracing::instrument(skip_all, err)]
    async fn create_session(&self) -> Result<SessionId, AuthClientError> {
        self.req("/create_session", ()).await
    }
}
