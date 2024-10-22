use crate::data_model::{
    AuthClientError, AuthClientUnixSocket, AuthenticationError,
    AuthorizationSessionId as AuthSessionId, Contact, CreateAuthenticationError,
    CreateRecoveryError, Recovery, RecoveryError, VerificationError,
};
pub type AuthClientResult<T> = Result<T, AuthClientError>;

#[axum::async_trait]
pub trait AuthenticationClient {
    async fn authenticate(
        &self,
        username: String,
        password: String,
    ) -> AuthClientResult<Result<AuthSessionId, AuthenticationError>>;

    async fn verify(
        &self,
        username: String,
        code: String,
    ) -> AuthClientResult<Result<(), VerificationError>>;

    async fn create_unverified_authentication(
        &self,
        contact: String,
        username: String,
        password: String,
    ) -> AuthClientResult<Result<(String, String), CreateAuthenticationError>>;

    async fn create_recovery(
        &self,
        contact: Contact,
    ) -> AuthClientResult<Result<Recovery, CreateRecoveryError>>;

    async fn recover(&self, code: String)
        -> AuthClientResult<Result<AuthSessionId, RecoveryError>>;
}

#[axum::async_trait]
impl AuthenticationClient for AuthClientUnixSocket {
    async fn authenticate(
        &self,
        username: String,
        password: String,
    ) -> AuthClientResult<Result<AuthSessionId, AuthenticationError>> {
        self.req("/authenticate", (username, password)).await
    }

    async fn verify(
        &self,
        username: String,
        code: String,
    ) -> AuthClientResult<Result<(), VerificationError>> {
        self.req("/verify", (username, code)).await
    }

    /// Returns (Contact,Code)
    async fn create_unverified_authentication(
        &self,
        contact: String,
        username: String,
        password: String,
    ) -> AuthClientResult<Result<(String, String), CreateAuthenticationError>> {
        self.req(
            "/create_unverified_authentication",
            (contact, username, password),
        )
        .await
    }

    async fn create_recovery(
        &self,
        contact: Contact,
    ) -> AuthClientResult<Result<Recovery, CreateRecoveryError>> {
        self.req("/create_recovery", contact).await
    }

    async fn recover(
        &self,
        code: String,
    ) -> AuthClientResult<Result<AuthSessionId, RecoveryError>> {
        self.req("/recover", code).await
    }
}
