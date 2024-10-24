use axum::{
    async_trait,
    body::{Body, Bytes},
    extract::FromRequestParts,
};
use http::StatusCode;
use http_body_util::BodyExt as _;
use hyper::client::conn::http1::SendRequest;
/*
    Our Data Model revolves around creating an authentication attempt, which is Identification (who the user is) + our authentication method.
    I.e A password, or a two factor or a single sign on from FANG etc.
    And the systems result.
    So the Client collects the info, builds the pattern sends it to the server and gets back a result.
*/
use hyper_util::rt::TokioIo;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{error::Error, ops::Deref, str::FromStr as _};
use thiserror::Error as ThisError;
use tokio::net::UnixStream;
use uuid::Uuid;

use crate::server::SessionId;

pub type AuthorizationSessionId = Uuid;
pub type AntiCsrfToken = Uuid;
pub type VerificationCode = String;
/// How the sytem will identify the user in the database. We combine Identification with Authentication to find an AuthorizationId match in the database.
pub type Identification = String;

/// AuthenticationAttempt is given to the AuthenticationClient
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticationAttempt {
    pub identification: Identification,
    pub authentication: Authentication,
    pub anti_csrf_token: Option<AntiCsrfToken>,
}

impl AuthenticationAttempt {
    /// This is the method if you are using email(or username) and password as identification and authentication in the browser.
    /// It expects a AntiCsrfToken generated by the system, See `AuthenticationClient::anti_csrf_token()`.
    /// And an email and password. The csrf token should be attached in a hidden field to the form you ask for the email/username and password on.
    /// There's no meaningful difference in this step wether you use username or email, they are both just strings in the database for lookup at this point.
    pub fn new_browser_password<S: AsRef<str>>(
        identification: S,
        password: S,
        anti_csrf_token: AntiCsrfToken,
    ) -> Self {
        Self {
            identification: identification.as_ref().to_string(),
            authentication: Authentication::Password(password.as_ref().to_string()),
            anti_csrf_token: Some(anti_csrf_token),
        }
    }
}

/// CreateAuthentication is given to the AuthenticationClient,
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateUnverifiedAuthentication {
    pub identification: Identification,
    pub contact: Contact,
    pub authentication: Authentication,
    pub anti_csrf_token: Option<AntiCsrfToken>,
}

impl CreateUnverifiedAuthentication {
    /// This is the method to use if you are using email and password as identification and authentication on the browser.
    /// Here's how to use this method.
    /// Create a csrf token,
    /// pass the csrf token into your registration form in a hidden field.
    /// Collect email & password & the csrf_token from the form the user submits.
    /// Put all that information in here.
    /// Take CreateAuthenticationAttempt and give that to `AuthenticationClient::create_authentication`
    /// see the docs for `AuthenticationClient::create_authentication` for next steps.
    pub fn new_browser_email_password<S: AsRef<str>>(
        email: S,
        password: S,
        anti_csrf_token: AntiCsrfToken,
    ) -> Self {
        Self {
            identification: email.as_ref().to_string(),
            contact: Contact::Email(email.as_ref().to_string()),
            authentication: Authentication::Password(password.as_ref().to_string()),
            anti_csrf_token: Some(anti_csrf_token),
        }
    }
    /// This is the method to use if you are using username and password as identification and authentication on the browser.
    /// AND if you are using an email as a contact to verify the user.
    /// Here's how to use this method.
    /// Create a csrf token,
    /// pass the csrf token into your registration form in a hidden field.
    /// Collect username, password, email & the csrf_token from the form the user submits.
    /// Put all that information in here.
    /// Take CreateAuthenticationAttempt and give that to `AuthenticationClient::create_authentication`
    /// see the docs for `AuthenticationClient::create_authentication` for next steps.
    pub fn new_browser_username_password_contact_email<S: AsRef<str>>(
        username: S,
        email: S,
        password: S,
        anti_csrf_token: AntiCsrfToken,
    ) -> Self {
        Self {
            identification: username.as_ref().to_string(),
            contact: Contact::Email(email.as_ref().to_string()),
            authentication: Authentication::Password(password.as_ref().to_string()),
            anti_csrf_token: Some(anti_csrf_token),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticationCreated {
    pub contact: Contact,
    pub verification: VerificationCode,
}

/// How the system will contact the user for verification, registration, recovery, two-factor, account compromise, etc.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Contact {
    Email(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Authentication {
    Password(String),
    // Todo SingleSignOn(SSOMethod),
    // Todo TwoFactor(TwoFactorMethod),
}
/// There is no CreateVerification, a verification is created when you call `AuthenticationClient::create_unverified_authentication`
/// Then the verification must be fulfilled by the code given in the AuthenticationCreated.verification field
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationAttempt {
    pub identification: Identification,
    pub code: String,
    pub anti_csrf_token: Option<AntiCsrfToken>,
}

impl VerificationAttempt {
    /// After sending a code to the users contact, collect the code in the browser alongside the csrf_token from the form used to gather the input
    pub fn new_browser(
        identification: Identification,
        code: String,
        anti_csrf_token: AntiCsrfToken,
    ) -> Self {
        Self {
            identification,
            code,
            anti_csrf_token: Some(anti_csrf_token),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateRecovery {
    pub contact: Contact,
    pub anti_csrf_token: Option<AntiCsrfToken>,
}
impl CreateRecovery {
    /// How to use this.
    /// Create a recovery form on your website with a field "email" and a hidden field "anti_csrf_token" which is initialized to the value
    /// produced by `AuthenticationClient::anti_csrf_token`
    /// collect the input, and produce a CreateRecovery using this method.
    /// Pass the CreateRecovery to AuthenticationClient::create_recovery
    /// It will create a Recovery and return it to you.
    pub fn new_browser_email<S: AsRef<str>>(email: S, anti_csrf_token: AntiCsrfToken) -> Self {
        Self {
            contact: Contact::Email(email.as_ref().to_string()),
            anti_csrf_token: Some(anti_csrf_token),
        }
    }
}
/// If you've been given this type by the system, a recovery has been created by the user hasn't been informed yet.
/// Use the contact in the recovery to send the code to the user. The user should likely already be on the verify_recovery page
/// on your client. I.e after having been redirected, this is important since some email clients will block emails with links in them
/// and the form will also inform users what to do next.
/// Send the code to the user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Recovery {
    pub contact: Contact,
    pub code: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttemptRecovery {
    pub code: String,
    pub anti_csrf_token: Option<AntiCsrfToken>,
}
impl AttemptRecovery {
    /// Use this method after the user submits their code on your recovery page
    pub fn new_browser(code: String, anti_csrf_token: AntiCsrfToken) -> Self {
        Self {
            code,
            anti_csrf_token: Some(anti_csrf_token),
        }
    }
}

/// Don't leak this error to the client and don't return a statuscode 500 to the client if receiving this error from the system.
/// Instead return OK "Check your point of contact", so that you don't leak private information and allow account enumeration.
/// If you get an error about an internal system, i.e the client failed then you can return that information to allow the user
/// to decide what to do next etc.
#[derive(ThisError, Deserialize, Serialize, Debug)]
pub enum CreateRecoveryError {
    #[error("Contact doesn't exist")]
    ContactDoesntExist,
}

#[derive(ThisError, Deserialize, Serialize, Debug)]
pub enum RecoveryError {
    #[error("Verification timed out.")]
    Timeout,
    #[error("Incorrect recoveru code.")]
    InvalidCode,
    #[error("Recovery not found.")]
    NotFound,
}

/// Every input, regardless of error or sucess to the create_authentication method should return a message with the same meaning to the user.
/// Along the lines of "Check your point of contact for further instructions."
/// This is to avoid leaking the existence of accounts in the system.
/// The exception being if an internal error occured.
/// Don't map errors into 500 status's to return from functions.
/// Don't send error messages produced by the system to users.
/// Instead return Status 200 and "Check your point of contact for further information".
/// Unless an internal error occurred.
#[derive(ThisError, Deserialize, Serialize, Debug)]
pub enum CreateAuthenticationError {
    #[error("Identification already exists in the sytem.")]
    IdentificationAlreadyExists,
}

/// The authentication error. Return a generic authentication error message to the user.
/// i.e "The email / password combo is incorrect or the email does not exist in the database."
/// Don't return the error messages associated with this error to the user, they are for your internal logs.
/// If this error occurs return an error status handle to the user, instead return StatusCode::OK with a generic message that does not
/// leak the existence of your users in the system.
/// If another error occured, such as the client failed etc. Then you can return a 500 StatusCode to the user.
#[derive(ThisError, Deserialize, Serialize, Debug)]
pub enum AuthenticationError {
    #[error("Credentials not found.")]
    IdentificationDoesNotExist,
    #[error("Credentials incorrect.")]
    IncorrectCredentials,
}

/*
// What we store in the database.
pub struct Authentication {
    pub auth_id: Uuid,
    pub identification: Identification,
    pub authentication: Authentication,
}*/

/// You should let you users know detailed error messages about the verification process.
/// Verification will only exist in a specific window, and outside of that window won't leak information.
/// Generally making it easy to verify an account is more important than sharing knowledge of whether a verification is pending for an email address.
#[derive(ThisError, Deserialize, Serialize, Debug)]
pub enum VerificationError {
    #[error("Verification timed out.")]
    Timeout,
    #[error("Incorrect verification code.")]
    InvalidCode,
    #[error("Verification not found.")]
    NotFound,
}

pub type AuthClientResult<T> = Result<T, AuthClientError>;

#[axum::async_trait]
pub trait AuthenticationClient {
    async fn create_anti_csrf_token(
        &self,
        session_id: SessionId,
    ) -> AuthClientResult<AntiCsrfToken>;
    async fn check_anti_csrf_token(
        &self,
        token: AntiCsrfToken,
        session_id: SessionId,
    ) -> AuthClientResult<AntiCsrfToken>;

    /// Collect AuthenticationAttempt data from a Login form and give to the authenticate method on the AuthenticationClient.
    /// It will send it to the system which will attempt to match the data in the attempt with an entry in the database.
    /// If successful it will produce an AuthorizationSessionId, which is a Uuid that needs to be put into a cookie.
    /// Later when the user returns, the AuthorizationSessionId will be turned into a x-auth-id header for AuthorizationId
    /// (AuthorizationId is not provided by the AuthenticationClient, it is only the product of extracting AuthorizationId from the request which).
    /// Complete view:
    /// A user inserts there credentials, gets a AuthorizationSessionId, this ID needs to be added to the user's client via a Cookie.
    ///
    /// ```ignore
    ///     async fn login_handler(
    ///                 State(authentication_client):State<AuthenticationClient>,
    ///                 ExtractLoginForm((username,password,anti_csrf_token)):ExtractLoginForm
    ///             ) -> impl IntoResponse {
    ///         let authorization_session_id = authentication_client.authenticate(Attempt::new_browser_password(username,password,anti_csrf_token))
    ///             .await?;
    ///         // Sets the x-auth-session-id header.
    ///         set_auth_session_cookie(authorization_session_id);
    ///     }
    /// ```
    ///
    /// On future requests the proxy will map the x-auth-session-id to an x-auth-id. There is a AuthorizationId that implementions FromRequestParts,
    /// which can be used in handlers or in other request extractors.
    async fn authenticate(
        &self,
        attempt: AuthenticationAttempt,
    ) -> AuthClientResult<Result<AuthorizationSessionId, AuthenticationError>>;

    /// If the verification is OK, then the system won't produce a value.
    /// But now the authenticate method will sucessfully return given the data provided to the create_authentication method.
    async fn verify(
        &self,
        attempt: VerificationAttempt,
    ) -> AuthClientResult<Result<(), VerificationError>>;

    /// If the creation suceeded then the system will return the contact input alongside a verification code.
    /// Send the verification code to the user with a link back to your site to collect the verification code.
    async fn create_unverified_authentication(
        &self,
        create_authentication: CreateUnverifiedAuthentication,
    ) -> AuthClientResult<Result<AuthenticationCreated, CreateAuthenticationError>>;

    /// The system takes a point of contact, and creates a recovery code.
    /// It will return the contact input and the recovery code.
    /// Send the recovery code to the contact with a link to an a
    async fn create_recovery(
        &self,
        contact: Contact,
    ) -> AuthClientResult<Result<Recovery, CreateRecoveryError>>;

    /// Attempting recovery will produce an authorization id, the same as authenticating. Recovery is basically authentication by secondary means.
    /// See authenticate method documentation for how to use AuthorizationSessionId
    async fn recover(
        &self,
        attempt: AttemptRecovery,
    ) -> AuthClientResult<Result<AuthorizationSessionId, RecoveryError>>;

    /// Check to see if a contact exists in the system. Idempotent existence lookup that returns a boolean.
    async fn contact_exists(&self, contact: Contact) -> AuthClientResult<bool>;
}
#[derive(Clone, Debug)]
pub struct AuthClientUnixSocket;

#[derive(ThisError, Debug)]
pub enum AuthClientError {
    #[error(transparent)]
    StdIo(#[from] std::io::Error),
    #[error(transparent)]
    Http(#[from] http::Error),
    #[error(transparent)]
    Hyper(#[from] hyper::Error),
    #[error(transparent)]
    Bincode(#[from] Box<bincode::ErrorKind>),
}
impl AuthClientUnixSocket {
    pub async fn req<Resp: DeserializeOwned, Body: Serialize>(
        &self,
        path: &'static str,
        body: Option<Body>,
    ) -> Result<Resp, AuthClientError> {
        // We establish a new connection for each request. We could hypothetically create a connection pool, but would the lookup into the pool
        // be faster than this? And by how much? And will this even be a bottleneck?

        let stream = UnixStream::connect("/tmp/glass-slippers-auth-server.socket").await?;

        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;

        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                tracing::error!("{err:?}");
            }
        });
        let body = {
            if let Some(body) = body {
                let body = bincode::serialize(&body)?;
                axum::body::Body::from(body)
            } else {
                axum::body::Body::empty()
            }
        };

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(&format!("http://EMPTY.com/{path}"))
            .body(body)?;

        let response = sender.send_request(request).await?;
        let body = response.collect().await?.to_bytes();
        let resp = bincode::deserialize::<Resp>(&*body)?;
        Ok(resp)
    }
}

#[axum::async_trait]
impl AuthenticationClient for AuthClientUnixSocket {
    async fn create_anti_csrf_token(
        &self,
        session_id: SessionId,
    ) -> AuthClientResult<AntiCsrfToken> {
        self.req("/create_anti_csrf_token", Some(session_id)).await
    }
    async fn check_anti_csrf_token(
        &self,
        token: AntiCsrfToken,
        session_id: SessionId,
    ) -> AuthClientResult<AntiCsrfToken> {
        self.req("/check_anti_csrf_token", Some((token, session_id)))
            .await
    }
    async fn authenticate(
        &self,
        attempt: AuthenticationAttempt,
    ) -> AuthClientResult<Result<AuthorizationSessionId, AuthenticationError>> {
        self.req("/authenticate", Some(attempt)).await
    }

    async fn verify(
        &self,
        attempt: VerificationAttempt,
    ) -> AuthClientResult<Result<(), VerificationError>> {
        self.req("/verify", Some(attempt)).await
    }

    async fn create_unverified_authentication(
        &self,
        create_authentication: CreateUnverifiedAuthentication,
    ) -> AuthClientResult<Result<AuthenticationCreated, CreateAuthenticationError>> {
        self.req(
            "/create_unverified_authentication",
            Some(create_authentication),
        )
        .await
    }

    async fn create_recovery(
        &self,
        contact: Contact,
    ) -> AuthClientResult<Result<Recovery, CreateRecoveryError>> {
        self.req("/create_recovery", Some(contact)).await
    }

    async fn recover(
        &self,
        attempt: AttemptRecovery,
    ) -> AuthClientResult<Result<AuthorizationSessionId, RecoveryError>> {
        self.req("/recover", Some(attempt)).await
    }

    async fn contact_exists(&self, contact: Contact) -> AuthClientResult<bool> {
        self.req("/contact_exists", Some(contact)).await
    }
}

pub static X_AUTH_ID_HEADER_NAME: &'static str = "x-auth-id";

/// This type implements FromRequestParts, and it parses the id given by the system in the authorization header, most likely "x-auth-id".
/// If you call this extractor and there's no value in the header or the header doesnt exist it will return a 401 UNAUTHORIZED status code.
/// If should never return 500 INTERNAL_SERVER_ERROR, and if it does so that's a bug in this libraries code.
///
/// This type derefs into Uuid.
#[derive(Copy, Clone, Debug, Default)]
pub struct AuthorizationId(pub Uuid);
impl AuthorizationId {
    /// Checks to see if the uuid is default before accepting.
    pub fn new(id: Uuid) -> Option<Self> {
        id.ne(&Uuid::default()).then(move || AuthorizationId(id))
    }
}
impl Deref for AuthorizationId {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthorizationId {
    type Rejection = (http::StatusCode, ());

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .headers
            .get(X_AUTH_ID_HEADER_NAME)
            .ok_or((StatusCode::UNAUTHORIZED, ()))
            .and_then(|id| {
                id.to_str()
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))
            })
            .and_then(|id| Uuid::from_str(id).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ())))
            .and_then(|id| AuthorizationId::new(id).ok_or((StatusCode::INTERNAL_SERVER_ERROR, ())))
    }
}

/*
    Each user has a session and session id, the session id is sent to the server via cookie
    When a user is authorized a new session id is issued which maps to an authorization id, otherwise it's just a value that we use to generate the anti-csrf-token
    csrf tokens are associated with session ids and sent in x-anti-csrf headers
    csrf token are generated using hmac(session_id,SECRET)
    and the secret is generate on auth system start based on secure cryptographic function not vulnerable to timing attacks etc.
    so to get an x-auth-id header from a session-id, we need to get the session-id from the token and match that to the anti-csrf-token header
    if we only have 1 or the other then no good.
*/
