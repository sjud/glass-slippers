use axum::{
    body::Bytes,
    extract::{FromRef, State},
    response::IntoResponse,
};
use http::StatusCode;
use uuid::Uuid;

use super::{
    auth_session_db::AuthSessionDb,
    data_model::{
        AntiCsrfToken, AuthorizationId, Contact, CreateUnverifiedAuthentication, SessionId,
    },
    server_state::AuthServerState,
    user_db::UserDatabase,
};
pub type CheckAntiCsrfTokenBody = (AntiCsrfToken, SessionId);

#[tracing::instrument(skip_all)]
pub async fn create_anti_csrf_token<
    SessionDb: AuthSessionDb + FromRef<AuthServerState<SessionDb, UserDb>>,
    UserDb: UserDatabase,
>(
    State(session_db): State<SessionDb>,
    body: Bytes,
) -> impl IntoResponse {
    let session_id = Uuid::from_slice(&body).map_err(|err| {
        tracing::error!("{err:?}");
        (StatusCode::BAD_REQUEST, ())
    })?;
    let token = session_db
        .create_anti_csrf_token(session_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?;
    Ok::<_, (StatusCode, _)>((StatusCode::OK, token.as_bytes().clone()))
}
#[tracing::instrument(skip_all)]
pub async fn check_anti_csrf_token<
    SessionDb: AuthSessionDb + FromRef<AuthServerState<SessionDb, UserDb>>,
    UserDb: UserDatabase,
>(
    State(session_db): State<SessionDb>,
    body: Bytes,
) -> impl IntoResponse {
    let (token, session_id) = bincode::deserialize::<CheckAntiCsrfTokenBody>(&body)
        .map_err(|_| (StatusCode::BAD_REQUEST, ()))?;
    let is_protected = session_db
        .check_anti_csrf_token(token, session_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?;
    Ok::<_, (StatusCode, _)>((
        StatusCode::OK,
        bincode::serialize(&is_protected).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?,
    ))
}
#[tracing::instrument(skip_all)]
pub async fn authenticate<DB1: AuthSessionDb, DB2: UserDatabase>(
    State(state): State<AuthServerState<DB1, DB2>>,
    body: Bytes,
) -> impl IntoResponse {
    // TODO
    // we need to invalidate the current session, and provide a new csrf token, a new session id (one that is mapped to the auth id)
    //  its not enough to create a new session and leave the old one hanging, and it's not enough to set the old session to the new session auth
    let (username, password) = bincode::deserialize::<(String, String)>(&body).map_err(|err| {
        tracing::error!("{err:?}");
        (StatusCode::BAD_REQUEST, ())
    })?;
    let auth_id = state
        .user_db
        .auth_id_by_username_password(username, password)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, ()))?;
    state
        .session_db
        .create_session(auth_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?;
    Ok::<_, (StatusCode, _)>((StatusCode::OK, ()))
}
#[tracing::instrument(skip_all)]
pub async fn create_session<
    SessionDb: AuthSessionDb + FromRef<AuthServerState<SessionDb, UserDb>>,
    UserDb: UserDatabase,
>(
    State(session_db): State<SessionDb>,
) -> impl IntoResponse {
    let session_id = session_db
        .create_session(AuthorizationId::empty())
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?;
    Ok::<_, (StatusCode, _)>((
        StatusCode::OK,
        bincode::serialize(&session_id).map_err(|err| {
            tracing::error!("{err:?}");
            (StatusCode::INTERNAL_SERVER_ERROR, ())
        })?,
    ))
}

#[tracing::instrument(skip_all)]
pub async fn check_session<
    SessionDb: AuthSessionDb + FromRef<AuthServerState<SessionDb, UserDb>>,
    UserDb: UserDatabase,
>(
    State(session_db): State<SessionDb>,
    body: Bytes,
) -> impl IntoResponse {
    let session_id = bincode::deserialize::<Uuid>(&body).map_err(|err| {
        tracing::error!("{err:?}");
        (StatusCode::BAD_REQUEST, ())
    })?;
    let maybe_auth_id = session_db
        .check_session(session_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?;
    Ok::<_, (StatusCode, _)>((
        StatusCode::OK,
        bincode::serialize(&maybe_auth_id).map_err(|err| {
            tracing::error!("{err:?}");
            (StatusCode::INTERNAL_SERVER_ERROR, ())
        })?,
    ))
}

pub async fn verify<DB1: AuthSessionDb, DB2: UserDatabase>(
    State(state): State<AuthServerState<DB1, DB2>>,
    body: Bytes,
) -> impl IntoResponse {
    let code = bincode::deserialize::<String>(&body).map_err(|err| {
        tracing::error!("{err:?}");
        (StatusCode::BAD_REQUEST, ())
    })?;

    let auth_id = state
        .session_db
        .get_auth_id_from_verification_code(code)
        .await
        .map_err(|err| {
            tracing::error!("{err:?}");
            (StatusCode::BAD_REQUEST, ())
        })?;

    state
        .user_db
        .edit_user(auth_id, None, None, None, true)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?;
    Ok::<_, (StatusCode, _)>((StatusCode::OK, ()))
}

pub async fn create_unverified_authentication<DB1: AuthSessionDb, DB2: UserDatabase>(
    State(state): State<AuthServerState<DB1, DB2>>,
    body: Bytes,
) -> impl IntoResponse {
    let create_auth =
        bincode::deserialize::<CreateUnverifiedAuthentication>(&body).map_err(|err| {
            tracing::error!("{err:?}");
            (StatusCode::BAD_REQUEST, ())
        })?;
    let (contact, username, unhashed_password) = create_auth.unwrap_email_password();
    let auth_id = state
        .user_db
        .create_user(&contact, &username, &unhashed_password)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?;
    let code = state
        .session_db
        .create_verification_code(auth_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?;

    Ok::<_, (StatusCode, _)>((
        StatusCode::OK,
        bincode::serialize(&(contact, code)).map_err(|err| {
            tracing::error!("{err:?}");
            (StatusCode::INTERNAL_SERVER_ERROR, ())
        })?,
    ))
}

/// A recovery is just a session that the user can claim by clicking a link in their email.
/// When we create a recovery we return a session id, that is placed in a link sent to the email address and will let the user set the session
/// by following the link. The link should allow the user reset their password and then invalidate the previous session and prompt them to re log in.
pub async fn create_recovery<DB1: AuthSessionDb, DB2: UserDatabase>(
    State(state): State<AuthServerState<DB1, DB2>>,
    body: Bytes,
) -> impl IntoResponse {
    let contact = bincode::deserialize::<Contact>(&body).map_err(|err| {
        tracing::error!("{err:?}");
        (StatusCode::BAD_REQUEST, ())
    })?;
    let contact = match contact {
        Contact::Email(contact) => contact,
    };
    let auth_id = state
        .user_db
        .auth_id_by_contact(contact)
        .await
        .map_err(|err| {
            tracing::error!("{err:?}");
            (StatusCode::BAD_REQUEST, ())
        })?;
    let session_id = state
        .session_db
        .create_session(auth_id)
        .await
        .map_err(|err| {
            tracing::error!("{err:?}");
            (StatusCode::BAD_REQUEST, ())
        })?;
    Ok::<_, (StatusCode, _)>((
        StatusCode::OK,
        bincode::serialize(&session_id).map_err(|err| {
            tracing::error!("{err:?}");
            (StatusCode::INTERNAL_SERVER_ERROR, ())
        })?,
    ))
}

#[tracing::instrument(skip_all)]
pub async fn recover<
    SessionDb: AuthSessionDb + FromRef<AuthServerState<SessionDb, UserDb>>,
    UserDb: UserDatabase,
>(
    State(session_db): State<SessionDb>,
    body: Bytes,
) -> impl IntoResponse {
    // get the session id from the link from the email
    let session_id = bincode::deserialize::<Uuid>(&body).map_err(|err| {
        tracing::error!("{err:?}");
        (StatusCode::BAD_REQUEST, ())
    })?;
    // get the auth id from the session id
    // is none when the session doesn't exist.
    // but is guranteed not to be empty if the session doesnt exist and the session id was sent via attempt recovery email
    // since attempt recovery will always return a valid auth id.
    let maybe_auth_id = session_db
        .check_session(session_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, ()))?;
    Ok::<_, (StatusCode, _)>((
        StatusCode::OK,
        bincode::serialize(&maybe_auth_id).map_err(|err| {
            tracing::error!("{err:?}");
            (StatusCode::INTERNAL_SERVER_ERROR, ())
        })?,
    ))
}
