use axum::{
    extract::{connect_info, FromRef},
    http::Request,
    routing::post,
    Router,
};

use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server,
};

use super::handlers::*;
use std::{convert::Infallible, error::Error, path::PathBuf, sync::Arc};
use tokio::net::{unix::UCred, UnixListener, UnixStream};
use tower::Service;

use super::{auth_session_db::AuthSessionDb, server_state::AuthServerState, user_db::UserDatabase};
pub static AUTH_SERVICE_UNIX_SOCKET_FILE_PATH: &'static str =
    "/tmp/glass-slippers-auth-server.socket";

/// Runs the auth service, and listens on the unix socket AUTH_SERVICE_UNIX_SOCKET_FILE_PATH, routing every http message recieved
/// via the unix socket to an axum router with the auth::handlers
#[tracing::instrument(skip_all, err)]
pub async fn server<
    SessionDb: AuthSessionDb + FromRef<AuthServerState<SessionDb, UserDb>>,
    UserDb: UserDatabase + FromRef<AuthServerState<SessionDb, UserDb>>,
>(
    state: AuthServerState<SessionDb, UserDb>,
) -> Result<(), Box<dyn Error>> {
    let path = PathBuf::from(AUTH_SERVICE_UNIX_SOCKET_FILE_PATH);

    // ignore error
    let _ = tokio::fs::remove_file(&path).await;

    let uds = UnixListener::bind(path.clone())?;

    let app = Router::new()
        .route(
            "/create_anti_csrf_token",
            post(create_anti_csrf_token::<SessionDb, UserDb>),
        )
        .route(
            "/check_anti_csrf_token",
            post(check_anti_csrf_token::<SessionDb, UserDb>),
        )
        .route("/authenticate", post(authenticate))
        .route("/verify", post(verify::<SessionDb, UserDb>))
        .route(
            "/create_unverified_authentication",
            post(create_unverified_authentication::<SessionDb, UserDb>),
        )
        .route("/create_recovery", post(create_recovery))
        .route("/recover", post(recover::<SessionDb, UserDb>))
        .route("/create_session", post(create_session::<SessionDb, UserDb>))
        .route("/check_session", post(check_session::<SessionDb, UserDb>))
        .with_state(state);

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
        let (socket, _remote_addr) = uds.accept().await?;

        fn unwrap_infallible<T>(result: Result<T, Infallible>) -> T {
            match result {
                Ok(value) => value,
                Err(err) => match err {},
            }
        }

        let tower_service = unwrap_infallible(make_service.call(&socket).await);

        tokio::spawn(async move {
            let socket = TokioIo::new(socket);

            let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
                tower_service.clone().call(request)
            });

            if let Err(err) = server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(socket, hyper_service)
                .await
            {
                tracing::error!("{err:?}");
            }
        });
    }
}
