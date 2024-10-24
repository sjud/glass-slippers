use auth::{
    data_model::{AuthClientUnixSocket, ANTI_CSRF_TOKEN_HEADER_NAME, X_AUTH_ID_HEADER_NAME},
    proxy_client::AuthProxyClient as _,
    AUTH_SESSION_COOKIE,
};
use cookie::Cookie;
use http::{header::SET_COOKIE, HeaderMap, HeaderValue};
use runner::{self, MAIN_SERVER_PORT};
use std::str::FromStr as _;
use uuid::Uuid;

use pingora::{http::RequestHeader, prelude::HttpPeer};
#[derive(Default, Clone, Copy, Debug)]
pub struct ReqContext {
    append_new_session_to_response: bool,
}
pub struct Proxy;
#[async_trait::async_trait]
impl pingora::prelude::ProxyHttp for Proxy {
    type CTX = ReqContext;
    fn new_ctx(&self) -> Self::CTX {
        ReqContext::default()
    }
    async fn upstream_peer(
        &self,
        session: &mut pingora::prelude::Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        // TODO replace this with a load balancer and some other way to connec to our github webhook.
        // According to the docs, this should panic and we need to session.read_reaquest() but that never completes and this doesn't panic.
        // So I don't know what is going on, maybe session.read_request has already been called by some other hidden thing and that's why
        // it never returns? I have no idea.
        let parts: &http::request::Parts = session.req_header().as_ref();
        let leading = parts.uri.path().split("/").next().unwrap_or_default();
        let address = match leading {
            "/github" => ("127.0.0.1", 5000),
            _ => (
                "127.0.0.1",
                MAIN_SERVER_PORT
                    .read()
                    .expect("main server port to be set")
                    .expect("main server port to be set"),
            ),
        };

        // pick the upstream peer here,
        // either we forward to the service on it's blue green port or we send the request to one of the supporting services.
        Ok(Box::new(HttpPeer::new(address, false, "".to_string())))
    }
    #[tracing::instrument(skip_all, err)]
    async fn upstream_request_filter(
        &self,
        session: &mut pingora::prelude::Session,
        upstream_request: &mut pingora::prelude::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> {
        // If the client set the x auth id header remove it and bounce the request.
        if upstream_request
            .remove_header(X_AUTH_ID_HEADER_NAME)
            .is_some()
        {
            return Err(pingora::Error::new_str("Don't set auth id header."));
        }

        // get all the data we need.
        let parts = upstream_request.as_ref();
        let anti_csrf_token = parts.headers.get(ANTI_CSRF_TOKEN_HEADER_NAME).cloned();
        let session_id = session_id_cookie_value(&parts.headers);

        // authenticate the session id
        if let Some(session_id) = session_id {
            match AuthClientUnixSocket.check_session(session_id).await {
                Ok(Some(auth_id)) => {
                    upstream_request.append_header(
                        X_AUTH_ID_HEADER_NAME,
                        (*auth_id).unwrap_or_default().to_string(),
                    )?;
                }
                Err(err) => {
                    tracing::error!(
                        session_id = session_id.to_string(),
                        "glass-slippers bug {err:?}"
                    );
                    return Err(pingora::Error::new(pingora::ErrorType::ConnectProxyFailure));
                }
                // If we got back None, there's a session id in the cookie's from the downstream client.
                // but there is no matching session id in the database.
                Ok(None) => ctx.append_new_session_to_response = true,
            }
        }

        // check the anti csrf token
        if let Some((anti_csrf_token, session_id)) = anti_csrf_token
            .and_then(|token| {
                token
                    .to_str()
                    .ok()
                    .and_then(|token| Uuid::from_str(token).ok())
            })
            .zip(session_id)
        {
            let result = AuthClientUnixSocket
                .check_anti_csrf_token(anti_csrf_token, session_id)
                .await;
            match result {
                Ok(is_protected) => {
                    if is_protected {
                        return Ok(());
                    } else {
                        // If this is an error I don't know what will happen but we won't process the request further.
                        _ = session.respond_error(400).await?;
                        return Err(pingora::Error::new(pingora::ErrorType::ConnectProxyFailure));
                    }
                }
                Err(err) => {
                    tracing::error!(
                        anti_csrf_token = anti_csrf_token.to_string(),
                        session_id = session_id.to_string(),
                        "{err:?}",
                    );
                    _ = session.respond_error(500).await?;
                    return Err(pingora::Error::new(pingora::ErrorType::ConnectProxyFailure));
                }
            }
        }

        // pass to upstream
        Ok(())
    }
    #[tracing::instrument(skip_all, err)]
    async fn response_filter(
        &self,
        _session: &mut pingora::prelude::Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<pingora::Error>> {
        // if theres no session id add the session id cookie via a set cookie header
        if ctx.append_new_session_to_response {
            match AuthClientUnixSocket.create_session().await {
                Ok(session_id) => {
                    let session_id_cookie =
                        Cookie::build((AUTH_SESSION_COOKIE, session_id.to_string()))
                            .secure(true)
                            .http_only(true)
                            .same_site(cookie::SameSite::Strict)
                            .path("/")
                            .build();
                    // Append the cookie header to the response
                    upstream_response.append_header(SET_COOKIE, session_id_cookie.to_string())?;
                }
                Err(err) => {
                    tracing::error!("glass-slippers error {err:?}");
                    // not sure what to do here, we need to set the session id cookie for future requests but we can't.
                    return Err(pingora::Error::new(pingora::ErrorType::ConnectProxyFailure));
                }
            }
        }
        Ok(())
    }
}

#[tracing::instrument(skip_all, ret)]
pub fn session_id_cookie_value(headers: &HeaderMap<HeaderValue>) -> Option<Uuid> {
    let mut session_id = None;
    if let Some(cookie_header) = headers.get(http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                if let Ok(parsed_cookie) = Cookie::parse(cookie.trim()) {
                    if parsed_cookie.name() == AUTH_SESSION_COOKIE {
                        session_id = Uuid::from_str(parsed_cookie.value()).ok();
                    }
                }
            }
        }
    }
    session_id
}
#[tracing::instrument(skip_all)]
pub fn remove_session_id_from_cookie(upstream_request: &mut RequestHeader) {
    if let Some(cookie_header) = upstream_request.as_ref().headers.get(http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            let mut cookies_to_keep = Vec::new();

            for cookie in cookie_str.split(';') {
                if let Ok(parsed_cookie) = Cookie::parse(cookie.trim()) {
                    if parsed_cookie.name() != AUTH_SESSION_COOKIE {
                        cookies_to_keep.push(cookie.trim());
                    }
                }
            }

            // If there are cookies left, set them in the upstream request.
            if !cookies_to_keep.is_empty() {
                tracing::error!("cookie kept {cookies_to_keep:?}");
                let new_cookie_header = cookies_to_keep.join("; ");
                _ = upstream_request
                    .insert_header(
                        http::header::COOKIE,
                        HeaderValue::from_str(&new_cookie_header).unwrap(),
                    )
                    .map_err(|err| tracing::error!("{err:?}"));
            } else {
                tracing::error!("cookie header removed");
                // Remove the cookie header entirely if no cookies should be kept.
                upstream_request.remove_header(http::header::COOKIE.as_str());
            }
        }
    }
}
