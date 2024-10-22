use axum::{async_trait, extract::FromRequestParts};
use http::{
    header::SET_COOKIE, request::Parts, HeaderMap, HeaderValue, Request, Response, StatusCode,
};
use http_body::Body;
use pin_project_lite::pin_project;
use std::{
    future::Future,
    task::{ready, Poll},
};
use tower::{Layer, Service};
use uuid::Uuid;

pin_project! {
    pub struct BrowserSessionIdFuture<F>{
        #[pin]
        inner:F,
        set_browser_session_id:Option<Uuid>,
    }
}
impl<Fut, ResBody, E> Future for BrowserSessionIdFuture<Fut>
where
    Fut: Future<Output = Result<Response<ResBody>, E>>,
    ResBody: Body,
{
    type Output = Result<Response<ResBody>, E>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        let mut resp = ready!(this.inner.poll(cx)?);
        if let Some(browser_session_id) = this.set_browser_session_id {
            resp.headers_mut().insert(
                SET_COOKIE,
                HeaderValue::from_str(&format!(
                    "browserSessionId={}; Max-Age=30; Path=/;",
                    browser_session_id
                ))
                .unwrap(),
            );
        }
        Poll::Ready(Ok(resp))
    }
}
#[derive(Clone)]
pub struct BrowserSessionIdService<S> {
    inner: S,
}
impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for BrowserSessionIdService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Body,
    ResBody: Body,
{
    type Response = Response<ResBody>;

    type Error = S::Error;

    type Future = BrowserSessionIdFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let header_map = req.headers_mut();
        // if map contains id we're done.
        if header_map.contains_key("x-browser-session-id") {
            let fut = self.inner.call(req);
            return BrowserSessionIdFuture {
                inner: fut,
                set_browser_session_id: None,
            };
        }
        // In some circumstances we want to create a browser session id from scratch, set the rest of the request to have it and then set a set cookie
        // header on the response to store the browser_session id.
        let propagate_cookie = |header_map: &mut HeaderMap| -> Option<Uuid> {
            let browser_session_id = Uuid::new_v4();
            header_map.insert(
                "x-browser-session-id",
                HeaderValue::from_str(&browser_session_id.to_string())
                    // dont just unwrap because we can't trust a cookie
                    .unwrap_or(HeaderValue::from_static("0")),
            );
            Some(browser_session_id)
        };

        if let Some(cookie) = header_map.get(http::header::COOKIE) {
            if let Some(browser_session_id) = cookie
                .to_str()
                .unwrap_or_default()
                .split(';')
                .filter_map(|s| {
                    if s.contains("browserSessionId") {
                        s.split("=").last()
                    } else {
                        None
                    }
                })
                .next()
            {
                header_map.insert(
                    "x-browser-session-id",
                    HeaderValue::from_str(browser_session_id)
                        // dont just unwrap because we can't trust a cookie
                        .unwrap_or(HeaderValue::from_static("0")),
                );
                let fut = self.inner.call(req);
                BrowserSessionIdFuture {
                    inner: fut,
                    set_browser_session_id: None,
                }
            } else {
                let set_browser_session_id = propagate_cookie(header_map);
                let fut = self.inner.call(req);
                BrowserSessionIdFuture {
                    inner: fut,
                    set_browser_session_id,
                }
            }
        } else {
            let set_browser_session_id = propagate_cookie(header_map);
            let fut = self.inner.call(req);
            BrowserSessionIdFuture {
                inner: fut,
                set_browser_session_id,
            }
        }
    }
}
/// Our browser session id layer, looks at cookies for browser-session-id  cookie and if that exists creates a x-session-id header from that cookie value
/// AND if a cookie doesn't exist we check if the x-browser-session-id is set
/// IF it x-browser-session-id is not set and no cookie exists, we create an browserSessionId cookie, set it and propagate the value in x-browser-session-id header
/// We only need the cookie for a small period after in process the first request for index, as this will let us get the session id while loading static assets
/// before the wasm has set the client headers for server functions.
#[derive(Clone, Copy)]
pub struct BrowserSessionIdLayer;
impl<S> Layer<S> for BrowserSessionIdLayer {
    type Service = BrowserSessionIdService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BrowserSessionIdService { inner }
    }
}
