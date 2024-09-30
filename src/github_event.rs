// copied from https://github.com/daaku/axum-github-webhook-extract/tree/main
use axum::async_trait;
use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use hmac_sha256::HMAC;
use serde::de::DeserializeOwned;
use std::fmt::Display;
use subtle::ConstantTimeEq;

use crate::runner::RunnerState;

/// Verify and extract Github Event Payload.
#[derive(Debug, Clone, Copy, Default)]
#[must_use]
pub struct GithubEvent<T>(pub T);

fn err(m: impl Display) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, m.to_string())
}

#[async_trait]
impl<T> FromRequest<RunnerState> for GithubEvent<T>
where
    T: DeserializeOwned,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request, state: &RunnerState) -> Result<Self, Self::Rejection> {
        let signature_sha256 = req
            .headers()
            .get("X-Hub-Signature-256")
            .and_then(|v| v.to_str().ok())
            .ok_or(err("signature missing"))?
            .strip_prefix("sha256=")
            .ok_or(err("signature prefix missing"))?;
        let signature = hex::decode(signature_sha256).map_err(|_| err("signature malformed"))?;
        let body = Bytes::from_request(req, state)
            .await
            .map_err(|_| err("error reading body"))?;
        let token = state.config.as_ref().github_token.as_bytes();
        let mac = HMAC::mac(&body, token);
        if mac.ct_ne(&signature).into() {
            return Err(err("signature mismatch"));
        }

        let deserializer = &mut serde_json::Deserializer::from_slice(&body);
        let value = serde_path_to_error::deserialize(deserializer).map_err(err)?;
        Ok(GithubEvent(value))
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::Router;
    use http_body_util::BodyExt;
    use serde::Deserialize;
    use tower::ServiceExt;

    use crate::runner::{MockHttpClient, RunnerConfig, RunnerState};

    use super::GithubEvent;

    #[derive(Debug, Deserialize)]
    struct Event {
        action: String,
    }

    async fn echo(GithubEvent(e): GithubEvent<Event>) -> impl IntoResponse {
        e.action
    }

    fn app() -> Router {
        let mut config = RunnerConfig::new_test();
        let client = MockHttpClient::new();
        config.github_token = String::from("42");
        Router::new()
            .route("/", post(echo))
            .with_state(RunnerState::new(config, client))
    }

    async fn body_string(body: Body) -> String {
        String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into()
    }

    fn with_header(v: &'static str) -> Request {
        Request::builder()
            .method("POST")
            .header("X-Hub-Signature-256", v)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn signature_missing() {
        let req = Request::builder()
            .method("POST")
            .body(Body::empty())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_string(res.into_body()).await, "signature missing");
    }

    #[tokio::test]
    async fn signature_prefix_missing() {
        let res = app().oneshot(with_header("x")).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_string(res.into_body()).await,
            "signature prefix missing"
        );
    }

    #[tokio::test]
    async fn signature_malformed() {
        let res = app().oneshot(with_header("sha256=x")).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_string(res.into_body()).await, "signature malformed");
    }

    #[tokio::test]
    async fn signature_mismatch() {
        let res = app().oneshot(with_header("sha256=01")).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_string(res.into_body()).await, "signature mismatch");
    }

    #[tokio::test]
    async fn signature_valid() {
        let req: Request = Request::builder()
            .method("POST")
            .header(
                "X-Hub-Signature-256",
                "sha256=8b99afd7996c3e3c291a0b54399bacb72016bdb088071de42d1d7156a6a4273d",
            )
            .body(r#"{"action":"hello world"}"#.into())
            .unwrap();
        let res = app().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_string(res.into_body()).await, "hello world");
    }
}
