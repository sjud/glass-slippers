use std::sync::Arc;

use axum::{response::IntoResponse, routing::post, Router};
use serde::{Deserialize, Serialize};

use crate::github_event::{GithubEvent, GithubToken};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RunnerConfig {
    /// this is used to confirm the webhook signature
    pub github_token: String,
    pub artifact_url: String,
    /// this is used to download the artifact
    pub github_api_key: String,
}

#[derive(Debug, Deserialize)]
struct Event {}

async fn check_webhook(GithubEvent(e): GithubEvent<Event>) -> impl IntoResponse {
    ()
}

/// The runner listens for github web hooks, checks to see if they are pull requests on main whose checks passed.
/// If so it fetches the artifact, as described in the Config.toml and starts the artifact (presuming its a server) in green/blue deployment style.
pub async fn runner(config: RunnerConfig) {
    let router: Router<GithubToken> = Router::new()
        .route("/", post(check_webhook))
        .with_state(GithubToken(Arc::new(config.github_token)));
}
