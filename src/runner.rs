use std::sync::Arc;

use axum::{response::IntoResponse, routing::post, Router, ServiceExt};
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

#[derive(Deserialize, Debug)]
struct GithubWebhookPayload {
    action: String,
    pull_request: Option<PullRequest>,
    workflow_run: Option<WorkflowRun>,
}

#[derive(Deserialize, Debug)]
struct PullRequest {
    base: BranchInfo,
}

#[derive(Deserialize, Debug)]
struct BranchInfo {
    #[serde(rename = "ref")]
    ref_name: String,
}

#[derive(Deserialize, Debug)]
struct WorkflowRun {
    status: String,
    conclusion: Option<String>,
    head_branch: String,
}

#[derive(Debug, Deserialize)]
pub struct Repository {}
async fn check_webhook(
    // GithubEvent(e): GithubEvent<GithubWebhookPayload>
    body: String,
) -> impl IntoResponse {
    println!("{}", body);
    ()
}

/// The runner listens for github web hooks, checks to see if they are pull requests on main whose checks passed.
/// If so it fetches the artifact, as described in the Config.toml and starts the artifact (presuming its a server) in green/blue deployment style.
pub async fn runner(config: RunnerConfig) {
    let router: Router<()> = Router::new()
        .route("/github", post(check_webhook))
        .with_state(GithubToken(Arc::new(config.github_token)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    axum::serve(listener, router).await.unwrap();
}
