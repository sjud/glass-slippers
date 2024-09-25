use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use serde::Deserialize;

use crate::github_event::GithubEvent;

#[derive(Clone, Deserialize, Debug)]
pub struct RunnerConfigDeserialize {
    /// this is used to confirm the webhook signature
    pub github_token: String,
    pub artifact_url: String,
    /// this is used to download the artifact
    pub github_api_key: String,
}

impl From<RunnerConfigDeserialize> for RunnerConfig {
    fn from(other: RunnerConfigDeserialize) -> RunnerConfig {
        RunnerConfig {
            github_token: Arc::new(other.github_token),
            artifact_url: Arc::new(other.artifact_url),
            github_api_key: Arc::new(other.github_api_key),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RunnerConfig {
    /// this is used to confirm the webhook signature
    pub github_token: Arc<String>,
    pub artifact_url: Arc<String>,
    /// this is used to download the artifact
    pub github_api_key: Arc<String>,
}

#[derive(Deserialize, Debug)]
struct GithubWebhookPayload {
    action: String, // i.e "completed"
    workflow_run: Option<WorkflowRun>,
}
impl GithubWebhookPayload {
    pub fn valid(self) -> bool {
        if let Some(workflow) = self.workflow_run {
            self.action == String::from("completed")
                && workflow.status == String::from("completed")
                && workflow.conclusion == Some(String::from("success"))
                && workflow.head_branch == String::from("main")
        } else {
            false
        }
    }
}
#[derive(Deserialize, Debug)]
struct WorkflowRun {
    status: String,             // i.e "completed"
    conclusion: Option<String>, // "success"
    head_branch: String,        // "main"
}

#[derive(Debug, Deserialize)]
pub struct Repository {}

#[axum::debug_handler]
async fn check_webhook(
    State(config): State<RunnerConfig>,
    GithubEvent(e): GithubEvent<GithubWebhookPayload>,
) -> Result<impl IntoResponse, StatusCode> {
    if e.valid() {
        let client = reqwest::Client::new();
        let url = config.artifact_url;
        let token = config.github_token;

        let response = client
            .get(url.as_ref())
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let mut file =
            std::fs::File::create("artifact.zip").map_err(|_| StatusCode::INSUFFICIENT_STORAGE)?;

        let content = response
            .bytes()
            .await
            .map_err(|_| StatusCode::IM_A_TEAPOT)?;

        std::io::copy(&mut content.as_ref(), &mut file).unwrap();

        println!("Artifact downloaded successfully!");
    }
    Ok(())
}

/// The runner listens for github web hooks, checks to see if they are pull requests on main whose checks passed.
/// If so it fetches the artifact, as described in the Config.toml and starts the artifact (presuming its a server) in green/blue deployment style.
pub async fn runner(config: RunnerConfig) {
    let router: Router<()> = Router::new()
        .route("/github", post(check_webhook))
        .with_state(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    axum::serve(listener, router).await.unwrap();
}
