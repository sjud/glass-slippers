use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Router};
use serde::Deserialize;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use crate::github_event::GithubEvent;

#[derive(Clone, Deserialize, Debug)]
pub struct RunnerConfigDeserialize {
    /// this is used to confirm the webhook signature
    pub github_token: String,
    /// this is used to download the artifact
    pub github_api_key: String,
}

impl From<RunnerConfigDeserialize> for RunnerConfig {
    fn from(other: RunnerConfigDeserialize) -> RunnerConfig {
        RunnerConfig {
            github_token: Arc::new(other.github_token),
            github_api_key: Arc::new(other.github_api_key),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RunnerConfig {
    /// this is used to confirm the webhook signature
    pub github_token: Arc<String>,
    /// this is used to download the artifact
    pub github_api_key: Arc<String>,
}

#[derive(Deserialize, Debug)]
struct GithubWebhookPayload {
    action: String, // i.e "completed"
    workflow_run: Option<WorkflowRun>,
}
impl GithubWebhookPayload {
    pub fn valid(self) -> Option<String> {
        if let Some(workflow) = self.workflow_run {
            if self.action == String::from("completed")
                && workflow.status == String::from("completed")
                && workflow.conclusion == Some(String::from("success"))
                && workflow.head_branch == String::from("main")
            {
                Some(workflow.artifacts_url)
            } else {
                None
            }
        } else {
            None
        }
    }
}
#[derive(Deserialize, Debug)]
struct WorkflowRun {
    status: String,             // i.e "completed"
    conclusion: Option<String>, // "success"
    head_branch: String,        // "main"
    artifacts_url: String, // "https://api.github.com/repos/sjud/glass-slippers/actions/runs/11039278965/artifacts",
}

#[derive(Deserialize)]
pub struct GetArtifactUrlResp {
    pub artifacts: Vec<Artifact>, // https://api.github.com/repos/sjud/glass-slippers/actions/artifacts/1978642466/zip
}
#[derive(Deserialize, Clone)]
pub struct Artifact {
    pub archive_download_url: String,
    pub name: String,
}
#[derive(Debug, Deserialize)]
pub struct Repository {}

#[axum::debug_handler]
async fn check_webhook(
    State(config): State<RunnerConfig>,
    GithubEvent(e): GithubEvent<GithubWebhookPayload>,
) -> Result<impl IntoResponse, StatusCode> {
    if let Some(artifacts_url) = e.valid() {
        println!("{}", artifacts_url);
        let client = reqwest::Client::new();
        let token = config.github_api_key;
        let resp = client
            .get(artifacts_url)
            .header(reqwest::header::USER_AGENT, "Glass-Slippers")
            //.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .text()
            .await
            .unwrap();

        println!("{resp}");
        let artifacts = serde_json::from_str::<GetArtifactUrlResp>(&resp)
            .unwrap()
            .artifacts;
        for artifact in artifacts {
            let response = client
                .get(artifact.archive_download_url)
                .header(reqwest::header::USER_AGENT, "Glass-Slippers")
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .send()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let zip_file = format!("zips/{}.zip", artifact.name);
            let mut file = std::fs::File::create(&zip_file).unwrap();

            let content = response.bytes().await.unwrap();

            std::io::copy(&mut content.as_ref(), &mut file).unwrap();
            let mut permissions = file.metadata().unwrap().permissions();
            permissions.set_mode(0o777);
            let mut zip = zip::ZipArchive::new(&mut file).unwrap();
            zip.extract("unzipped").unwrap();
        }

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
