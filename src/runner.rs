use crate::github_event::GithubEvent;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Router};
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use serde::Deserialize;
use std::{fs::read_dir, sync::Arc};
use tempfile::{tempfile, TempDir};
use tokio::{process::Command, spawn};

#[derive(Clone, Deserialize, Debug)]
pub struct RunnerConfigDeserialize {
    /// this is used to confirm the webhook signature
    pub github_token: String,
    /// this is used to download the artifact
    pub github_api_key: String,
    pub app_name: String,
    pub runner_port: u16,
    pub blue_server_address: String,
    pub green_server_address: String,
    pub repo_owner: String,
    pub repo_name: String,
}

impl RunnerConfig {
    pub fn new(other: RunnerConfigDeserialize) -> RunnerConfig {
        let (app_color_sender, app_color_receiver) = tokio::sync::watch::channel(AppColor::NoApp);
        RunnerConfig {
            github_token: Arc::new(other.github_token),
            github_api_key: Arc::new(other.github_api_key),
            app_name: Arc::new(other.app_name),
            app_color_sender,
            app_color_receiver,
            runner_port: other.runner_port,
            blue_server_address: Arc::new(other.blue_server_address),
            green_server_address: Arc::new(other.green_server_address),
            repo_owner: Arc::new(other.repo_owner),
            repo_name: Arc::new(other.repo_name),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RunnerConfig {
    /// this is used to confirm the webhook signature
    pub github_token: Arc<String>,
    /// this is used to download the artifact
    pub github_api_key: Arc<String>,
    pub app_name: Arc<String>,
    pub app_color_sender: tokio::sync::watch::Sender<AppColor>,
    pub app_color_receiver: tokio::sync::watch::Receiver<AppColor>,
    pub runner_port: u16,
    pub blue_server_address: Arc<String>,
    pub green_server_address: Arc<String>,
    pub repo_owner: Arc<String>,
    pub repo_name: Arc<String>,
}

#[derive(Clone, Copy, Debug)]
pub enum AppColor {
    NoApp,
    Blue,
    Green,
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
async fn handle_new_artifacts_webhook(
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

        let artifacts = serde_json::from_str::<GetArtifactUrlResp>(&resp)
            .unwrap()
            .artifacts; //
        for artifact in artifacts {
            let response = client
                .get(artifact.archive_download_url)
                .header(reqwest::header::USER_AGENT, "Glass-Slippers")
                .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                .send()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            // open in write only
            let mut file = tempfile().unwrap();

            let content = response.bytes().await.unwrap();

            std::io::copy(&mut content.as_ref(), &mut file).unwrap();

            let mut zip = zip::ZipArchive::new(&mut file).unwrap();
            let dir = TempDir::new().unwrap();
            zip.extract(dir.path()).unwrap();
            let mut read_dir = read_dir(dir.path()).unwrap();
            let file_path = read_dir.next().unwrap().unwrap().path();
            let file = std::fs::File::open(file_path).unwrap();
            let mut archive = tar::Archive::new(file);
            let mut read_dir_blue = std::fs::read_dir("app_blue").unwrap();
            let mut read_dir_green = std::fs::read_dir("app_green").unwrap();
            let app_color_sender = config.app_color_sender.clone();
            let mut if_true_write_blue_else_green = |do_it: bool| {
                if do_it {
                    archive.unpack("app_blue").unwrap();
                    app_color_sender.send(AppColor::Blue).unwrap();
                } else {
                    archive.unpack("app_green").unwrap();
                    app_color_sender.send(AppColor::Green).unwrap();
                }
            };
            // we set app color here we don't read from it. Which we could do, i.e use app color to decipher what to do next.
            // but where would we decide what app color is?
            if let Some(Ok(file)) = read_dir_blue.next() {
                let first_blue_file_accessed = file.metadata().unwrap().accessed().unwrap();
                if let Some(Ok(file)) = read_dir_green.next() {
                    let first_green_file_accessed = file.metadata().unwrap().accessed().unwrap();
                    // if blue has been accessed more recently write into green
                    if first_blue_file_accessed > first_green_file_accessed {
                        if_true_write_blue_else_green(false);
                    } else {
                        if_true_write_blue_else_green(true);
                    }
                } else {
                    // if green is empty write into green
                    if_true_write_blue_else_green(false);
                }
            } else {
                if_true_write_blue_else_green(true);
            }
        }

        println!("Artifact downloaded successfully!");
    }
    Ok(())
}

/// The runner listens for github web hooks, checks to see if they are pull requests on main whose checks passed.
/// If so it fetches the artifact, as described in the Config.toml and starts the artifact (presuming its a server) in green/blue deployment style.
pub async fn runner(config: RunnerConfig) {
    let addr = format!("127.0.0.1:{}", config.runner_port);
    let mut app_color_receiver = config.app_color_receiver.clone();
    let app_color_sender = config.app_color_sender.clone();
    let sender_c = app_color_sender.clone();
    let repo_owner = config.repo_owner.clone();
    let repo_name = config.repo_name.clone();
    let app_name = config.app_name.clone();
    let token = config.github_api_key.clone();

    let blue_server_address = config.blue_server_address.clone();
    let green_server_address = config.green_server_address.clone();
    let router: Router<()> = Router::new()
        .route("/github", post(handle_new_artifacts_webhook))
        .with_state(config);
    println!("Listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    spawn(async move {
        while app_color_receiver.changed().await.is_ok() {
            let color = *app_color_receiver.borrow();
            let mut blue_pid = None::<Pid>;
            let mut green_pid = None::<Pid>;
            match color {
                AppColor::NoApp => {
                    let mut read_dir_blue = std::fs::read_dir("app_blue").unwrap();
                    let mut read_dir_green = std::fs::read_dir("app_green").unwrap();
                    if let Some(Ok(file)) = read_dir_blue.next() {
                        let first_blue_file_accessed = file.metadata().unwrap().accessed().unwrap();
                        if let Some(Ok(file)) = read_dir_green.next() {
                            let first_green_file_accessed =
                                file.metadata().unwrap().accessed().unwrap();
                            // if blue has been accessed more recently write into green
                            if first_blue_file_accessed > first_green_file_accessed {
                                app_color_sender.send(AppColor::Green).unwrap();
                            } else {
                                app_color_sender.send(AppColor::Blue).unwrap();
                            }
                        } else {
                            app_color_sender.send(AppColor::Blue).unwrap();
                        }
                    } else {
                        if let Some(Ok(_)) = read_dir_green.next() {
                            app_color_sender.send(AppColor::Green).unwrap();
                        } else {
                            // fetch the latest artifact and write it to app_blue

                            let client = reqwest::Client::new();
                            let artifacts_url = format!("https://api.github.com/repos/{repo_owner}/{repo_name}/actions/artifacts");
                            let artifacts = client
                                .get(artifacts_url)
                                .header(reqwest::header::USER_AGENT, "Glass-Slippers")
                                //.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
                                .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                                .send()
                                .await
                                .unwrap()
                                .json::<GetArtifactUrlResp>()
                                .await
                                .unwrap()
                                .artifacts;
                            if let Some(artifact_url) = artifacts
                                .iter()
                                .next()
                                .map(|art| art.archive_download_url.clone())
                            {
                                let response = client
                                    .get(artifact_url)
                                    .header(reqwest::header::USER_AGENT, "Glass-Slippers")
                                    .header(
                                        reqwest::header::AUTHORIZATION,
                                        format!("Bearer {}", token),
                                    )
                                    .header(reqwest::header::ACCEPT, "application/vnd.github+json")
                                    .send()
                                    .await
                                    .unwrap();
                                // open in write only
                                let mut file = tempfile().unwrap();

                                let content = response.bytes().await.unwrap();

                                std::io::copy(&mut content.as_ref(), &mut file).unwrap();

                                let mut zip = zip::ZipArchive::new(&mut file).unwrap();
                                let dir = TempDir::new().unwrap();
                                zip.extract(dir.path()).unwrap();
                                let mut read_dir = read_dir(dir.path()).unwrap();
                                let file_path = read_dir.next().unwrap().unwrap().path();
                                let file = std::fs::File::open(file_path).unwrap();
                                let mut archive = tar::Archive::new(file);
                                archive.unpack("app_blue").unwrap();
                                app_color_sender.send(AppColor::Blue).unwrap();
                            }
                            // list artifacts
                        }
                    }
                }
                AppColor::Blue => {
                    std::env::set_var("LEPTOS_SITE_ADDR", blue_server_address.as_ref());
                    let working_dir = std::fs::canonicalize("app_blue")
                        .unwrap()
                        .into_os_string()
                        .into_string()
                        .unwrap();
                    let path = format!("{}/{}", working_dir, app_name.as_ref());
                    println!("Running {}", path);
                    let mut child = Command::new(path).current_dir(working_dir).spawn().unwrap(); // we can pipe the traces back to us and forward them to our observability service
                    let pid = Pid::from_raw(child.id().expect("valid id here") as i32);
                    spawn(async move {
                        child.wait().await.unwrap();
                    });
                    blue_pid.replace(pid);
                    if let Some(pid) = green_pid {
                        signal::kill(pid, Signal::SIGKILL).unwrap();
                    }
                    // TODO kill after health check? should we communicate with our reverse proxy here to switch over (after health check)
                }
                AppColor::Green => {
                    std::env::set_var("LEPTOS_SITE_ADDR", green_server_address.as_ref());
                    let working_dir = std::fs::canonicalize("app_green")
                        .unwrap()
                        .into_os_string()
                        .into_string()
                        .unwrap();
                    let path = format!("{}/{}", working_dir, app_name.as_ref());
                    println!("Running {}", path);
                    let mut child = Command::new(path).current_dir(working_dir).spawn().unwrap(); // we can pipe the traces back to us and forward them to our observability service
                    let pid = Pid::from_raw(child.id().expect("valid id here") as i32);
                    spawn(async move {
                        child.wait().await.unwrap();
                    });
                    green_pid.replace(pid);
                    if let Some(pid) = blue_pid {
                        signal::kill(pid, Signal::SIGKILL).unwrap();
                    }
                }
            }
        }
    });
    // our init value starts as seen so send a new value to get the ball rolling.
    sender_c.send(AppColor::NoApp).unwrap();
    axum::serve(listener, router).await.unwrap();
}
