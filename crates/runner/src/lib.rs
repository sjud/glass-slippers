use axum::{
    async_trait, extract::State, http::StatusCode, response::IntoResponse, routing::post, Router,
};
use bytes::Bytes;
use github_event::GithubEvent;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use reqwest::Url;
use serde::Deserialize;
use std::{
    fs::read_dir,
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
};
use tempfile::{tempfile, TempDir};
use tokio::{process::Command, spawn};
pub mod github_event;
pub static MAIN_SERVER_PORT: RwLock<Option<u16>> = RwLock::new(None);
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
        let (fetch_artifact_sender, fetch_artifact_receiver) = tokio::sync::watch::channel(());

        RunnerConfig {
            github_token: other.github_token,
            github_api_key: other.github_api_key,
            app_name: other.app_name,
            fetch_artifact_sender,
            fetch_artifact_receiver,
            runner_port: other.runner_port,
            blue_server_address: other.blue_server_address,
            green_server_address: other.green_server_address,
            repo_owner: other.repo_owner,
            repo_name: other.repo_name,
        }
    }
    #[cfg(test)]
    pub fn new_test() -> Self {
        let config: RunnerConfigDeserialize = toml::from_str(
            &r#"
        github_token = ""
github_api_key = ""
app_name = "dev_example"
runner_port = 5000
blue_server_address = "127.0.0.1:3000"
green_server_address = "127.0.0.1:3001"
repo_owner = "sjud"
repo_name = "glass-slippers"
        "#,
        )
        .expect("Config.toml to be valid toml");
        Self::new(config)
    }
}

#[derive(Clone, Debug)]
pub struct RunnerState {
    pub config: Arc<RunnerConfig>,
    pub client: Arc<dyn RunnerHttpClient>,
}

impl RunnerState {
    pub fn new(config: RunnerConfig, client: impl RunnerHttpClient + 'static) -> Self {
        Self {
            config: Arc::new(config),
            client: Arc::new(client),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RunnerConfig {
    /// this is used to confirm the webhook signature
    pub github_token: String,
    /// this is used to download the artifact
    pub github_api_key: String,
    pub app_name: String,
    pub fetch_artifact_sender: tokio::sync::watch::Sender<()>,
    pub fetch_artifact_receiver: tokio::sync::watch::Receiver<()>,

    pub runner_port: u16,
    pub blue_server_address: String,
    pub green_server_address: String,
    pub repo_owner: String,
    pub repo_name: String,
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

#[derive(Deserialize)]
pub struct GetArtifactUrlResp {
    pub artifacts: Vec<Artifact>, // https://api.github.com/repos/sjud/glass-slippers/actions/artifacts/1978642466/zip
}
#[derive(Deserialize, Clone)]
#[cfg_attr(test, derive(Default))]
pub struct Artifact {
    pub archive_download_url: String,
    pub name: String,
}
#[derive(Debug, Deserialize)]
pub struct Repository {}

#[axum::debug_handler]
async fn handle_new_artifacts_webhook(
    State(state): State<RunnerState>,
    GithubEvent(e): GithubEvent<GithubWebhookPayload>,
) -> Result<impl IntoResponse, StatusCode> {
    if e.valid() {
        state
            .config
            .fetch_artifact_sender
            .send(())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(())
}

/// Runs blue or green server , if blue run blue...
fn run_blue_green(
    blue_pid: Arc<Mutex<Option<Pid>>>,
    green_pid: Arc<Mutex<Option<Pid>>>,
    green_server_address: String,
    blue_server_address: String,
    app_name: &str,
    blue: bool,
) {
    let server_address = if blue {
        blue_server_address
    } else {
        green_server_address
    };
    let dir_name = if blue { "app_blue" } else { "app_green" };
    std::env::set_var("LEPTOS_SITE_ADDR", &server_address);
    let server_address = Url::from_str(&format!("http://{server_address}")).unwrap();
    let working_dir = std::fs::canonicalize(dir_name)
        .unwrap()
        .into_os_string()
        .into_string()
        .unwrap();
    let path = format!("{}/{}", working_dir, app_name);
    println!("Running {}", path);
    let mut child = Command::new(path).current_dir(working_dir).spawn().unwrap();
    let pid = Pid::from_raw(child.id().expect("valid id here") as i32);
    spawn(async move {
        child.wait().await.unwrap();
    });
    if blue {
        blue_pid.lock().unwrap().replace(pid);
    } else {
        green_pid.lock().unwrap().replace(pid);
    }
    spawn(async move {
        let port = server_address
            .port()
            .expect("server address to contain port");
        healthcheck(server_address).await;
        let mut main_port = MAIN_SERVER_PORT.write().unwrap();
        *main_port = Some(port);
        println!("Wrote {port} to main server port");
        if let Some(pid) = {
            if blue {
                green_pid.lock().unwrap().take()
            } else {
                blue_pid.lock().unwrap().take()
            }
        } {
            println!("Killing {pid:#?}");
            signal::kill(pid, Signal::SIGKILL).unwrap();
        }
    });
}

async fn fetch_and_unpack_most_recent_artifact(
    client: Arc<dyn RunnerHttpClient>,
    github_api_key: &str,
    repo_owner: &str,
    repo_name: &str,
    tar_destination: &str,
) {
    let artifacts_url =
        format!("https://api.github.com/repos/{repo_owner}/{repo_name}/actions/artifacts");
    let artifacts = client.list_artifacts(artifacts_url.as_str()).await;
    if let Some(artifact) = artifacts.into_iter().next() {
        let content = client.artifact_bytes(artifact, github_api_key).await;
        let mut file = tempfile().unwrap();
        std::io::copy(&mut content.as_ref(), &mut file).unwrap();
        let mut zip = zip::ZipArchive::new(&mut file).unwrap();
        let dir = TempDir::new().unwrap();
        zip.extract(dir.path()).unwrap();
        let mut read_dir = read_dir(dir.path()).unwrap();
        let file_path = read_dir.next().unwrap().unwrap().path();
        let file = std::fs::File::open(file_path).unwrap();
        let mut archive = tar::Archive::new(file);
        archive.unpack(tar_destination).unwrap();
    }
}

/// Builds the runner, and sends an initial command to begin running the server.
pub async fn runner_with_init(state: RunnerState) {
    let sender = state.config.fetch_artifact_sender.clone();
    // delay and send a message to get the ball rolling, this will trigger a fresh artifact run
    spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        sender.send(()).unwrap();
    });

    runner(state).await;
}
pub async fn fetch_run_green_blue(RunnerState { config, client }: RunnerState) {
    let RunnerConfig {
        github_api_key,
        app_name,
        mut fetch_artifact_receiver,
        blue_server_address,
        green_server_address,
        repo_owner,
        repo_name,
        ..
    } = (*config).clone();
    let blue_pid = Arc::new(Mutex::new(None::<Pid>));
    let green_pid = Arc::new(Mutex::new(None::<Pid>));

    while fetch_artifact_receiver.changed().await.is_ok() {
        let blue_pid = blue_pid.clone();
        let green_pid = green_pid.clone();
        let blue_server_address = blue_server_address.clone();
        let green_server_address = green_server_address.clone();
        let client = client.clone();
        let mut read_dir_blue = std::fs::read_dir("app_blue").unwrap();
        let mut read_dir_green = std::fs::read_dir("app_green").unwrap();
        if read_dir_blue.next().is_some() {
            if read_dir_green.next().is_some() {
                if std::fs::metadata("app_blue").unwrap().modified().unwrap()
                    > std::fs::metadata("app_green").unwrap().modified().unwrap()
                {
                    fetch_and_unpack_most_recent_artifact(
                        client,
                        github_api_key.as_ref(),
                        repo_owner.as_ref(),
                        repo_name.as_ref(),
                        "app_green",
                    )
                    .await;
                    run_blue_green(
                        blue_pid,
                        green_pid,
                        green_server_address,
                        blue_server_address,
                        app_name.as_ref(),
                        false,
                    );
                } else {
                    fetch_and_unpack_most_recent_artifact(
                        client,
                        github_api_key.as_ref(),
                        repo_owner.as_ref(),
                        repo_name.as_ref(),
                        "app_blue",
                    )
                    .await;
                    run_blue_green(
                        blue_pid,
                        green_pid,
                        green_server_address,
                        blue_server_address,
                        app_name.as_ref(),
                        true,
                    );
                }
            } else {
                fetch_and_unpack_most_recent_artifact(
                    client,
                    github_api_key.as_ref(),
                    repo_owner.as_ref(),
                    repo_name.as_ref(),
                    "app_green",
                )
                .await;
                run_blue_green(
                    blue_pid,
                    green_pid,
                    green_server_address,
                    blue_server_address,
                    app_name.as_ref(),
                    false,
                );
            }
        } else {
            fetch_and_unpack_most_recent_artifact(
                client,
                github_api_key.as_ref(),
                repo_owner.as_ref(),
                repo_name.as_ref(),
                "app_blue",
            )
            .await;
            run_blue_green(
                blue_pid,
                green_pid,
                green_server_address,
                blue_server_address,
                app_name.as_ref(),
                true,
            );
        }
    }
}
/// The runner listens for github web hooks, checks to see if they are pull requests on main whose checks passed.
/// If so it fetches the artifact, as described in the Config.toml and starts the artifact (presuming its a server) in green/blue deployment style.
pub async fn runner(state: RunnerState) {
    let addr = format!("127.0.0.1:{}", state.config.runner_port);
    let state_c = state.clone();
    let router: Router<()> = Router::new()
        .route("/github", post(handle_new_artifacts_webhook))
        // TODO specify client for http
        .with_state(state);
    println!("Listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    spawn(fetch_run_green_blue(state_c));
    axum::serve(listener, router).await.unwrap();
}
#[mockall::automock]
#[async_trait]
pub trait RunnerHttpClient: std::fmt::Debug + Sync + Send {
    async fn list_artifacts(&self, artifacts_url: &str) -> Vec<Artifact>;
    async fn artifact_bytes(&self, artifact: Artifact, token: &str) -> Bytes;
}
mockall::mock! {
    #[derive(Debug)]
    pub HttpClient{}
    #[async_trait]
    impl RunnerHttpClient for HttpClient{
        async fn list_artifacts(&self, artifacts_url: &str) -> Vec<Artifact>;
        async fn artifact_bytes(&self, artifact: Artifact, token: &str) -> Bytes;
    }
}
#[derive(Clone, Debug)]
pub struct HttpClient(pub reqwest::Client);
#[async_trait]
impl RunnerHttpClient for HttpClient {
    async fn list_artifacts(&self, artifacts_url: &str) -> Vec<Artifact> {
        self.0
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
            .artifacts
    }

    async fn artifact_bytes(&self, artifact: Artifact, token: &str) -> Bytes {
        self.0
            .get(artifact.archive_download_url)
            .header(reqwest::header::USER_AGENT, "Glass-Slippers")
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token))
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
    }
}
/// block until addr is healthy, if addr never gets healthy then this will block forever.
async fn healthcheck(addr: Url) {
    loop {
        let addr = addr.as_str();
        println!("checking {addr:#?}");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        match reqwest::Client::new().get(addr).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    println!("{addr} healthy");
                    break;
                } else {
                    println!("bad status {:#?}", resp.status())
                }
            }
            Err(_err) => {} //println!("{_err:#?}"),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;
    use std::io::Read;

    use super::*;

    use std::fs;

    fn remove_dir_contents(dir: &str) -> std::io::Result<()> {
        // Iterate over the entries in the directory
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            // Check if the entry is a directory or a file
            if path.is_dir() {
                // Recursively delete contents if it's a directory
                fs::remove_dir_all(&path)?;
            } else {
                // Otherwise, remove the file
                fs::remove_file(&path)?;
            }
        }

        Ok(())
    }

    fn kill_process_on_ports(ports: Vec<u16>) {
        // get all processes
        let all_procs = procfs::process::all_processes().unwrap();

        // build up a map between socket inodes and processes:
        let mut map: HashMap<u64, Pid> = HashMap::new();
        for process in all_procs.into_iter() {
            let process = process.unwrap();
            if let procfs::ProcResult::Ok(fds) = process.fd() {
                for fd in fds {
                    if let procfs::process::FDTarget::Socket(inode) = fd.unwrap().target {
                        map.insert(inode, Pid::from_raw(process.pid()));
                    }
                }
            }
        }

        // get the tcp table
        let tcp = procfs::net::tcp().unwrap();
        let tcp6 = procfs::net::tcp6().unwrap();

        for entry in tcp.into_iter().chain(tcp6) {
            if ports.contains(&entry.local_address.port())
                && entry.state == procfs::net::TcpState::Listen
            {
                if let Some(pid) = map.get(&entry.inode) {
                    signal::kill(*pid, Signal::SIGKILL).unwrap();
                }
            }
        }
    }

    #[tokio::test]
    async fn test_switch() {
        kill_process_on_ports(vec![3000, 3001]);
        let config = RunnerConfig::new_test();
        let mut client = MockHttpClient::new();
        client
            .expect_list_artifacts()
            .returning(|_| vec![Artifact::default()]);
        let mut buf = Vec::new();
        _ = std::fs::File::open("test_data/app-tar.zip")
            .expect("Run test in crate root.")
            .read_to_end(&mut buf)
            .unwrap();
        let bytes = bytes::Bytes::from(buf);
        client
            .expect_artifact_bytes()
            .returning(move |_, _| bytes.clone());
        let sender = config.fetch_artifact_sender.clone();
        remove_dir_contents("app_blue").unwrap();
        remove_dir_contents("app_green").unwrap();
        spawn(async move {
            runner(RunnerState {
                config: Arc::new(config),
                client: Arc::new(client),
            })
            .await;
        });

        // our init value starts as seen so send a new value to get the ball rolling.
        sender.send(()).unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        //healthcheck(blue_addr.clone()).await;
        sender.send(()).unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        //healthcheck(green_addr.clone()).await;
        sender.send(()).unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        //healthcheck(blue_addr.clone()).await;
        sender.send(()).unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        //healthcheck(green_addr.clone()).await;
        //cleanup
        kill_process_on_ports(vec![3000, 3001]);
        remove_dir_contents("app_blue").unwrap();
        remove_dir_contents("app_green").unwrap();
    }
}
