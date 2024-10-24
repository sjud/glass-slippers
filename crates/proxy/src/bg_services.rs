use auth::{server::server as auth_server, server_state::AuthServerState};
use runner::{self, RunnerConfig, RunnerConfigDeserialize};
use std::sync::Arc;

use pingora::services::background::BackgroundService;
use tokio::sync::watch::Receiver;
pub struct RunnerBackgroundService;

pub struct AuthBackgroundService;

#[async_trait::async_trait]
impl BackgroundService for RunnerBackgroundService {
    async fn start(&self, _: Receiver<bool>) {
        let config_contents =
            std::fs::read_to_string("Config.toml").expect("Config file in crate root.");

        // Deserialize the String into your RunnerConfig struct
        let config: RunnerConfigDeserialize =
            toml::from_str(&config_contents).expect("Config.toml to be valid toml");
        let config = Arc::new(RunnerConfig::new(config));
        let runner_state = runner::RunnerState {
            config,
            client: std::sync::Arc::new(runner::HttpClient(reqwest::Client::new())),
        };
        runner::runner_with_init(runner_state).await;
    }
}

#[async_trait::async_trait]
impl BackgroundService for AuthBackgroundService {
    async fn start(&self, _: Receiver<bool>) {
        auth_server(AuthServerState::new().await.unwrap())
            .await
            .expect("Server always to start");
    }
}
