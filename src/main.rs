use glass_slippers::{
    runner::{self, RunnerConfig, RunnerConfigDeserialize},
    MAIN_SERVER_PORT,
};
use std::sync::Arc;

use pingora::{
    prelude::{background_service, HttpPeer},
    server::configuration::ServerConf,
    services::background::BackgroundService,
};
use tokio::sync::watch::Receiver;
fn main() {
    let mut proxy = pingora::proxy::http_proxy_service(&Arc::new(ServerConf::default()), Proxy {});
    let mut runner_bg = background_service("runner", RunnerBackgroundService);
    proxy.add_tcp("127.0.0.1:8000");
    let mut my_server = pingora::server::Server::new(None).unwrap();
    //my_server.bootstrap();
    // run add service after bootstrap? probably because if we take over a previous running instance add service
    my_server.add_service(proxy);
    my_server.add_service(runner_bg);
    my_server.run_forever();
}

pub struct RunnerBackgroundService;
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

pub struct Proxy;
#[async_trait::async_trait]
impl pingora::prelude::ProxyHttp for Proxy {
    type CTX = ();
    fn new_ctx(&self) {}
    async fn upstream_peer(
        &self,
        session: &mut pingora::prelude::Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let parts = session.req_header().as_ref();
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
        Ok(Box::new(HttpPeer::new(
            address,
            false,
            "wut put here?".to_string(),
        )))
    }
}

/*
 the vps runner runs on the server that runs the webserver
 when the github workflow completes for the project the workflow will create an artifact
 the runner will listen on webhook for the completion of the workflow on main
 it will take the artifact
 the runner will have two ports one that is listening and running a server and the other that isnt
 when the runner gets the artifact it will begin listening on the second port and decommission the first port
 requests will have the server version attached to them, and when the versions don't match (i.e the client is out of sync with the server)
 we'll force the client to refresh
 this two port strategy presumes that there is an nginx server or reverse proxy that is set up so that incoming requests are handled by either port

 pitfalls:
 if the server manages in memory data for the client, that will be lost between deployments
 if there are migration changes those changes need to be applied before the server comes up, but would be distruptive to do before the earlier server goes down
 security around artifacts/webhooks (use a secure key, validate artifacts before deployment)
 handling failure (if the new instance fails, how do you roll back or keep the old running?) use health check after deployment before switching over (and before database migration)
 graceful shutdown/ connection draining (allow old server to finish processing requests before shutdown)
 ..
ideas:

pingora reverse proxy (we're planning on running our server behind cloudflared anyways so our reverse proxy here can mostly be for deployment but it can also automatically validate users based on their tokens
    kind of like an ory lite)

    using a reverse proxy here will let us manage our request forwarding to our green/blue server (for continous deployment)
    while providing authorization
    it will capture data from the browser fingerprinting and session replaying
    and consume the traces emitted by our leptos app to show the admin
    it can provide generic register/login/forget password/authentication processes (and we'll build unstyled components or server functionality)
    + Oauth connectors for popular services
    can keep crm data here and be a source for new leads (i.e scrape potential customers and then send the data here to be part of an email effort etc, track their interactions with the app impressions so forth)
    this is CRM lite for consumer facing apps where customers are expected to have low life time value relative to an enterprise sales CRM
    tracking browsers sessions (between refreshes), browser fingerprints (one for each session), authorization sessions (log in/ log out windows), cookie tracker (there's a cookie that is just a cookie id, which tracks as long as it exists)
    tracking IP addresses, associating all of the various tracking data points. IP + Session + FP + Auth Session + Cookie Id, to get the most in depth look of usage across devices, across ips, across session and authorizations etc.
    session replaying,
    feedback aggregation
    console logs
    tie session id's to marketing email, so send links to users that have unique id's in the URL's so when a user clicks on them they'll be associated with a session
    and thus a browser FP and IP
    and see when the user opens the email (invisible email tracking)

    provide a leptos specific library to get error tracking and monitoring without the hassle of the reverse lookup that sentry io requires (from memory location to function names)
    basic geo location stuff
*/

/*
We need
   config file management
       -github key so we can read artifact
   when we start the app if we don't have the binary we'll get it

   web hook
       - a webhook (so we need to register our server with github to be told when an update occurs)


*/
