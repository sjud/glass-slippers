#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use std::{
        io::{Stdout, Write},
        os::unix::net::UnixStream,
        sync::Mutex,
    };

    use axum::Router;
    use dev_example::{app::*, browser_session_id::BrowserSessionIdLayer};
    use http::Request;
    use leptos::prelude::*;
    use leptos_axum::{generate_route_list, LeptosRoutes};

    use request_id::MyMakeRequestId;
    use tower::ServiceBuilder;

    use tower_http::{trace::TraceLayer, ServiceBuilderExt};
    use tracing::info_span;
    use tracing_subscriber::fmt::format::FmtSpan;
    use uuid::Uuid;

    let unix_stream = UnixStream::connect("/tmp/glass_slippers_main_server_tracing.sock").unwrap();
    let stdout = std::io::stdout();

    struct MixedWriter(UnixStream, Stdout);
    impl Write for MixedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.1.write(buf)?;
            self.0.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.1.flush()?;
            self.0.flush()?;
            Ok(())
        }
    }
    tracing_subscriber::fmt()
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .flatten_event(false)
        .with_span_events(FmtSpan::NEW)
        .with_writer(Mutex::new(MixedWriter(unix_stream, stdout)))
        .init();

    let conf = get_configuration(None).unwrap();
    let addr = conf.leptos_options.site_addr;
    let leptos_options = conf.leptos_options;
    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(App);

    let request_id = reqwest::Client::new()
        .get("http:127.0.0.1:3006/api/next_request_id")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<u64>()
        .await
        .unwrap();

    let middleware = ServiceBuilder::new()
        .set_x_request_id(MyMakeRequestId::new(request_id))
        .layer(BrowserSessionIdLayer)
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                let browser_session_id = request.headers().get("x-browser-session-id");
                // Log the request id as generated.
                let request_id = request.headers().get("x-request-id");
                let path_and_query = request
                    .uri()
                    .path_and_query()
                    .map(|p| format!("{p:#?}"))
                    .unwrap_or_default();
                match (request_id, browser_session_id) {
                    (Some(request_id), Some(browser_session_id)) => info_span!(
                        "http_request",
                        browser_session_id = browser_session_id
                            .to_str()
                            .unwrap_or_default()
                            .parse::<Uuid>()
                            .unwrap_or_default()
                            .as_u128(),
                        request_id = request_id
                            .to_str()
                            .unwrap_or_default()
                            .parse::<u64>()
                            .unwrap_or_default(),
                        path_and_query = path_and_query
                    ),
                    (Some(request_id), None) => {
                        error!("could not extract session_id");
                        info_span!(
                            "http_request",
                            session_id = 0,
                            request_id = request_id
                                .to_str()
                                .unwrap_or_default()
                                .parse::<u64>()
                                .unwrap_or_default(),
                            path_and_query = path_and_query
                        )
                    }
                    (None, _) => {
                        error!("could not extract request_id");
                        info_span!("http_request")
                    }
                }
            }),
        );

    let app = Router::new()
        .leptos_routes(&leptos_options, routes, {
            let leptos_options = leptos_options.clone();
            move || shell(leptos_options.clone())
        })
        .fallback(leptos_axum::file_and_error_handler(shell))
        .with_state(leptos_options)
        .layer(middleware);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    log!("listening on http://{}", &addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

#[cfg(feature = "ssr")]
pub mod request_id {
    use http::Request;
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };
    use tower_http::request_id::{MakeRequestId, RequestId};

    #[derive(Clone)]
    pub struct MyMakeRequestId {
        counter: Arc<AtomicU64>,
    }
    impl MyMakeRequestId {
        pub fn new(value: u64) -> Self {
            Self {
                counter: Arc::new(AtomicU64::new(value)),
            }
        }
    }
    impl MakeRequestId for MyMakeRequestId {
        fn make_request_id<B>(&mut self, _: &Request<B>) -> Option<RequestId> {
            let request_id = self
                .counter
                .fetch_add(1, Ordering::SeqCst)
                .to_string()
                .parse()
                .unwrap();

            Some(RequestId::new(request_id))
        }
    }
}
#[cfg(not(feature = "ssr"))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for pure client-side testing
    // see lib.rs for hydration function instead
}
