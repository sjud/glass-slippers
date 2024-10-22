#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use axum::{extract::Extension, routing::get, Router};
    use leptos::prelude::*;
    use leptos_axum::{generate_route_list, LeptosRoutes};
    use server::next_request_id;
    use tracing_ui::app::*;
    use tracing_ui::db::ClickhouseClient;

    let conf = get_configuration(None).unwrap();
    let addr = conf.leptos_options.site_addr;
    let leptos_options = conf.leptos_options;
    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(App);

    let clickhouse_client = ClickhouseClient::new().await.unwrap();
    let app = Router::new()
        .leptos_routes(&leptos_options, routes, {
            let leptos_options = leptos_options.clone();
            move || shell(leptos_options.clone())
        })
        .route("/api/next_request_id", get(next_request_id))
        .fallback(leptos_axum::file_and_error_handler(shell))
        .with_state(leptos_options)
        .layer(Extension(clickhouse_client.clone()));

    tokio::spawn(server::ingest_main_server_traces(clickhouse_client));

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    log!("listening on http://{}", &addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

#[cfg(not(feature = "ssr"))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for pure client-side testing
    // see lib.rs for hydration function instead
}

#[cfg(feature = "ssr")]
pub mod server {
    use axum::response::IntoResponse;
    use axum::Extension;
    use http::StatusCode;
    use tokio::fs::remove_file;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    pub async fn next_request_id(
        Extension(client): Extension<ClickhouseClient>,
    ) -> impl IntoResponse {
        let body = client.get_last_request_id().await.unwrap();
        (StatusCode::OK, serde_json::to_string(&body).unwrap())
    }

    use tracing_ui::db::{digest_trace, ClickhouseClient, TraceUndigested};

    /// Sets up an IPC socket to ingest data from the reverse proxy.
    pub async fn ingest_main_server_traces(client: ClickhouseClient) {
        let socket_path = "/tmp/glass_slippers_main_server_tracing.sock";
        // ignore errors, if file doesnt exist then we're good.
        _ = remove_file(socket_path).await;
        let listener = UnixListener::bind(socket_path).unwrap();
        println!("Listening on {}", socket_path);
        // Asynchronously accept an incoming connection
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            println!("Stream Accepted.");
            let client = client.clone();
            // Spawn a new asynchronous task to handle the connection
            tokio::spawn(async move {
                if let Err(e) = handle_server_traces(stream, client).await {
                    tracing::error!("Error: {:?}", e);
                }
            });
        }
    }

    async fn handle_server_traces(
        stream: UnixStream,
        client: ClickhouseClient,
    ) -> tokio::io::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut buffer = String::new();

        // Asynchronously read data from the client
        while reader.read_line(&mut buffer).await? > 0 {
            match serde_json::from_str::<TraceUndigested>(&buffer) {
                Ok(trace) => {
                    let trace = digest_trace(trace);
                    client.insert_trace(trace).await.unwrap();
                }
                Err(err) => {
                    tracing::error!("{err:#?}")
                }
            }
            buffer.clear(); // Clear buffer for next message
        }

        Ok(())
    }
}
