use std::future::Future;

use leptos::{html::P, prelude::*};
use leptos_meta::{provide_meta_context, MetaTags, Stylesheet, Title};
use leptos_router::{
    components::{Route, Router, Routes},
    StaticSegment,
};
use server_fn::{
    client::{browser::BrowserClient, Client},
    request::browser::BrowserRequest,
    response::browser::BrowserResponse,
};
use std::cell::RefCell;
#[cfg(feature = "hydrate")]
use wasm_bindgen::JsCast;
// When we hydrate the app, we'll check for a cookie that tells use our session id.
#[cfg(feature = "hydrate")]
thread_local! {
    pub static BROWSER_SESSION_ID : String = document()
    .unchecked_into::<web_sys::HtmlDocument>()
    .cookie()
    .expect("expecting a cookie here.")
    .split(';')
    .filter_map(|s| {
        if s.contains("browserSessionId") {
            s.split("=").last()
        } else {
            None
        }
    })
    .next()
    .unwrap()
    .to_string();
}

pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <AutoReload options=options.clone() />
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    view! {
        // injects a stylesheet into the document <head>
        // id=leptos means cargo-leptos will hot-reload this stylesheet
        <Stylesheet id="leptos" href="/pkg/dev-example.css"/>

        // sets the document titlej
        <Title text="Welcome to Leptos"/>

        // content for this welcome page
        <Router>
            <main>
                <Routes fallback=|| "Page not found.".into_view()>
                    <Route path=StaticSegment("") view=HomePage/>
                </Routes>
            </main>
        </Router>
    }
}

/// Renders the home page of your application.
#[component]
fn HomePage() -> impl IntoView {
    // Creates a reactive value to update the button
    let count = RwSignal::new(0);
    let action = ServerAction::<ClickMe>::new();
    Effect::new(move || {
        if let Some(Ok(c)) = action.value().get() {
            count.set(c);
        }
    });
    view! {
        <h1>"Welcome to Leptos!"</h1>
        <button on:click=move|_|{action.dispatch(ClickMe{count:count.get_untracked()});}>"Click Me: " {count}</button>
    }
}

pub struct GlassClient;
impl<CustErr> Client<CustErr> for GlassClient {
    type Request = BrowserRequest;
    type Response = BrowserResponse;

    fn send(
        req: Self::Request,
    ) -> impl Future<Output = Result<Self::Response, ServerFnError<CustErr>>> + Send {
        // I think this will only get called on the client anyways? Otherwise why would we use BrowserRequest.

        #[cfg(feature = "hydrate")]
        let headers = req.headers();
        #[cfg(feature = "hydrate")]
        headers.append(
            "x-browser-session-id",
            BROWSER_SESSION_ID.with(|s| s.clone()).as_ref(),
        );
        BrowserClient::send(req)
    }
}

#[server(client=GlassClient)]
#[cfg_attr(feature = "ssr", tracing::instrument)]
pub async fn click_me(count: usize) -> Result<usize, ServerFnError> {
    use tracing::{event, Level};

    #[tracing::instrument]
    pub async fn click_me_inner(count: usize) -> Result<usize, ServerFnError> {
        event!(Level::ERROR, debug = true, "error",);
        event!(Level::DEBUG, fourty_five = 45, other = "other", "debug",);
        Ok(count + 1)
    }

    event!(Level::WARN, asdas = 1, "warning.");
    click_me_inner(count).await
}
