use leptos::prelude::*;
use leptos_meta::{provide_meta_context, MetaTags, Stylesheet, Title};
use leptos_router::{
    components::{Route, Router, Routes},
    StaticSegment,
};

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
    #[cfg(feature = "ssr")]
    tracing::event!(tracing::Level::ERROR, "Hello while doing SSR.");
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

#[server]
#[cfg_attr(feature = "ssr", tracing::instrument)]
pub async fn click_me(count: usize) -> Result<usize, ServerFnError> {
    tracing::event!(tracing::Level::TRACE, "Hello from click_me");
    Ok(count + 1)
}
