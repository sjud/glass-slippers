pub mod app;
#[cfg(feature = "ssr")]
pub mod db;
#[cfg(feature = "ssr")]
pub use db::*;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    use crate::app::*;
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}

use leptos::prelude::ServerFnError;

#[cfg(feature = "ssr")]
pub async fn clickhouse_client() -> Result<ClickhouseClient, ServerFnError> {
    Ok(
        leptos_axum::extract::<axum::Extension<crate::db::ClickhouseClient>>()
            .await?
            .0,
    )
}
