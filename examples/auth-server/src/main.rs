/*
Our Authorization/Identity service.
We expose an API so our MAIN_SERVER can access the auth functionality.
This service handles Identification and Authentication it does not handle Authorization.
So we'll provide tools to let the user confirm an identity, i.e associating an authentication_id with a set of credentials.
We give that id to the MAIN_SERVER which will handle the other logic. i.e what they know about the user and how they are authorized
So the whole service just takes credentials, checks their validity against known authentications and if we match spits out an authentication.
It also creates authentications, via, email/password or SSO.

So we provide endpoints, we expect the client to collect login information through their app and feed it into our endpoints. We can have example
components to show how it works.

When requests pass through our reverse proxy, we grab the JWT cookie and if valid add an auth_id to the request that is associated with the JWT.
The auth id can be extracted via extractors in axum. and in the MAIN_SERVER's server functions can associate that AUTH id with their user's data or whatever.

we don't have credentials we strip the x-auth-id header (otherwise a user can provide their own auth_id header and claim to be whoever thats bad)
*/
#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use auth_server::server::server;
    use auth_server::{app::*, data_model::AuthClientUnixSocket};
    use axum::Router;
    use leptos::prelude::*;
    use leptos_axum::{generate_route_list, LeptosRoutes};

    // spawn the auth server
    server().await;
    #[derive(Clone)]

    pub struct State {
        leptos_options: LeptosOptions,
        auth_client: AuthClientUnixSocket,
    }
    impl axum::extract::FromRef<State> for LeptosOptions {
        fn from_ref(value: &State) -> Self {
            value.leptos_options.clone()
        }
    }
    let conf = get_configuration(None).unwrap();
    let addr = conf.leptos_options.site_addr;
    let leptos_options = conf.leptos_options;
    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(App);
    let state = State {
        leptos_options,
        auth_client: AuthClientUnixSocket,
    };

    let app = Router::new()
        .leptos_routes(&state, routes, {
            let leptos_options = state.leptos_options.clone();
            move || shell(leptos_options.clone())
        })
        .fallback(leptos_axum::file_and_error_handler::<State, _>(shell))
        .with_state(state);

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

/*
password length 8-64
user notification, verification, registration but also if correct password with failed MFA multi-factor
csrf-token should be married to browser session, like the fingerprint.
owasp reccomends signed-double submit cookie with HMAC
*/
