#![feature(never_type, never_type_fallback)]

pub mod auth_session_db;
pub mod auth_user_client;
pub mod data_model;
pub mod handlers;
pub mod proxy_client;
pub mod server;
pub mod server_state;
pub mod user_db;
pub static AUTH_SESSION_COOKIE: &'static str = "session_id";
