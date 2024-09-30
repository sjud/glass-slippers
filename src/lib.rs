pub mod github_event;
pub mod runner;
use std::sync::RwLock;

pub static MAIN_SERVER_PORT: RwLock<Option<u16>> = RwLock::new(None);
