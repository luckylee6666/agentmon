pub mod alert;
pub mod collect;
pub mod config;
pub mod detect;
pub mod dns;
pub mod install;
pub mod model;
pub mod paths;
pub mod pipeline;
pub mod profiles;
pub mod proxy;
pub mod registry;
pub mod sensitive;
pub mod store;
pub mod util;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
