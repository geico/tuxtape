pub mod connection;
pub mod grpc;
mod models;
mod schema;

// dsync requires `diesel` to be available at crate level
#[allow(clippy::single_component_path_imports)]
use diesel;
