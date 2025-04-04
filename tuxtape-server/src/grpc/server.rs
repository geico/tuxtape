use super::service::database::DatabaseServiceState;
use super::service::fleet_client::FleetClientServiceState;
use super::service::registrar::RegistrarServiceState;
use color_eyre::Result;
use proto::tuxtape::server::database::v1::database_service_server::DatabaseServiceServer;
use proto::tuxtape::server::fleet_client::v1::fleet_client_service_server::FleetClientServiceServer;
use proto::tuxtape::server::registrar::v1::registrar_service_server::RegistrarServiceServer;
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::codec::CompressionEncoding;
use tonic::transport::{Server, ServerTlsConfig};
use tuxtape_database_bridge::connection::DatabaseConnectionDetails;

/// Starts a server with all tuxtape-server gRPC services.
pub async fn start_server(
    grpc_addr: SocketAddr,
    tls_config: Option<ServerTlsConfig>,
    db_conn_details: Arc<DatabaseConnectionDetails>,
) -> Result<()> {
    let database_service_state = DatabaseServiceState::new(db_conn_details.clone());
    let fleet_client_service_state = FleetClientServiceState::new(db_conn_details.clone());
    let registrar_service_state = RegistrarServiceState::new(db_conn_details.clone());

    let file_descriptor_set = std::fs::read(proto::FILE_DESCRIPTOR_SET_PATH)?;

    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(&file_descriptor_set)
        .build_v1()?;

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<DatabaseServiceServer<DatabaseServiceState>>()
        .await;

    if let Some(tls_config) = tls_config {
        Server::builder().tls_config(tls_config.clone())?
    } else {
        Server::builder()
    }
    .add_service(
        DatabaseServiceServer::new(database_service_state)
            .accept_compressed(CompressionEncoding::Gzip)
            .send_compressed(CompressionEncoding::Gzip),
    )
    .add_service(
        FleetClientServiceServer::new(fleet_client_service_state)
            .accept_compressed(CompressionEncoding::Gzip)
            .send_compressed(CompressionEncoding::Gzip),
    )
    .add_service(
        RegistrarServiceServer::new(registrar_service_state)
            .accept_compressed(CompressionEncoding::Gzip)
            .send_compressed(CompressionEncoding::Gzip),
    )
    .add_service(reflection_service)
    .add_service(
        health_service
            .accept_compressed(CompressionEncoding::Gzip)
            .send_compressed(CompressionEncoding::Gzip),
    )
    .serve(grpc_addr)
    .await?;

    Ok(())
}
