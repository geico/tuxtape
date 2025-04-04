use proto::tuxtape::server::fleet_client::v1::fleet_client_service_server::FleetClientService;
use proto::tuxtape::server::fleet_client::v1::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tuxtape_database_bridge::connection::DatabaseConnectionDetails;

pub struct FleetClientServiceState {
    db_conn_details: Arc<DatabaseConnectionDetails>,
}

impl FleetClientServiceState {
    pub fn new(db_conn_details: Arc<DatabaseConnectionDetails>) -> Self {
        FleetClientServiceState { db_conn_details }
    }
}

#[tonic::async_trait]
impl FleetClientService for FleetClientServiceState {
    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        todo!()
    }

    async fn report_livepatch_status(
        &self,
        request: Request<ReportLivepatchStatusRequest>,
    ) -> Result<Response<ReportLivepatchStatusResponse>, Status> {
        todo!()
    }

    async fn report_livepatch_error(
        &self,
        request: Request<ReportLivepatchErrorRequest>,
    ) -> Result<Response<ReportLivepatchErrorResponse>, Status> {
        todo!()
    }
}
