use proto::tuxtape::server::fleet_client::v1::fleet_client_service_server::FleetClientService;
use proto::tuxtape::server::fleet_client::v1::*;
use sqlx::PgPool;
use tonic::{Request, Response, Status};

pub struct FleetClientServiceState {
    db_pool: PgPool,
}

impl FleetClientServiceState {
    pub fn new(db_pool: &PgPool) -> Self {
        FleetClientServiceState {
            db_pool: db_pool.clone(),
        }
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
