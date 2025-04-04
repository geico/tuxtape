use proto::tuxtape::server::database::v1::database_service_server::DatabaseService;
use proto::tuxtape::server::database::v1::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tuxtape_database_bridge::connection::DatabaseConnectionDetails;

pub struct DatabaseServiceState {
    db_conn_details: Arc<DatabaseConnectionDetails>,
}

impl DatabaseServiceState {
    pub fn new(db_conn_details: Arc<DatabaseConnectionDetails>) -> Self {
        DatabaseServiceState { db_conn_details }
    }
}

#[tonic::async_trait]
impl DatabaseService for DatabaseServiceState {
    async fn get_vulnerabilities(
        &self,
        request: Request<GetVulnerabilitiesRequest>,
    ) -> Result<Response<GetVulnerabilitiesResponse>, Status> {
        todo!()
    }

    async fn get_kernel_source(
        &self,
        request: Request<GetKernelSourceRequest>,
    ) -> Result<Response<GetKernelSourceResponse>, Status> {
        todo!()
    }

    async fn create_kernel(
        &self,
        request: Request<CreateKernelRequest>,
    ) -> Result<Response<CreateKernelResponse>, Status> {
        todo!()
    }
}
