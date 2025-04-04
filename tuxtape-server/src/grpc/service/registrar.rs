use proto::tuxtape::server::registrar::v1::registrar_service_server::RegistrarService;
use proto::tuxtape::server::registrar::v1::*;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tuxtape_database_bridge::connection::DatabaseConnectionDetails;

pub struct RegistrarServiceState {
    db_conn_details: Arc<DatabaseConnectionDetails>,
}

impl RegistrarServiceState {
    pub fn new(db_conn_details: Arc<DatabaseConnectionDetails>) -> Self {
        RegistrarServiceState { db_conn_details }
    }
}

#[tonic::async_trait]
impl RegistrarService for RegistrarServiceState {
    async fn register_kernel_builder(
        &self,
        request: Request<RegisterKernelBuilderRequest>,
    ) -> Result<Response<RegisterKernelBuilderResponse>, Status> {
        todo!()
    }

    async fn register_patch_builder(
        &self,
        request: Request<RegisterPatchBuilderRequest>,
    ) -> Result<Response<RegisterPatchBuilderResponse>, Status> {
        todo!()
    }
}
