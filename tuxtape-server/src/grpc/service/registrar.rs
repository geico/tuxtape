use proto::tuxtape::server::registrar::v1::registrar_service_server::RegistrarService;
use proto::tuxtape::server::registrar::v1::*;
use sqlx::PgPool;
use tonic::{Request, Response, Status};

pub struct RegistrarServiceState {
    db_pool: PgPool,
}

impl RegistrarServiceState {
    pub fn new(db_pool: &PgPool) -> Self {
        RegistrarServiceState {
            db_pool: db_pool.clone(),
        }
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
