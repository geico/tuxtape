use super::get_connection;
use proto::tuxtape::server::database::v1::{database_service_server::DatabaseService, *};
use sqlx::PgPool;
use tonic::{Request, Response, Status};
use tuxtape_database_bridge::grpc as db_bridge;

pub struct DatabaseServiceState {
    db_pool: PgPool,
}

impl DatabaseServiceState {
    pub fn new(db_pool: &PgPool) -> Self {
        DatabaseServiceState {
            db_pool: db_pool.clone(),
        }
    }
}

#[tonic::async_trait]
impl DatabaseService for DatabaseServiceState {
    async fn get_vulnerabilities(
        &self,
        _request: Request<GetVulnerabilitiesRequest>,
    ) -> Result<Response<GetVulnerabilitiesResponse>, Status> {
        let mut conn = get_connection(&self.db_pool).await?;
        let response = db_bridge::get_vulnerabilities(&mut conn).await?;

        Ok(response)
    }

    async fn get_vulnerability_instances(
        &self,
        request: Request<GetVulnerabilityInstancesRequest>,
    ) -> Result<Response<GetVulnerabilityInstancesResponse>, Status> {
        let mut conn = get_connection(&self.db_pool).await?;
        let response =
            db_bridge::get_vulnerability_instances(&request.into_inner(), &mut conn).await?;

        Ok(response)
    }

    async fn get_kernel_source(
        &self,
        request: Request<GetKernelSourceRequest>,
    ) -> Result<Response<GetKernelSourceResponse>, Status> {
        let mut conn = get_connection(&self.db_pool).await?;
        let response = db_bridge::get_kernel_source(&request.into_inner(), &mut conn).await?;

        Ok(response)
    }

    async fn get_affected_kernel_releases(
        &self,
        request: Request<GetAffectedKernelReleasesRequest>,
    ) -> Result<Response<GetAffectedKernelReleasesResponse>, Status> {
        let mut conn = get_connection(&self.db_pool).await?;
        let response =
            db_bridge::get_affected_kernel_releases(&request.into_inner(), &mut conn).await?;

        Ok(response)
    }

    async fn create_kernel(
        &self,
        request: Request<CreateKernelRequest>,
    ) -> Result<Response<CreateKernelResponse>, Status> {
        let mut conn = get_connection(&self.db_pool).await?;
        let response = db_bridge::create_kernel(&request.into_inner(), &mut conn).await?;

        Ok(response)
    }
}
