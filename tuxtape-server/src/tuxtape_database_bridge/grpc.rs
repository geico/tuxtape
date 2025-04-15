use proto::tuxtape::server::database::v1::*;
use sqlx::PgConnection;
use tonic::{Response, Status};

pub fn get_vulnerabilities(
    conn: &mut PgConnection,
    request: &GetVulnerabilitiesRequest,
) -> Result<Response<GetVulnerabilitiesResponse>, Status> {
    todo!();
}

pub fn get_kernel_source(
    conn: &mut PgConnection,
    request: &GetKernelSourceRequest,
) -> Result<Response<GetKernelSourceResponse>, Status> {
    todo!();
}

pub fn create_kernel(
    conn: &mut PgConnection,
    request: &CreateKernelRequest,
) -> Result<Response<CreateKernelResponse>, Status> {
    todo!();
}
