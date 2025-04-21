use super::handlers::vulnerability;
use crate::error::DatabaseBridgeError;
use proto::tuxtape::server::database::v1::*;
use sqlx::PgConnection;
use tonic::{Response, Status};

pub async fn get_vulnerabilities(
    conn: &mut PgConnection,
    request: &GetVulnerabilitiesRequest,
) -> Result<Response<GetVulnerabilitiesResponse>, Status> {
    use get_vulnerabilities_request::GetBy;

    let get_by = if let Some(get_by) = &request.get_by {
        get_by
    } else {
        return Err(DatabaseBridgeError::proto_missing_field("get_by").into());
    };

    let vulnerabilities = match get_by {
        GetBy::All(_) => vulnerability::fetch_all(conn).await.map_err(Status::from)?,
        GetBy::KernelRelease(by_kernel_releases) => {
            vulnerability::fetch_by_kernel_releases(&by_kernel_releases.kernel_release, conn)
                .await?
        }
    };

    Ok(Response::new(GetVulnerabilitiesResponse {
        vulnerabilities,
    }))
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
