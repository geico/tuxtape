use super::handlers::vulnerability;
use crate::error::{DatabaseBridgeError, Result};
use proto::tuxtape::server::database::v1::*;
use sqlx::{Acquire, PgConnection};
use tonic::Response;

pub async fn get_vulnerabilities(
    conn: &mut PgConnection,
    request: &GetVulnerabilitiesRequest,
) -> Result<Response<GetVulnerabilitiesResponse>> {
    use get_vulnerabilities_request::GetBy;

    let mut tx = conn.begin().await?;

    let get_by = if let Some(get_by) = &request.get_by {
        get_by
    } else {
        return Err(DatabaseBridgeError::proto_missing_field("get_by"));
    };

    let vulnerabilities = match get_by {
        GetBy::All(_) => vulnerability::fetch_all(&mut tx).await?,
        GetBy::KernelRelease(by_kernel_releases) => {
            vulnerability::fetch_by_kernel_releases(&by_kernel_releases.kernel_release, &mut tx)
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
) -> Result<Response<GetKernelSourceResponse>> {
    todo!();
}

pub fn create_kernel(
    conn: &mut PgConnection,
    request: &CreateKernelRequest,
) -> Result<Response<CreateKernelResponse>> {
    todo!();
}
