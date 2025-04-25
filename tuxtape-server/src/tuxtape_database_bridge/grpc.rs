use crate::{
    error::{DatabaseBridgeError, Result},
    handlers,
};
use proto::tuxtape::server::database::v1::*;
use sqlx::PgConnection;
use tonic::Response;

pub async fn get_vulnerabilities(
    conn: &mut PgConnection,
    request: &GetVulnerabilitiesRequest,
) -> Result<Response<GetVulnerabilitiesResponse>> {
    use proto::tuxtape::server::database::v1::get_vulnerabilities_request::GetBy;
    // TODO - implement excludes

    let get_by = if let Some(get_by) = &request.get_by {
        get_by
    } else {
        return Err(DatabaseBridgeError::proto_missing_field("get_by"));
    };

    let vulnerabilities = match get_by {
        GetBy::All(_) => handlers::vulnerability::get_all_vulnerabilities(conn).await,
        GetBy::KernelRelease(by_kernel_release) => {
            handlers::vulnerability::get_all_vulnerabilities_affecting_kernel_releases(
                &by_kernel_release.kernel_releases,
                conn,
            )
            .await
        }
    }?;

    Ok(Response::new(GetVulnerabilitiesResponse {
        vulnerabilities,
    }))
}

pub async fn get_kernel_source(
    conn: &mut PgConnection,
    request: &GetKernelSourceRequest,
) -> Result<Response<GetKernelSourceResponse>> {
    todo!();
}

pub async fn create_kernel(
    conn: &mut PgConnection,
    request: &CreateKernelRequest,
) -> Result<Response<CreateKernelResponse>> {
    todo!();
}
