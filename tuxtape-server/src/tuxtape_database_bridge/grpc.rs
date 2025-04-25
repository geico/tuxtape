use crate::{
    error::{DatabaseBridgeError, Result},
    handlers,
};
use proto::tuxtape::server::database::v1::*;
use sqlx::PgConnection;
use tonic::Response;

pub async fn get_vulnerabilities(
    conn: &mut PgConnection,
) -> Result<Response<GetVulnerabilitiesResponse>> {
    let vulnerabilities = handlers::vulnerability::get_vulnerabilities(conn).await?;

    Ok(Response::new(GetVulnerabilitiesResponse {
        vulnerabilities,
    }))
}

pub async fn get_vulnerability_instances(
    request: &GetVulnerabilityInstancesRequest,
    conn: &mut PgConnection,
) -> Result<Response<GetVulnerabilityInstancesResponse>> {
    let vulnerability_instances =
        handlers::vulnerability_instance::get_vulnerability_instances_by_vulnerability_ids(
            &request.vulnerability_ids,
            conn,
        )
        .await?;

    Ok(Response::new(GetVulnerabilityInstancesResponse {
        vulnerability_instances,
    }))
}

pub async fn get_kernel_source(
    request: &GetKernelSourceRequest,
    conn: &mut PgConnection,
) -> Result<Response<GetKernelSourceResponse>> {
    let kernel_source =
        handlers::kernel_source::get_kernel_source(request.kernel_release_id, conn).await?;

    Ok(Response::new(GetKernelSourceResponse {
        kernel_source: Some(kernel_source),
    }))
}

pub async fn get_affected_kernel_releases(
    request: &GetAffectedKernelReleasesRequest,
    conn: &mut PgConnection,
) -> Result<Response<GetAffectedKernelReleasesResponse>> {
    let kernel_releases = handlers::kernel_release::get_affected_kernel_releases(
        &request.vulnerability_instance_ids,
        conn,
    )
    .await?;

    Ok(Response::new(GetAffectedKernelReleasesResponse {
        kernel_releases,
    }))
}

pub async fn create_kernel(
    request: &CreateKernelRequest,
    conn: &mut PgConnection,
) -> Result<Response<CreateKernelResponse>> {
    let kernel_release = if let Some(kernel_release) = &request.kernel_release {
        kernel_release
    } else {
        return Err(DatabaseBridgeError::proto_missing_field("kernel_release"));
    };

    let kernel_source = if let Some(kernel_source) = &request.kernel_source {
        kernel_source
    } else {
        return Err(DatabaseBridgeError::proto_missing_field("kernel_source"));
    };

    handlers::kernel::create_kernel(kernel_release, kernel_source, conn).await?;

    Ok(Response::new(CreateKernelResponse {}))
}
