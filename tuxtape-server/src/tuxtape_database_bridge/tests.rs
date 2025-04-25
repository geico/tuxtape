use crate::{grpc, handlers};
use proto::tuxtape::server::database::v1::GetVulnerabilitiesRequest;
use proto::tuxtape::{
    common::v1::{Cve, MainlineKernelRelease, Vulnerability, VulnerabilityInstance},
    server::database::v1::get_vulnerabilities_request::GetBy,
};
use sqlx::{PgConnection, PgPool};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct TestData {
    vulnerability_instance_1: VulnerabilityInstance,
    vulnerability_instance_2: VulnerabilityInstance,
    cve_1: Cve,
    cve_2: Cve,
    vulnerability_1: Vulnerability,
    vulnerability_2: Vulnerability,
}

impl TestData {
    fn new() -> Self {
        let vulnerability_instance_1 = VulnerabilityInstance {
            introduced: Some(MainlineKernelRelease {
                major_version: 5,
                minor_version: 10,
                patch_version: 0,
                extra_version: "extra".to_string(),
            }),
            fixed: Some(MainlineKernelRelease {
                major_version: 5,
                minor_version: 10,
                patch_version: 1,
                extra_version: "extra".to_string(),
            }),
            fixed_commit: Some("abcdefghijl".to_string()),
            affected_files: vec!["/path/to/file1".to_string()],
            affected_kernels: vec![],
            patch_diff: Some("diff1".to_string()),
        };

        let vulnerability_instance_2 = VulnerabilityInstance {
            introduced: Some(MainlineKernelRelease {
                major_version: 5,
                minor_version: 10,
                patch_version: 0,
                extra_version: "extra".to_string(),
            }),
            fixed: Some(MainlineKernelRelease {
                major_version: 5,
                minor_version: 10,
                patch_version: 2,
                extra_version: "extra".to_string(),
            }),
            fixed_commit: Some("mnopqrstuvwx".to_string()),
            affected_files: vec!["/path/to/file2".to_string()],
            affected_kernels: vec![],
            patch_diff: Some("diff2".to_string()),
        };

        let cve_1 = Cve {
            cve_id: "CVE-2025-0001".to_string(),
            base_score: Some(7.5),
            attack_vector: Some("NETWORK".to_string()),
            attack_complexity: Some("LOW".to_string()),
            privileges_required: Some("NONE".to_string()),
            user_interaction: Some("NONE".to_string()),
            scope: Some("UNCHANGED".to_string()),
            confidentiality_impact: Some("HIGH".to_string()),
            integrity_impact: Some("HIGH".to_string()),
            availability_impact: Some("HIGH".to_string()),
            description: Some("A test CVE description".to_string()),
        };

        let cve_2 = Cve {
            cve_id: "CVE-2025-0002".to_string(),
            base_score: Some(5.0),
            attack_vector: Some("LOCAL".to_string()),
            attack_complexity: Some("HIGH".to_string()),
            privileges_required: Some("LOW".to_string()),
            user_interaction: Some("REQUIRED".to_string()),
            scope: Some("UNCHANGED".to_string()),
            confidentiality_impact: Some("LOW".to_string()),
            integrity_impact: Some("LOW".to_string()),
            availability_impact: Some("LOW".to_string()),
            description: Some("Another test CVE description".to_string()),
        };

        let vulnerability_1 = Vulnerability {
            description: Some("Test vulnerability 1".to_string()),
            cve: Some(cve_1.clone()),
            instances: vec![vulnerability_instance_1.clone()],
        };

        let vulnerability_2 = Vulnerability {
            description: Some("Test vulnerability 2".to_string()),
            cve: Some(cve_2.clone()),
            instances: vec![vulnerability_instance_2.clone()],
        };

        TestData {
            vulnerability_instance_1,
            vulnerability_instance_2,
            cve_1,
            cve_2,
            vulnerability_1,
            vulnerability_2,
        }
    }

    async fn insert_vulnerabilities(&self, conn: &mut PgConnection) -> Result<Vec<i32>> {
        let vulnerability_row_1 =
            handlers::vulnerability::insert_proto(&self.vulnerability_1, conn).await?;
        let vulnerability_row_2 =
            handlers::vulnerability::insert_proto(&self.vulnerability_2, conn).await?;

        Ok(vec![vulnerability_row_1, vulnerability_row_2])
    }
}

#[sqlx::test]
async fn test_get_all_vulnerabilities(pool: PgPool) -> Result<()> {
    // Acquire a connection from the pool.
    let mut conn = pool.acquire().await?;

    let test_data = TestData::new();
    let _ = test_data.insert_vulnerabilities(&mut conn).await?;

    let request = GetVulnerabilitiesRequest {
        excludes: vec![],
        get_by: Some(GetBy::All(Default::default())),
    };

    let response = grpc::get_vulnerabilities(&mut conn, &request).await?;

    assert_eq!(
        [test_data.vulnerability_1, test_data.vulnerability_2].as_slice(),
        response.into_inner().vulnerabilities.as_slice(),
    );

    Ok(())
}
