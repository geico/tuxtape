/// JSON types for the NIST CVE API
/// https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
use serde_derive::{Deserialize, Serialize};

pub type NistResponse = Root;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub total_results: usize,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    pub cve: Cve,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cve {
    pub id: String,
    pub metrics: Metrics,
    pub published: String,
    pub last_modified: String,
    pub descriptions: Vec<Description>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Description {
    pub lang: String,
    pub value: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metrics {
    pub cvss_metric_v31: Option<Vec<CvssMetricV31>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssMetricV31 {
    pub cvss_data: CvssData,
    pub exploitability_score: f64,
    pub impact_score: f64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssData {
    pub version: String,
    pub vector_string: String,
    pub attack_vector: String,
    pub attack_complexity: String,
    pub privileges_required: String,
    pub user_interaction: String,
    pub scope: String,
    pub confidentiality_impact: String,
    pub integrity_impact: String,
    pub availability_impact: String,
    pub base_score: f64,
    pub base_severity: String,
}
