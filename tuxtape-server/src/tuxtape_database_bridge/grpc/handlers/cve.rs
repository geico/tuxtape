use crate::models::cve::CveRow;
use proto::tuxtape::common::v1::Cve;

impl From<CveRow> for Cve {
    fn from(row: CveRow) -> Self {
        Self {
            id: row.cve_id,
            base_score: row.base_score,
            attack_vector: row.attack_vector,
            attack_complexity: row.attack_complexity,
            privileges_required: row.privileges_required,
            user_interaction: row.user_interaction,
            scope: row.scope,
            confidentiality_impact: row.confidentiality_impact,
            integrity_impact: row.integrity_impact,
            availability_impact: row.availability_impact,
            description: row.description,
        }
    }
}
