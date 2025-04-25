use super::{Result, TestExt};
use crate::handlers;
use proto::tuxtape::common::v1::Cve;
use sqlx::{PgConnection, PgPool};

#[sqlx::test]
async fn test_insert_and_fetch_cve(pool: PgPool) -> Result<()> {
    let mut conn = pool.acquire().await?;

    let cves = Cve::create_and_insert(3, &mut conn).await?;
    for cve in &cves {
        let id = handlers::cve::insert_or_fetch(cve, &mut conn).await?;
        assert_eq!(cve.id.unwrap(), id);
    }

    Ok(())
}

#[sqlx::test]
async fn test_insert_duplicate_cve(pool: PgPool) -> Result<()> {
    let mut conn = pool.acquire().await?;

    let mut cves = Cve::create_and_insert(1, &mut conn).await?;
    let cve = &mut cves[0];
    let id2 = handlers::cve::insert_or_fetch(cve, &mut conn).await?;
    // Check that the ID is the same as the first one
    assert_eq!(cve.id.unwrap(), id2);

    Ok(())
}

impl TestExt for Cve {
    async fn create_and_insert(amount: usize, conn: &mut PgConnection) -> Result<Vec<Self>> {
        let mut cves = (0..amount)
            .map(|i| {
                // Half of the CVEs will have been rated, half not.
                let is_some: bool = i % 2 == 0;

                Cve {
                    id: Some((i as i32) + 1),
                    cve_id: format!("CVE-2025-{:0>4}", i),
                    base_score: { if is_some { Some((i % 10) as f32) } else { None } },
                    attack_vector: {
                        if is_some {
                            Some(match i % 4 {
                                0 => "NETWORK".to_string(),
                                1 => "LOCAL".to_string(),
                                2 => "ADJACENT".to_string(),
                                3 => "PHYSICAL".to_string(),
                                _ => unreachable!(),
                            })
                        } else {
                            None
                        }
                    },
                    attack_complexity: {
                        if is_some {
                            Some(match i % 2 {
                                0 => "LOW".to_string(),
                                1 => "HIGH".to_string(),
                                _ => unreachable!(),
                            })
                        } else {
                            None
                        }
                    },
                    privileges_required: {
                        if is_some {
                            Some(match i % 3 {
                                0 => "NONE".to_string(),
                                1 => "LOW".to_string(),
                                2 => "HIGH".to_string(),
                                _ => unreachable!(),
                            })
                        } else {
                            None
                        }
                    },
                    user_interaction: {
                        if is_some {
                            Some(match i % 3 {
                                0 => "NONE".to_string(),
                                1 => "REQUIRED".to_string(),
                                2 => "POSSIBLE".to_string(),
                                _ => unreachable!(),
                            })
                        } else {
                            None
                        }
                    },
                    scope: {
                        if is_some {
                            Some(match i % 2 {
                                0 => "UNCHANGED".to_string(),
                                1 => "CHANGED".to_string(),
                                _ => unreachable!(),
                            })
                        } else {
                            None
                        }
                    },
                    confidentiality_impact: {
                        if is_some {
                            Some(match i % 3 {
                                0 => "NONE".to_string(),
                                1 => "LOW".to_string(),
                                2 => "HIGH".to_string(),
                                _ => unreachable!(),
                            })
                        } else {
                            None
                        }
                    },
                    integrity_impact: {
                        if is_some {
                            Some(match i % 3 {
                                0 => "NONE".to_string(),
                                1 => "LOW".to_string(),
                                2 => "HIGH".to_string(),
                                _ => unreachable!(),
                            })
                        } else {
                            None
                        }
                    },
                    availability_impact: {
                        if is_some {
                            Some(match i % 3 {
                                0 => "NONE".to_string(),
                                1 => "LOW".to_string(),
                                2 => "HIGH".to_string(),
                                _ => unreachable!(),
                            })
                        } else {
                            None
                        }
                    },
                    description: {
                        if is_some {
                            Some(format!("Test CVE description {}", i))
                        } else {
                            None
                        }
                    },
                }
            })
            .collect::<Vec<Cve>>();

        for cve in cves.iter_mut() {
            let id = handlers::cve::insert_or_fetch(cve, conn).await?;
            cve.id = Some(id);
        }

        Ok(cves)
    }
}
