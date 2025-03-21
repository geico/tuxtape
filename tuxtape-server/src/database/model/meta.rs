use crate::database::schema;
use diesel::prelude::*;
use diesel_attributes::*;

#[diesel_model_fetch(schema::meta)]
pub struct Meta {
    pub id: i32,
    pub based_on_vulns_commit: String,
    pub last_run_unix_time: i32,
}

#[diesel_model_insert(schema::meta)]
pub struct InsertMeta<'a> {
    pub based_on_vulns_commit: &'a str,
    pub last_run_unix_time: i32,
}

#[diesel_model_update(schema::meta)]
pub struct UpdateMeta<'a> {
    pub based_on_vulns_commit: Option<&'a str>,
    pub last_run_unix_time: Option<i32>,
}
