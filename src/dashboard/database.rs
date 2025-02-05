/// This file should hold the single connection to the TuxTape database needed for this dashboard.
/// Every function here should be `async` so requests to the database do not block the TUI.
mod tuxtape_server {
    tonic::include_proto!("tuxtape_server");
}

use crate::action::Action;
use crate::config::Config;
use color_eyre::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use strum::Display;
use tokio::sync::mpsc::UnboundedSender;
use tonic::{
    codec::CompressionEncoding,
    transport::{Certificate, Channel, ClientTlsConfig},
};
use tuxtape_server::{database_client::DatabaseClient, FetchCvesRequest, PutKernelConfigRequest};
pub use tuxtape_server::{Cve, CveInstance, KernelConfig, KernelConfigMetadata, KernelVersion};

#[derive(Clone)]
pub struct Database {
    client: DatabaseClient<Channel>,
    command_tx: UnboundedSender<Action>,
}

impl Database {
    pub async fn new(config: Arc<Config>, command_tx: UnboundedSender<Action>) -> Result<Self> {
        let url = match config.database.use_tls {
            true => format!("https://{}", config.database.server_url),
            false => format!("http://{}", config.database.server_url),
        };

        // Strip port from URL if one was provided
        let domain_name = if let Some(domain_name) = config
            .database
            .server_url
            .split(':')
            .collect::<Vec<&str>>()
            .first()
        {
            *domain_name
        } else {
            &config.database.server_url
        };

        let channel =
            match config.database.use_tls {
                true => {
                    // TODO - improve error handling
                    let pem =
                        std::fs::read_to_string(config.database.tls_cert_path.as_ref().expect(
                            "tls cert does not exist but option use_tls = true in config",
                        ))?;
                    let ca = Certificate::from_pem(pem);

                    let tls = ClientTlsConfig::new()
                        .ca_certificate(ca)
                        .domain_name(domain_name);

                    Channel::from_shared(url)?
                        .tls_config(tls)?
                        .connect()
                        .await?
                }
                false => Channel::from_shared(url)?.connect().await?,
            };

        let client = DatabaseClient::new(channel)
            .accept_compressed(CompressionEncoding::Gzip)
            .send_compressed(CompressionEncoding::Gzip)
            .max_decoding_message_size(usize::MAX)
            .max_encoding_message_size(usize::MAX);

        Ok(Self { client, command_tx })
    }

    pub fn handle_request(&self, request: &Request) -> Result<()> {
        match request {
            Request::PopulateTable() => {
                tokio::task::spawn(fetch_all_relevant_cves(self.clone()));
            }
            Request::PutKernelConfig(kernel_config) => {
                tokio::task::spawn(put_kernel_config(self.clone(), kernel_config.clone()));
            }
        }

        Ok(())
    }
}

async fn fetch_all_relevant_cves(mut db: Database) {
    let request = create_fetch_cves_request(None, false, false);
    let response = db.client.fetch_cves(request).await.unwrap();
    let cves = response
        .into_inner()
        .cves
        .iter()
        .map(|cve| Arc::new(cve.clone()))
        .collect();

    let database_response = Response::PopulateTable(cves);
    let action = Action::Database(DatabaseAction::Response(database_response));
    let _ = db.command_tx.send(action);
}

fn create_fetch_cves_request(
    kernel_configs_metadata: Option<Vec<KernelConfigMetadata>>,
    exclude_unpatched: bool,
    exclude_deployable_patched: bool,
) -> tonic::Request<FetchCvesRequest> {
    let kernel_configs_metadata = kernel_configs_metadata.unwrap_or_default();

    let fetch_cve_req = FetchCvesRequest {
        kernel_configs_metadata,
        exclude_unpatched,
        exclude_deployable_patched,
    };
    tonic::Request::new(fetch_cve_req)
}

async fn put_kernel_config(mut db: Database, kernel_config: KernelConfig) {
    let request = PutKernelConfigRequest {
        kernel_config: Some(kernel_config.clone()),
    };
    let response = db.client.put_kernel_config(request).await;

    let database_response = Response::PutKernelConfig {
        kernel_config_metadata: kernel_config.metadata,
        success: response.is_ok(),
    };
    let action = Action::Database(DatabaseAction::Response(database_response));
    db.command_tx.send(action).expect("Should not fail to send");
}

#[derive(Debug, Clone, PartialEq, Display, Serialize, Deserialize)]
pub enum DatabaseAction {
    Request(Request),
    Response(Response),
}

#[derive(Debug, Clone, PartialEq, Display, Serialize, Deserialize)]
pub enum Request {
    PopulateTable(),
    PutKernelConfig(KernelConfig),
}

#[derive(Debug, Clone, PartialEq, Display, Serialize, Deserialize)]
pub enum Response {
    PopulateTable(Vec<Arc<Cve>>),
    PutKernelConfig {
        kernel_config_metadata: Option<KernelConfigMetadata>,
        success: bool,
    },
}
