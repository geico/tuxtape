pub mod build_queue;

use build_queue::{BuildAction, BuildQueue};
use clap::Parser;
use color_eyre::eyre::eyre;
use color_eyre::Result;
use rusqlite::{OpenFlags, Row};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;
use tuxtape_server::database_server::{Database, DatabaseServer};
use tuxtape_server::{
    Cve, CveInstance, FetchCvesReponse, FetchCvesRequest, FetchKernelConfigRequest,
    FetchKernelConfigResponse, FetchKernelConfigsMetadataRequest,
    FetchKernelConfigsMetadataResponse, KernelConfig, KernelConfigMetadata, KernelVersion,
    PutKernelConfigRequest, PutKernelConfigResponse, RegisterKernelBuilderRequest,
    RegisterKernelBuilderResponse,
};
use tokio::sync::Mutex;
use tonic::codec::CompressionEncoding;
use tonic::{
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};

#[derive(Parser, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// The path to the database
    #[arg(short('d'), long, default_value = concat!(env!("HOME"), "/.cache/tuxtape-server/db.db3"))]
    db_path: String,

    /// The socket address for this server, either IPv4 or IPv6.
    #[arg(short('s'), long, default_value = "127.0.0.1:50051")]
    addr: String,

    /// Enables TLS support
    #[arg(short('t'), long, requires_all(["tls_cert_path", "tls_key_path"]), default_value = "false")]
    tls: bool,

    /// Path to TLS CA (requires -t)
    #[arg(long, requires("tls"), default_value = "")]
    tls_ca_path: String,

    /// Path to TLS certificate (requires -t)
    #[arg(long, requires("tls"), default_value = "")]
    tls_cert_path: String,

    /// Path to TLS key (requires -t)
    #[arg(long, requires("tls"), default_value = "")]
    tls_key_path: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Arc::new(Args::parse());

    check_db_tables_exist(Path::new(&args.clone().db_path))?;

    loop {
        // This will return if the server crashes for any reason, so we want to keep this in a loop.
        // In the future, we should log the errors should the server crash.
        start_server(args.clone()).await?;
    }
}

async fn start_server(args: Arc<Args>) -> Result<(), Box<dyn std::error::Error>> {
    let addr = args.addr.parse()?;
    let database = MyDatabase::new(args.clone());
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(tuxtape_server::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<DatabaseServer<MyDatabase>>()
        .await;

    if args.tls {
        let cert = std::fs::read_to_string(&args.tls_cert_path)?;
        let key = std::fs::read_to_string(&args.tls_key_path)?;
        let identity = Identity::from_pem(cert, key);

        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity))?
            .add_service(
                DatabaseServer::new(database)
                    .accept_compressed(CompressionEncoding::Gzip)
                    .send_compressed(CompressionEncoding::Gzip)
                    .max_decoding_message_size(usize::MAX)
                    .max_encoding_message_size(usize::MAX),
            )
            .add_service(reflection_service)
            .add_service(
                health_service
                    .accept_compressed(CompressionEncoding::Gzip)
                    .send_compressed(CompressionEncoding::Gzip),
            )
            .serve(addr)
            .await?
    } else {
        Server::builder()
            .add_service(
                DatabaseServer::new(database)
                    .accept_compressed(CompressionEncoding::Gzip)
                    .send_compressed(CompressionEncoding::Gzip),
            )
            .add_service(reflection_service)
            .add_service(
                health_service
                    .accept_compressed(CompressionEncoding::Gzip)
                    .send_compressed(CompressionEncoding::Gzip),
            )
            .serve(addr)
            .await?
    }

    Ok(())
}

pub mod tuxtape_server {
    tonic::include_proto!("tuxtape_server");

    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("tuxtape_server_descriptor");
}

pub struct MyDatabase {
    args: Arc<Args>,
    build_queue: Arc<Mutex<BuildQueue>>,
}

impl MyDatabase {
    fn new(args: Arc<Args>) -> Self {
        let build_queue = Arc::new(Mutex::new(BuildQueue::new(args.clone())));
        tokio::spawn(loop_update_build_queue(build_queue.clone()));

        Self { args, build_queue }
    }
}

async fn loop_update_build_queue(build_queue: Arc<Mutex<BuildQueue>>) {
    loop {
        let mut build_queue = build_queue.lock().await;
        while let Ok(action) = build_queue.rx.try_recv() {
            build_queue.handle_action(&action);
        }

        build_queue.assign_jobs().await;

        // Wait a bit before receiving new events to prevent CPU overuse
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tonic::async_trait]
impl Database for MyDatabase {
    async fn fetch_cves(
        &self,
        request: Request<FetchCvesRequest>,
    ) -> Result<Response<FetchCvesReponse>, Status> {
        println!("New request to fetch CVEs from {:?}", request.remote_addr());

        let fetch_cve_req = request.into_inner();

        let db = get_db_connection(Path::new(&self.args.db_path))
            .map_err(|err| Status::from_error(Box::new(err)))?;
        let cves = fetch_cves(&db, fetch_cve_req).map_err(|e| Status::from_error(Box::new(e)))?;

        let resp = FetchCvesReponse { cves };
        Ok(Response::new(resp))
    }

    async fn fetch_kernel_configs_metadata(
        &self,
        request: Request<FetchKernelConfigsMetadataRequest>,
    ) -> Result<Response<FetchKernelConfigsMetadataResponse>, Status> {
        println!(
            "New request to fetch kernel configs metadata from {:?}",
            request.remote_addr()
        );

        let db = get_db_connection(Path::new(&self.args.db_path))
            .map_err(|e| Status::from_error(Box::new(e)))?;

        let query = "SELECT name, major, minor, patch FROM kernel_config";
        let mut stmt = db.prepare(query).unwrap();
        let kernel_configs = stmt
            .query_map([], |row| {
                let config_name: String = row.get(0)?;
                let major: u32 = row.get(1)?;
                let minor: u32 = row.get(2)?;
                let patch: Option<u32> = row.get(3)?;

                let kernel_version = Some(KernelVersion {
                    major,
                    minor,
                    patch,
                });

                Ok(KernelConfigMetadata {
                    config_name,
                    kernel_version,
                })
            })
            .map_err(|e| Status::from_error(Box::new(e)))?;

        let resp = FetchKernelConfigsMetadataResponse {
            metadata: kernel_configs.flatten().collect(),
        };
        Ok(Response::new(resp))
    }

    async fn fetch_kernel_config(
        &self,
        request: Request<FetchKernelConfigRequest>,
    ) -> Result<Response<FetchKernelConfigResponse>, Status> {
        println!(
            "New request to fetch kernel configs from {:?}",
            request.remote_addr()
        );

        let db = get_db_connection(Path::new(&self.args.db_path))
            .map_err(|e| Status::from_error(Box::new(e)))?;

        let metadata = request
            .into_inner()
            .metadata
            .expect("Inner should always have metadata");

        let query = "
            SELECT
                config_file 
            FROM 
                kernel_config kc
            WHERE
                kc.config_name = :config_name
        ";
        let mut stmt = db
            .prepare(query)
            .map_err(|e| Status::from_error(Box::new(e)))?;
        let mut result = stmt
            .query(rusqlite::named_params! {":config_name": metadata.config_name})
            .map_err(|e| Status::from_error(Box::new(e)))?;

        let row = result.next().map_err(|e| Status::from_error(Box::new(e)))?;
        if let Some(row) = row {
            let config_file: String = row.get(0).map_err(|e| Status::from_error(Box::new(e)))?;

            let metadata = Some(KernelConfigMetadata {
                config_name: metadata.config_name,
                kernel_version: metadata.kernel_version,
            });
            let kernel_config = Some(KernelConfig {
                metadata,
                config_file,
            });

            let resp = FetchKernelConfigResponse { kernel_config };
            return Ok(Response::new(resp));
        } else {
            return Err(Status::not_found(
                "KernelConfig matching provided metadata not found",
            ));
        }
    }

    async fn put_kernel_config(
        &self,
        request: Request<PutKernelConfigRequest>,
    ) -> Result<Response<PutKernelConfigResponse>, Status> {
        println!(
            "New request to put kernel config from {:?}",
            request.remote_addr()
        );

        let request = request.into_inner();

        let build_queue = self.build_queue.lock().await;
        build_queue
            .tx
            .send(BuildAction::AddJob { request })
            .expect("Send should never fail");

        Ok(Response::new(PutKernelConfigResponse {}))
    }

    async fn register_kernel_builder(
        &self,
        request: Request<RegisterKernelBuilderRequest>,
    ) -> Result<Response<RegisterKernelBuilderResponse>, Status> {
        println!(
            "New request to register kernel builder from {:?}",
            request.remote_addr()
        );

        let request = request.into_inner();
        let action = BuildAction::RegisterKernelBuilder { request };

        {
            let build_queue = self.build_queue.lock().await;
            build_queue.tx.send(action).expect("send should never fail");
        }

        let resp = RegisterKernelBuilderResponse {};
        Ok(Response::new(resp))
    }
}

fn get_db_connection(db_path: &Path) -> Result<rusqlite::Connection, rusqlite::Error> {
    rusqlite::Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
}

fn check_db_tables_exist(db_path: &Path) -> Result<(), rusqlite::Error> {
    // TODO - update for all tables
    let db = get_db_connection(db_path)?;

    let mut stmt = db.prepare("SELECT * FROM cve;")?;
    let _ = stmt.query(())?;

    let mut stmt = db.prepare("SELECT * FROM cve_instance;")?;
    let _ = stmt.query(())?;

    println!("Database exists");

    Ok(())
}

/// Fetch the CVEs that include files that are included in the builds of the kernel_configs of the request.
/// If request.kernel_configs_metadata is empty, returns CVEs that affect all KernelConfigs in the database.
/// If request.kernel_configs_metadata is not empty, returns CVEs that affect the specified KernelConfigs.
fn fetch_cves(
    db: &rusqlite::Connection,
    request: FetchCvesRequest,
) -> Result<Vec<Cve>, rusqlite::Error> {
    // Load array module into sqlite instance
    rusqlite::vtab::array::load_module(db)?;

    // Create an rarray-compatible list of kernel config names from the request
    let mut config_names: Vec<String> = Vec::new();
    for config in &request.kernel_configs_metadata {
        config_names.push(config.config_name.clone());
    }
    let request_configs = Rc::new(
        config_names
            .iter()
            .cloned()
            .map(rusqlite::types::Value::from)
            .collect::<Vec<rusqlite::types::Value>>(),
    );
    let params = if request_configs.is_empty() {
        rusqlite::params![]
    } else {
        rusqlite::params![request_configs]
    };

    // This query is unfortunately massive and convoluted, but it is the fastest way to get the results
    // that I've tested. Trying to do individual queries to flesh out data on fields of CveInstances
    // is much more readable, but takes magnitudes longer to return a result.
    //
    // The query groups its results into a particular order so that we don't need to create hashmaps
    // when building out complete Cve objects then copy them into into vectors.
    // The all_relevant_cve_instances subquery first determines the most relevant CveInstance for each
    // Cve that affects each KernelConfig.
    // Once we know the most relevant CveInstance for each KernelConfig, it then joins that with the Cve
    // metadata for each CveInstance.
    // Each row that gets returned contains part of the information for us to construct a complete Cve.
    // To avoid having to use hashmaps to construct the members of a Cve that are arrays
    // (all CveInstances of that Cve, all files that each CveInstance affects, all KernelConfigs that
    // each CveInstance affects), the query groups its output in a particular order that allows us to
    // first construct a complete CveInstance, then once we've created all CveInstances for a Cve,
    // we can complete the construction of that Cve and repeat the cycle on a new Cve.
    let cve_instances_query = if request_configs.is_empty() {
        "
        WITH
            all_relevant_cve_instances AS (
                SELECT
                    cve,
                    title,
                    version_introduced_major,
                    version_introduced_minor,
                    version_introduced_patch,
                    version_fixed_major,
                    version_fixed_minor,
                    version_fixed_patch,
                    fixed_commit_prefix,
                    ci.patch as patch,
                    config_name,
                    kc.major as kernel_major,
                    kc.minor as kernel_minor,
                    kc.patch as kernel_patch
                FROM
                    cve_instance ci
                    INNER JOIN kernel_config kc ON (
                        (
                            kc.major > ci.version_introduced_major
                            OR (
                                kc.major = ci.version_introduced_major
                                AND kc.minor > ci.version_introduced_minor
                            )
                            OR (
                                kc.major = ci.version_introduced_major
                                AND kc.minor = ci.version_introduced_minor
                                AND COALESCE(kc.patch, 0) >= COALESCE(ci.version_introduced_patch, 0)
                            )
                        )
                        AND (
                            ci.version_fixed_major = kc.major
                            AND ci.version_fixed_minor = kc.minor
                            AND COALESCE(ci.version_fixed_patch, 0) > COALESCE(kc.patch, 0)
                        )
                    )
                GROUP BY
                    cve,
                    config_name
                ORDER BY
                    version_fixed_major ASC,
                    version_fixed_minor ASC,
                    version_fixed_patch ASC
            )
        SELECT
            cve,
            title,
            version_introduced_major,
            version_introduced_minor,
            version_introduced_patch,
            version_fixed_major,
            version_fixed_minor,
            version_fixed_patch,
            fixed_commit_prefix,
            ci.patch as patch,
            config_name,
            kernel_major,
            kernel_minor,
            kernel_patch,
            severity,
            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
            scope,
            confidentiality_impact,
            integrity_impact,
            availability_impact,
            description,
            ciaf.file_path AS affected_file
        FROM
            all_relevant_cve_instances ci
            INNER JOIN cve ON ci.cve = cve.name
            INNER JOIN cve_instance_affected_file ciaf ON ciaf.cve_instance = ci.title
        ORDER BY
            severity DESC,
            title DESC,
            cve DESC,
            config_name ASC
        "
    } else {
        "
        WITH
            filtered_kernel_config AS (
                SELECT
                    config_name, major, minor, patch
                FROM 
                    kernel_config
                WHERE
                    config_name IN rarray(?1)
            ),
            all_relevant_cve_instances AS (
                SELECT
                    cve,
                    title,
                    version_introduced_major,
                    version_introduced_minor,
                    version_introduced_patch,
                    version_fixed_major,
                    version_fixed_minor,
                    version_fixed_patch,
                    fixed_commit_prefix,
                    ci.patch as patch,
                    config_name,
                    kc.major as kernel_major,
                    kc.minor as kernel_minor,
                    kc.patch as kernel_patch
                FROM
                    cve_instance ci
                    INNER JOIN filtered_kernel_config kc ON (
                        (
                            kc.major > ci.version_introduced_major
                            OR (
                                kc.major = ci.version_introduced_major
                                AND kc.minor > ci.version_introduced_minor
                            )
                            OR (
                                kc.major = ci.version_introduced_major
                                AND kc.minor = ci.version_introduced_minor
                                AND COALESCE(kc.patch, 0) >= COALESCE(ci.version_introduced_patch, 0)
                            )
                        )
                        AND (
                            ci.version_fixed_major = kc.major
                            AND ci.version_fixed_minor = kc.minor
                            AND COALESCE(ci.version_fixed_patch, 0) > COALESCE(kc.patch, 0)
                        )
                    )
                GROUP BY
                    cve,
                    config_name
                ORDER BY
                    version_fixed_major ASC,
                    version_fixed_minor ASC,
                    version_fixed_patch ASC
            )
        SELECT
            cve,
            title,
            version_introduced_major,
            version_introduced_minor,
            version_introduced_patch,
            version_fixed_major,
            version_fixed_minor,
            version_fixed_patch,
            fixed_commit_prefix,
            ci.patch as patch,
            config_name,
            kernel_major,
            kernel_minor,
            kernel_patch,
            severity,
            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
            scope,
            confidentiality_impact,
            integrity_impact,
            availability_impact,
            description,
            ciaf.file_path AS affected_file
        FROM
            all_relevant_cve_instances ci
            INNER JOIN cve ON ci.cve = cve.name
            INNER JOIN cve_instance_affected_file ciaf ON ciaf.cve_instance = ci.title
        ORDER BY
            severity DESC,
            title DESC,
            cve DESC,
            config_name ASC
        "
    };

    let mut cves: Vec<Cve> = Vec::new();
    let mut stmt = db.prepare(cve_instances_query)?;
    let mut rows: rusqlite::Rows<'_> = stmt.query(params)?;
    while let Ok(Some(row)) = rows.next() {
        let row = FetchCvesRow::try_from(row)?;

        if let Some(last_cve) = cves.last_mut() {
            if last_cve.id == row.cve_id {
                // This row contains more information about the Cve from the last row.
                // Check if we're on the same CveInstance.
                let last_cve_instance = if let Some(last_cve_instance) = last_cve.instances.last() {
                    last_cve_instance
                } else {
                    continue;
                };

                if last_cve_instance.title == row.instance_title {
                    // We are on the same CveInstance as the last row, check if we're on the same affected_config.
                    let last_affected_config = if let Some(last_affected_config) =
                        last_cve_instance.affected_configs.last()
                    {
                        last_affected_config
                    } else {
                        continue;
                    };

                    if last_affected_config.config_name == row.config_name {
                        // We are on the same affected_config. Push new affected file.
                        let affected_file = if let Some(affected_file) = row.affected_file {
                            affected_file
                        } else {
                            continue;
                        };

                        if let Some(last_cve_instance) = last_cve.instances.last_mut() {
                            last_cve_instance.affected_files.push(affected_file);
                        }
                    } else {
                        // We have a new affected_config. Push it.
                        if let Some(last_cve_instance) = last_cve.instances.last_mut() {
                            last_cve_instance
                                .affected_configs
                                .push(KernelConfigMetadata::from(&row));
                        }
                    }
                } else {
                    // We are on a new CveInstance but the same Cve. Create it, push it.
                    let cve_instance = match CveInstance::try_from(&row) {
                        Ok(cve_instance) => cve_instance,
                        Err(e) => {
                            println!("Bad CveInstance stored in database: {:?}", e);
                            continue;
                        }
                    };
                    last_cve.instances.push(cve_instance);
                }
            } else {
                // This row contains a new CVE. Create a new one, push it.
                let new_cve = match Cve::try_from(&row) {
                    Ok(new_cve) => new_cve,
                    Err(e) => {
                        println!("Bad Cve stored in database: {:?}", e);
                        continue;
                    }
                };
                cves.push(new_cve);
            }
        } else {
            // This is our first Cve. Push it.
            let new_cve = match Cve::try_from(&row) {
                Ok(new_cve) => new_cve,
                Err(e) => {
                    println!("Bad Cve stored in database: {:?}", e);
                    continue;
                }
            };
            cves.push(new_cve);
        }
    }

    Ok(cves)
}

struct FetchCvesRow {
    cve_id: String,
    instance_title: String,
    version_introduced_major: u32,
    version_introduced_minor: u32,
    version_introduced_patch: Option<u32>,
    version_fixed_major: Option<u32>,
    version_fixed_minor: Option<u32>,
    version_fixed_patch: Option<u32>,
    fixed_commit_prefix: Option<String>,
    patch: Option<String>,
    config_name: String,
    kernel_config_major: u32,
    kernel_config_minor: u32,
    kernel_config_patch: Option<u32>,
    severity: Option<f32>,
    attack_vector: Option<String>,
    attack_complexity: Option<String>,
    privileges_required: Option<String>,
    user_interaction: Option<String>,
    scope: Option<String>,
    confidentiality_impact: Option<String>,
    integrity_impact: Option<String>,
    availability_impact: Option<String>,
    description: Option<String>,
    affected_file: Option<String>,
}

impl<'stmt> TryFrom<&Row<'stmt>> for FetchCvesRow {
    type Error = rusqlite::Error;

    fn try_from(row: &Row<'stmt>) -> Result<Self, rusqlite::Error> {
        let cve_id: String = row.get(0)?;
        let instance_title: String = row.get(1)?;
        let version_introduced_major: u32 = row.get(2)?;
        let version_introduced_minor: u32 = row.get(3)?;
        let version_introduced_patch: Option<u32> = row.get(4)?;
        let version_fixed_major: Option<u32> = row.get(5)?;
        let version_fixed_minor: Option<u32> = row.get(6)?;
        let version_fixed_patch: Option<u32> = row.get(7)?;
        let fixed_commit_prefix: Option<String> = row.get(8)?;
        let patch: Option<String> = row.get(9)?;
        let config_name: String = row.get(10)?;
        let kernel_config_major: u32 = row.get(11)?;
        let kernel_config_minor: u32 = row.get(12)?;
        let kernel_config_patch: Option<u32> = row.get(13)?;
        let severity: Option<f32> = row.get(14)?;
        let attack_vector: Option<String> = row.get(15)?;
        let attack_complexity: Option<String> = row.get(16)?;
        let privileges_required: Option<String> = row.get(17)?;
        let user_interaction: Option<String> = row.get(18)?;
        let scope: Option<String> = row.get(19)?;
        let confidentiality_impact: Option<String> = row.get(20)?;
        let integrity_impact: Option<String> = row.get(21)?;
        let availability_impact: Option<String> = row.get(22)?;
        let description: Option<String> = row.get(23)?;
        let affected_file: Option<String> = row.get(24)?;

        Ok(Self {
            cve_id,
            instance_title,
            version_introduced_major,
            version_introduced_minor,
            version_introduced_patch,
            version_fixed_major,
            version_fixed_minor,
            version_fixed_patch,
            fixed_commit_prefix,
            patch,
            config_name,
            kernel_config_major,
            kernel_config_minor,
            kernel_config_patch,
            severity,
            attack_vector,
            attack_complexity,
            privileges_required,
            user_interaction,
            scope,
            confidentiality_impact,
            integrity_impact,
            availability_impact,
            description,
            affected_file,
        })
    }
}

impl TryFrom<&FetchCvesRow> for Cve {
    type Error = color_eyre::Report;

    fn try_from(row: &FetchCvesRow) -> Result<Self, color_eyre::Report> {
        let instances = match CveInstance::try_from(row) {
            Ok(cve_instance) => vec![cve_instance],
            Err(e) => return Err(e),
        };

        Ok(Self {
            id: row.cve_id.clone(),
            severity: row.severity,
            attack_vector: row.attack_vector.clone(),
            attack_complexity: row.attack_complexity.clone(),
            privileges_required: row.privileges_required.clone(),
            user_interaction: row.user_interaction.clone(),
            scope: row.scope.clone(),
            confidentiality_impact: row.confidentiality_impact.clone(),
            integrity_impact: row.integrity_impact.clone(),
            availability_impact: row.availability_impact.clone(),
            description: row.description.clone(),
            instances,
        })
    }
}

impl TryFrom<&FetchCvesRow> for CveInstance {
    type Error = color_eyre::Report;

    fn try_from(row: &FetchCvesRow) -> Result<Self, color_eyre::Report> {
        let introduced = Some(KernelVersion {
            major: row.version_introduced_major,
            minor: row.version_introduced_minor,
            patch: row.version_introduced_patch,
        });

        let fixed = if let Some(version_fixed_major) = row.version_fixed_major {
            let version_fixed_minor = if let Some(version_fixed_minor) = row.version_fixed_minor {
                version_fixed_minor
            } else {
                return Err(eyre!("row missing version_introduced_minor"));
            };

            Some(KernelVersion {
                major: version_fixed_major,
                minor: version_fixed_minor,
                patch: row.version_fixed_patch,
            })
        } else {
            None
        };

        let affected_files = if let Some(affected_file) = row.affected_file.clone() {
            vec![affected_file]
        } else {
            vec![]
        };

        Ok(Self {
            title: row.instance_title.clone(),
            introduced,
            fixed,
            fixed_commit_prefix: row.fixed_commit_prefix.clone(),
            affected_files,
            affected_configs: vec![KernelConfigMetadata::from(row)],
            raw_patch: row.patch.clone(),
            // TODO (MVP) - update once deployable_patch is implemented
            deployable_patch: None,
        })
    }
}

impl From<&FetchCvesRow> for KernelConfigMetadata {
    fn from(row: &FetchCvesRow) -> Self {
        let kernel_version = Some(KernelVersion {
            major: row.kernel_config_major,
            minor: row.kernel_config_minor,
            patch: row.kernel_config_patch,
        });

        Self {
            config_name: row.config_name.clone(),
            kernel_version,
        }
    }
}
