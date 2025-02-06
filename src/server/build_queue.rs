use crate::{
    get_db_connection,
    tuxtape_server::{
        builder_client::BuilderClient, BuildKernelRequest, BuildKernelResponse, KernelConfig,
        PutKernelConfigRequest, RegisterKernelBuilderRequest,
    },
    Args,
};
use std::{
    collections::{HashMap, VecDeque},
    path::Path,
    sync::Arc,
    time::SystemTime,
};
use tokio::sync::{
    mpsc::{self, UnboundedReceiver, UnboundedSender},
    RwLock,
};
use tonic::{
    codec::CompressionEncoding,
    transport::{Certificate, Channel, ClientTlsConfig},
    Status,
};
use tonic_health::pb::{
    health_check_response::ServingStatus, health_client::HealthClient, HealthCheckRequest,
};

pub enum BuildAction {
    RegisterKernelBuilder {
        request: RegisterKernelBuilderRequest,
    },
    RemoveKernelBuilder {
        builder_address: String,
    },
    AddJob {
        request: PutKernelConfigRequest,
    },
    BuildCompleted {
        builder_address: String,
        resp: BuildKernelResponse,
    },
    BuildFailed {
        builder_address: String,
        status: Status,
    },
}

pub struct BuildQueue {
    args: Arc<Args>,
    builders: Arc<RwLock<HashMap<String, Arc<Builder>>>>,
    job_queue: Arc<RwLock<VecDeque<Job>>>,
    pub rx: UnboundedReceiver<BuildAction>,
    pub tx: UnboundedSender<BuildAction>,
}

struct Builder {
    client: Arc<RwLock<BuilderClient<Channel>>>,
    address: String,
    job: Arc<RwLock<Option<Job>>>,
    tx: UnboundedSender<BuildAction>,
}

#[derive(Clone)]
struct Job {
    kernel_config: KernelConfig,
    // TODO (MVP) - rename _time_started to time_started and
    // use it in monitoring messages
    _time_started: SystemTime,
}

impl BuildQueue {
    pub fn new(args: Arc<Args>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<BuildAction>();

        Self {
            args,
            builders: Arc::new(RwLock::new(HashMap::new())),
            job_queue: Arc::new(RwLock::new(VecDeque::new())),
            rx,
            tx,
        }
    }

    pub fn handle_action(&mut self, action: &BuildAction) {
        match action {
            BuildAction::AddJob { request } => {
                let kernel_config = if let Some(kernel_config) = &request.kernel_config {
                    kernel_config
                } else {
                    eprintln!("Attempted to add build job from PutKernelConfigRequest with no kernel_config field");
                    return;
                };

                tokio::spawn(enqueue_job(self.job_queue.clone(), kernel_config.clone()));
            }
            BuildAction::BuildCompleted {
                builder_address,
                resp,
            } => {
                tokio::spawn(write_build_profile_to_db(
                    self.args.clone(),
                    self.builders.clone(),
                    builder_address.clone(),
                    resp.clone(),
                ));
            }
            BuildAction::BuildFailed {
                builder_address,
                status,
            } => {
                eprintln!(
                    "Build failed! Removing kernel builder with address {}. Status: {}",
                    builder_address, status
                );

                tokio::spawn(remove_kernel_builder(
                    self.builders.clone(),
                    self.job_queue.clone(),
                    builder_address.to_string(),
                ));
            }
            BuildAction::RegisterKernelBuilder { request } => {
                tokio::spawn(register_kernel_builder(
                    self.args.clone(),
                    self.builders.clone(),
                    self.tx.clone(),
                    request.clone(),
                ));
            }
            BuildAction::RemoveKernelBuilder { builder_address } => {
                tokio::spawn(remove_kernel_builder(
                    self.builders.clone(),
                    self.job_queue.clone(),
                    builder_address.clone(),
                ));
            }
        }
    }

    pub async fn assign_jobs(&mut self) {
        let mut job_queue = self.job_queue.write().await;
        let mut builders = self.builders.write().await;
        'jobs: while let Some(job) = job_queue.pop_front() {
            for (address, builder) in builders.iter_mut() {
                if builder.job.read().await.is_none() {
                    println!(
                        "Assigning job {} to builder {}",
                        job.kernel_config
                            .metadata
                            .as_ref()
                            .expect("metadata must exist here")
                            .config_name,
                        address
                    );

                    tokio::spawn(build_kernel(builder.clone(), job));
                    continue 'jobs;
                }
            }

            // We weren't able to assign the popped job to a builder. Put it back at highest priority.
            job_queue.push_front(job);
            return;
        }
    }
}

async fn register_kernel_builder(
    args: Arc<Args>,
    builders: Arc<RwLock<HashMap<String, Arc<Builder>>>>,
    tx: UnboundedSender<BuildAction>,
    request: RegisterKernelBuilderRequest,
) {
    let url = match args.tls {
        true => format!("https://{}", request.builder_address),
        false => format!("http://{}", request.builder_address),
    };
    println!("Getting connection to KernelBuilder at URL: {}", url);

    // Strip port from URL if one was provided
    let domain_name = if let Some(domain_name) = request
        .builder_address
        .split(':')
        .collect::<Vec<&str>>()
        .first()
    {
        *domain_name
    } else {
        &url
    };

    let channel = if args.tls {
        let ca_path = &args.tls_ca_path;
        let pem = std::fs::read_to_string(ca_path).expect("ca_path does not exist");
        let ca = Certificate::from_pem(pem);

        let tls = ClientTlsConfig::new()
            .ca_certificate(ca)
            .domain_name(domain_name);

        let endpoint = match Channel::from_shared(url.clone()) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                eprintln!("{}", e);
                return;
            }
        };
        let endpoint = match endpoint.tls_config(tls) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                eprintln!("Failed to create endpoint: {}", e);
                return;
            }
        };

        endpoint.connect().await
    } else {
        let endpoint = match Channel::from_shared(url.clone()) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                eprintln!("Failed to create endpoint: {}", e);
                return;
            }
        };

        endpoint.connect().await
    };

    let channel = match channel {
        Ok(channel) => channel,
        Err(e) => {
            eprintln!("Failed to create endpoint: {}", e);
            return;
        }
    };

    let client = Arc::new(RwLock::new(
        BuilderClient::new(channel.clone())
            .accept_compressed(CompressionEncoding::Gzip)
            .send_compressed(CompressionEncoding::Gzip)
            .max_decoding_message_size(usize::MAX)
            .max_encoding_message_size(usize::MAX),
    ));

    let job = Arc::new(RwLock::new(None));

    let builder = Arc::new(Builder {
        client,
        address: url.clone(),
        job,
        tx: tx.clone(),
    });

    {
        let mut builders = builders.write().await;
        builders.insert(url.clone(), builder);
    }

    tokio::spawn(watch_builder_health(url, channel.clone(), tx));
}

async fn enqueue_job(job_queue: Arc<RwLock<VecDeque<Job>>>, kernel_config: KernelConfig) {
    let metadata = if let Some(metadata) = &kernel_config.metadata {
        metadata
    } else {
        eprintln!("Attempted to enqueue job for kernel_config without metadata field");
        return;
    };

    println!("Enqueueing job for {}", metadata.config_name);

    let job = Job {
        kernel_config,
        _time_started: SystemTime::now(),
    };
    job_queue.write().await.push_back(job);
}

async fn remove_kernel_builder(
    builders: Arc<RwLock<HashMap<String, Arc<Builder>>>>,
    job_queue: Arc<RwLock<VecDeque<Job>>>,
    builder_address: String,
) {
    println!("Removing builder {} from queue.", builder_address);

    let mut builders = builders.write().await;
    let builder = if let Some(builder) = builders.get(&builder_address) {
        builder
    } else {
        eprintln!("No builder matching address {} found", &builder_address);
        return;
    };

    // If builder had a job, add it to the front of the queue
    if let Some(job) = builder.job.write().await.take() {
        let mut job_queue = job_queue.write().await;
        job_queue.push_front(job);
    }

    builders.remove(&builder_address);
}

async fn build_kernel(builder: Arc<Builder>, job: Job) {
    println!("Building kernel");

    let mut builder_job = builder.job.write().await;
    builder_job.replace(job.clone());

    let request = BuildKernelRequest {
        kernel_config: Some(job.kernel_config.clone()),
    };

    let builder_clone = builder.clone();
    tokio::spawn(async move {
        let mut builder_client = builder_clone.client.write().await;
        let result = builder_client.build_kernel(request).await;

        match result {
            Ok(resp) => builder_clone
                .tx
                .send(BuildAction::BuildCompleted {
                    builder_address: builder_clone.address.clone(),
                    resp: resp.into_inner(),
                })
                .expect("Send should never fail"),
            Err(status) => builder_clone
                .tx
                .send(BuildAction::BuildFailed {
                    builder_address: builder_clone.address.clone(),
                    status,
                })
                .expect("Send should never fail"),
        };
    });
}

async fn write_build_profile_to_db(
    args: Arc<Args>,
    builders: Arc<RwLock<HashMap<String, Arc<Builder>>>>,
    builder_address: String,
    resp: BuildKernelResponse,
) {
    let mut builders = builders.write().await;
    let builder = if let Some(builder) = builders.get_mut(&builder_address) {
        builder
    } else {
        eprintln!("Failed to find builder at address: {}", builder_address);
        return;
    };

    // Take ownership of Job from builder
    let job = builder
        .job
        .write()
        .await
        .take()
        .expect("We know there was a job here");

    let metadata = job
        .kernel_config
        .metadata
        .as_ref()
        .expect("metadata should always exist here");

    println!(
        "Build job for {} finished on builder {}",
        metadata.config_name, builder_address
    );

    let included_files = resp.included_files;
    let kernel_config = &job.kernel_config;
    let metadata = kernel_config
        .metadata
        .as_ref()
        .expect("metadata must exist here");
    let kernel_version = metadata
        .kernel_version
        .expect("kernel version must exist here");

    let db = match get_db_connection(Path::new(&args.db_path)) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to get connection to database: {}", e);
            return;
        }
    };

    match db.execute(
        "REPLACE INTO kernel_config (config_name, major, minor, patch, config_file) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            metadata.config_name,
            kernel_version.major,
            kernel_version.minor,
            kernel_version.patch,
            kernel_config.config_file
        ],
    ) {
        Ok(_) => {},
        Err(e) => {
            eprintln!("Failed to write job for {} into database. Error: {}", metadata.config_name, e);
            return;
        }
    }

    for file in included_files {
        match db.execute(
            "REPLACE INTO kernel_file (file_path, config_name) VALUES (?1, ?2)",
            rusqlite::params![file, metadata.config_name],
        ) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "Failed to write job for {} into database. Error: {}",
                    metadata.config_name, e
                );
                return;
            }
        }
    }

    println!(
        "Finished adding {} profile to database",
        metadata.config_name
    )
}

async fn watch_builder_health(
    builder_address: String,
    channel: Channel,
    tx: UnboundedSender<BuildAction>,
) {
    let mut health_client = HealthClient::new(channel)
        .accept_compressed(CompressionEncoding::Gzip)
        .send_compressed(CompressionEncoding::Gzip);

    let result = health_client
        .watch(HealthCheckRequest {
            service: "tuxtape_server.Builder".to_string(),
        })
        .await;

    match result {
        Ok(resp) => {
            let mut stream = resp.into_inner();
            while let Some(message) = stream.message().await.transpose() {
                match message {
                    Ok(resp) => match resp.status() {
                        ServingStatus::Serving => {}
                        _ => {
                            eprintln!(
                                "Kernel builder at {} no longer serving requests.",
                                &builder_address
                            );
                            tx.send(BuildAction::RemoveKernelBuilder { builder_address })
                                .expect("Send should never fail");

                            return;
                        }
                    },
                    Err(_) => {
                        println!("Lost connection to kernel builder at {}", &builder_address);
                        tx.send(BuildAction::RemoveKernelBuilder { builder_address })
                            .expect("Send should never fail");

                        return;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!(
                "Could not connect to health service on kernel builder at {}. Error: {}",
                &builder_address, e
            );
            tx.send(BuildAction::RemoveKernelBuilder { builder_address })
                .expect("Send should never fail")
        }
    }
}
