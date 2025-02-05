/// A kernel builder that registers itself to tuxtape-server and anticipates BuildKernelRequests.
///
/// Note: Currently, this program caches the Linux kernel repo as its build source instead of grabbing
/// a tarball. The idea is for a builder to be relatively ephimeral so we can scale this up/down as
/// we need, and fetching the whole Linux source code history is not ideal for that. In future versions,
/// we probably should store Linux kernels in the artifactory and fetch from there instead.

mod tuxtape_server {
    tonic::include_proto!("tuxtape_server");
}

use clap::Parser;
use color_eyre::eyre::{eyre, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tonic::codec::CompressionEncoding;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tonic_health::pb::{
    health_check_response::ServingStatus,
    health_client::HealthClient,
    health_server::{Health, HealthServer},
    HealthCheckRequest,
};
use tuxtape_server::builder_server::{Builder, BuilderServer};
use tuxtape_server::database_client::DatabaseClient;
use tuxtape_server::{
    BuildKernelRequest, BuildKernelResponse, KernelVersion, RegisterKernelBuilderRequest,
};

const CACHE_PATH: &str = concat!(env!("HOME"), "/.cache/tuxtape-kernel-builder");
const BUILD_PATH: &str = const_format::concatcp!(CACHE_PATH, "/builds");
const BUILD_PROFILES_PATH: &str = const_format::concatcp!(CACHE_PATH, "/build-profiles");
const GIT_PATH: &str = const_format::concatcp!(CACHE_PATH, "/git");
const LINUX_REPO_PATH: &str = const_format::concatcp!(GIT_PATH, "/linux");
const LINUX_REPO_URL: &str = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git";

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(about = "A kernel builder that connects to tuxtape-server.", long_about = None)]
struct Args {
    /// The socket address for this server, either IPv4 or IPv6.
    #[arg(short('a'), long, default_value = "127.0.0.1:50052")]
    addr: String,

    /// The web URL for this server (like tuxtape-kernel-builder.com)
    #[arg(short('u'), long, default_value = "")]
    url: String,

    /// The URL (and port) to tuxtape-server, either IPv4, IPv6, or domain name.
    #[arg(short('s'), long, default_value = "127.0.0.1:50051")]
    tuxtape_server_url: String,

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
async fn main() -> Result<()> {
    let mut args = Args::parse();
    if args.url.is_empty() {
        args.url = args.addr.clone();
    }
    let args = Arc::new(args);

    if !Path::new(LINUX_REPO_PATH).exists() {
        println!(
            "Linux repo dir '{}' does not exist. Creating.",
            LINUX_REPO_PATH
        );
        std::fs::create_dir_all(LINUX_REPO_PATH)?;
    }

    if !Path::new(format!("{}/.git", LINUX_REPO_PATH).as_str()).exists() {
        Command::new("git")
            .current_dir(LINUX_REPO_PATH)
            .args(["clone", LINUX_REPO_URL])
            .spawn()?
            .wait()?;
    }

    loop {
        println!("Attempting to connect to tuxtape-server at {}", &args.url);

        // This will return if the server crashes for any reason, so we want to keep this in a loop.
        // In the future, we should log the errors should the server crash.
        let result = start_server(args.clone()).await;
        match result {
            Ok(()) => {}
            Err(e) => eprintln!("Connection to tuxtape-server failed with error: {}", e),
        }

        // Wait for a bit then try to reconnect to server.
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

struct MyBuilder {}

#[tonic::async_trait]
impl Builder for MyBuilder {
    async fn build_kernel(
        &self,
        request: Request<BuildKernelRequest>,
    ) -> Result<Response<BuildKernelResponse>, Status> {
        println!(
            "New request to build kernel from {:?}",
            request.remote_addr()
        );

        if let Some(kernel_config) = &request.into_inner().kernel_config {
            if let Some(metadata) = &kernel_config.metadata {
                if let Some(kernel_version) = &metadata.kernel_version {
                    let result = build_kernel(
                        &kernel_config.config_file,
                        &metadata.config_name,
                        kernel_version,
                    );

                    match result {
                        Ok(_) => {
                            let included_files = get_included_files(&metadata.config_name);
                            match included_files {
                                Ok(included_files) => {
                                    Ok(Response::new(BuildKernelResponse { included_files }))
                                }
                                Err(e) => Err(Status::from_error(e.into())),
                            }
                        }
                        Err(e) => Err(Status::from_error(e.into())),
                    }
                } else {
                    Err(Status::invalid_argument(
                        "Request missing kernel_config.metadata.kernel_version",
                    ))
                }
            } else {
                Err(Status::invalid_argument(
                    "Request missing kernel_config.metadata",
                ))
            }
        } else {
            Err(Status::invalid_argument("Request missing kernel_config"))
        }
    }
}

async fn start_server(args: Arc<Args>) -> Result<()> {
    let builder = MyBuilder {};

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<BuilderServer<MyBuilder>>()
        .await;

    let tuxtape_server_url = match args.tls {
        true => format!("https://{}", &args.tuxtape_server_url),
        false => format!("http://{}", &args.tuxtape_server_url),
    };

    // Strip port from URL if one was provided
    let domain_name = if let Some(domain_name) = args
        .tuxtape_server_url
        .split(':')
        .collect::<Vec<&str>>()
        .first()
    {
        *domain_name
    } else {
        &tuxtape_server_url
    };

    let channel = match args.tls {
        true => {
            let pem = std::fs::read_to_string(&args.tls_ca_path)?;
            let ca = Certificate::from_pem(pem);

            let tls = ClientTlsConfig::new()
                .ca_certificate(ca)
                .domain_name(domain_name);

            Channel::from_shared(tuxtape_server_url)?
                .tls_config(tls)?
                .connect()
                .await?
        }
        false => Channel::from_shared(tuxtape_server_url)?.connect().await?,
    };

    println!("Starting kernel builder server.");

    let builder_service = BuilderServer::new(builder);

    let mut join_set = tokio::task::JoinSet::new();
    join_set.spawn(register_to_tuxtape_server(args.clone(), channel.clone()));
    join_set.spawn(host_server(args, health_service, builder_service));
    join_set.spawn(watch_server_health(channel));

    while let Some(join_result) = join_set.join_next().await {
        join_result??
    }

    Ok(())
}

async fn register_to_tuxtape_server(args: Arc<Args>, channel: Channel) -> Result<()> {
    let builder_address: String = args.url.clone();
    let mut tuxtape_server_client = DatabaseClient::new(channel)
        .accept_compressed(CompressionEncoding::Gzip)
        .send_compressed(CompressionEncoding::Gzip)
        .max_decoding_message_size(usize::MAX)
        .max_encoding_message_size(usize::MAX);

    tuxtape_server_client
        .register_kernel_builder(RegisterKernelBuilderRequest { builder_address })
        .await?;

    println!("Registered to tuxtape-server.");

    Ok(())
}

async fn host_server(
    args: Arc<Args>,
    health_service: HealthServer<impl Health>,
    builder_service: BuilderServer<MyBuilder>,
) -> Result<()> {
    let addr = args.addr.parse()?;

    if args.tls {
        let cert = std::fs::read_to_string(&args.tls_cert_path)?;
        let key = std::fs::read_to_string(&args.tls_key_path)?;
        let identity = Identity::from_pem(cert, key);

        Server::builder()
            .tls_config(ServerTlsConfig::new().identity(identity))?
            .add_service(
                health_service
                    .accept_compressed(CompressionEncoding::Gzip)
                    .send_compressed(CompressionEncoding::Gzip),
            )
            .add_service(
                builder_service
                    .accept_compressed(CompressionEncoding::Gzip)
                    .send_compressed(CompressionEncoding::Gzip)
                    .max_decoding_message_size(usize::MAX)
                    .max_encoding_message_size(usize::MAX),
            )
            .serve(addr)
            .await?;
    } else {
        Server::builder()
            .add_service(
                health_service
                    .accept_compressed(CompressionEncoding::Gzip)
                    .send_compressed(CompressionEncoding::Gzip),
            )
            .add_service(
                builder_service
                    .accept_compressed(CompressionEncoding::Gzip)
                    .send_compressed(CompressionEncoding::Gzip)
                    .max_decoding_message_size(usize::MAX)
                    .max_encoding_message_size(usize::MAX),
            )
            .serve(addr)
            .await?;
    }

    Ok(())
}

async fn watch_server_health(channel: Channel) -> Result<()> {
    let mut health_client = HealthClient::new(channel)
        .accept_compressed(CompressionEncoding::Gzip)
        .send_compressed(CompressionEncoding::Gzip);

    let result = health_client
        .watch(HealthCheckRequest {
            service: "tuxtape_server.Database".to_string(),
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
                            return Err(eyre!("tuxtape-server stopped serving requests"));
                        }
                    },
                    Err(_) => {
                        return Err(eyre!("Lost connection to tuxtape-server"));
                    }
                }
            }
        }
        Err(e) => {
            return Err(eyre!(
                "Could not connect to health service on tuxtape-server. Error: {}",
                e
            ));
        }
    }

    Ok(())
}

fn checkout_kernel_version(kernel_version: &KernelVersion) -> Result<()> {
    let result = Command::new("git")
        .current_dir(LINUX_REPO_PATH)
        .args(["clean", "-f", "-d", "-x"])
        .spawn()?
        .wait_with_output()?;

    match result.status.success() {
        true => {}
        false => {
            return Err(eyre!(
                "git clean -f -d failed with output: {}",
                String::from_utf8(result.stdout)?
            ))
        }
    }

    let result = Command::new("git")
        .current_dir(LINUX_REPO_PATH)
        .args(["reset", "--hard", "HEAD"])
        .spawn()?
        .wait_with_output()?;

    match result.status.success() {
        true => {}
        false => {
            return Err(eyre!(
                "git reset --hard HEAD failed with output: {}",
                String::from_utf8(result.stdout)?
            ))
        }
    }

    let tag_string = format!(
        "v{}.{}{}",
        kernel_version.major,
        kernel_version.minor,
        match kernel_version.patch {
            Some(patch) => format!(".{}", patch),
            None => "".to_string(),
        }
    );

    let result = Command::new("git")
        .current_dir(LINUX_REPO_PATH)
        .args(["checkout", tag_string.as_str()])
        .spawn()?
        .wait_with_output()?;

    match result.status.success() {
        true => Ok(()),
        false => Err(eyre!(
            "Git failed to checkout tag {} with output: {}",
            tag_string,
            String::from_utf8(result.stdout)?
        )),
    }
}

fn build_kernel(
    config_file: &str,
    config_name: &str,
    kernel_version: &KernelVersion,
) -> Result<()> {
    println!("Building kernel");

    // Sanity check before running rm -rf
    let build_path = Path::new(BUILD_PATH);
    let build_profiles_path = Path::new(BUILD_PROFILES_PATH);
    let cache_path: &Path = Path::new(CACHE_PATH);

    if build_path
        .parent()
        .is_none_or(|parent| parent != cache_path)
    {
        return Err(eyre!(
            "BUILD_PATH ({}) is not a child of CACHE_PATH ({})",
            BUILD_PATH,
            CACHE_PATH
        ));
    }

    if build_profiles_path
        .parent()
        .is_none_or(|parent| parent != cache_path)
    {
        return Err(eyre!(
            "BUILD_PROFILES_PATH ({}) is not a child of CACHE_PATH ({})",
            BUILD_PROFILES_PATH,
            CACHE_PATH
        ));
    }

    let build_output_path = PathBuf::from(format!("{}/{}", BUILD_PATH, config_name));
    let build_profile_output_path =
        PathBuf::from(format!("{}/{}", BUILD_PROFILES_PATH, config_name).as_str());

    // Clear out build_output_path and build_profile_output_path if they already exist
    Command::new("rm")
        .arg("-r")
        .arg("-f")
        .arg(&build_output_path)
        .spawn()?
        .wait()?;

    Command::new("rm")
        .arg("-r")
        .arg("-f")
        .arg(&build_profile_output_path)
        .spawn()?
        .wait()?;

    if !build_output_path.exists() {
        std::fs::create_dir_all(&build_output_path)?;
    }
    if !build_profile_output_path.exists() {
        std::fs::create_dir_all(&build_profile_output_path)?;
    }

    checkout_kernel_version(kernel_version)?;

    Command::new("make")
        .arg("distclean")
        .current_dir(LINUX_REPO_PATH)
        .spawn()?
        .wait()?;

    let config_file_path = build_output_path.join(".config");
    std::fs::write(config_file_path, config_file)?;

    // For some reason, Command is sometimes capturing a " character, so this filters
    // out all non-numeric characters
    let nproc_retval = Command::new("nproc")
        .output()?
        .stdout
        .iter()
        .filter(|char| char.is_ascii_digit())
        .copied()
        .collect();
    let threads = String::from_utf8(nproc_retval)?;
    let threads_arg = format!("-j{threads}");

    Command::new("make")
        .args([
            "-C",
            LINUX_REPO_PATH,
            "defconfig",
            format!("O={}", build_output_path.to_str().unwrap()).as_str(),
        ])
        .spawn()?
        .wait()?;

    Command::new("remake")
        .args([
            "--profile=json",
            format!(
                "--profile-directory={}",
                &build_profile_output_path.to_str().unwrap()
            )
            .as_str(),
            threads_arg.as_str(),
            "-C",
            LINUX_REPO_PATH,
            format!("O={}", build_output_path.to_str().unwrap()).as_str(),
        ])
        .spawn()?
        .wait()?;

    println!("Done building kernel");

    Ok(())
}

fn get_included_files(config_name: &str) -> Result<Vec<String>> {
    let build_profile_output_path =
        PathBuf::from(format!("{}/{}", BUILD_PROFILES_PATH, config_name).as_str());
    if !build_profile_output_path.exists() {
        std::fs::create_dir_all(&build_profile_output_path)?;
    }

    let mut included_files: HashSet<String> = HashSet::new();

    for file in build_profile_output_path.read_dir()?.flatten() {
        // Only operate on .json files
        if !file.path().extension().map_or(false, |s| s == "json") {
            continue;
        }

        let json = File::open(file.path())?;
        let kernel_profile: KernelProfileJson = serde_json::from_reader(json)
            .unwrap_or_else(|_| panic!("Failed at file: {:?}", file.path()));

        for target in kernel_profile.targets {
            if let Some(file) = target.file {
                let stripped_file = file.strip_prefix(LINUX_REPO_PATH).unwrap_or(&file);

                if Path::new(LINUX_REPO_PATH)
                    .join(Path::new(stripped_file))
                    .is_file()
                {
                    included_files.insert(stripped_file.to_string());
                }
            }

            for depend in target.depends {
                let stripped_file = depend.strip_prefix(LINUX_REPO_PATH).unwrap_or(&depend);

                if Path::new(LINUX_REPO_PATH)
                    .join(Path::new(stripped_file))
                    .is_file()
                {
                    included_files.insert(stripped_file.to_string());
                }
            }
        }
    }

    Ok(included_files.into_iter().collect())
}

#[derive(Serialize, Deserialize)]
struct KernelProfileJson {
    targets: Vec<Target>,
}

#[derive(Serialize, Deserialize)]
struct Target {
    file: Option<String>,
    depends: Vec<String>,
}
