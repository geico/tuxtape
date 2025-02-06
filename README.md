# TuxTape

TuxTape is an ecosystem for generating, compiling, deploying, and installing Linux kernel livepatches. It is a toolchain for simplifying the workflow of [kpatch](https://github.com/dynup/kpatch). 

Kernel livepatching is a service provided by many large companies (Canonical, Red Hat, Oracle, SuSE, TuxCare, etc), but as of today, no open source toolchain exists to allow individuals to self manage such a service. Additionally, most of these companies (with the exception of TuxCare) only provide livepatching services for their own custom kernel, e.g. Red Hat will only provide livepatches for the RHEL kernel.

The mission of TuxTape is not to invalidate these services. Reviewing patches, monitoring the success of patch application, and maintaining infrastructure to distribute patches are tasks that will make sense for many system administrators to outsource. 

One should consider TuxTape if they, whether for security reasons, cost reasons, or requirements to maintain custom kernels, have the need to maintain their own livepatching solution.

## Development Status

⚠️ **WARNING: This branch currently contains the proof-of-concept (PoC) of TuxTape. This is not meant to be utilized in production, and the project is expected to change dramatically from this state in the upcoming months. The PoC code is only shared for reference.** ⚠️

At this point in time, planning for the minimum viable product (MVP) is still in progress so implementation specifics are not yet available.

For more information on TuxTape, please review our FOSDEM 2025 talk [here](https://fosdem.org/2025/schedule/event/fosdem-2025-5689-tuxtape-a-kernel-livepatching-solution/).

## Pieces

The full livepatch solution, once developed, will consist of the following pieces: 

1. Common Vulnerabilities and Exposures (CVE) Scanner: The kernel community is its own CVE Numbering Authority (CNA) and publishes all CVE information in a [public mailing list](https://lore.kernel.org/linux-cve-announce/) and in [a git tree](https://git.kernel.org/pub/scm/linux/security/vulns.git). The CVE scanner will monitor this list for vulnerabilities which affect files which are compiled into our kernel. Fortunately, each email lists links to the patches fixing the vulnerability. The scanner can be run as a cronjob.

1. CVE Prioritizer: Unfortunately, since the kernel community believes that every bug is a possible security bug, the mailing list is very active. A method of prioritizing CVEs is still being devised.

1. Applicability Gauge: For any CVE which is deemed high enough priority, we must also decide whether it is applicable. This step is separated from the prioritizer because a basic priority applies for the CVE across all kernels, while applicability is per kernel. Since TuxTape is built to support multiple kernel configurations and distributions besides just mainline, some CVEs will stem from source files which are built into some but not all kernels. The applicability gauge will determine, for each kernel, whether a CVE is applicable.

1. Patch Generator: Once a CVE has been identified as worthy of live-patching, the Patch Generator will fetch the fixing commits and automatically generate a loadable module for the fix. In case the generator is unable to do so, it will send a notice to the system administrators to manually attempt to generate a livepatch module. Patches which are auto-generated will need to be carefully vetted through some combination of CI, heuristics, AI review, and human review.

1. Kernel Log Parser: Analyzes kernel warnings to determine whether a livepatch module has misbehaved.

1. Patch Archive: There is a need to publish all livepatch modules, as well as per-kernel and per-version lists of applicable modules. We are considering signing these using the [The Update Framework (TUF)](https://theupdateframework.io/) approach – signing using short-lived keys so that clients can be sure not to be handed stale data. The final state of the Patch Archive is still in discussion.

1. Fleet Client: Every node in the fleet will run a lightweight client which tracks the kernel version and livepatch status of the node on which it runs. It will periodically fetch the latest information from the Patch Archive. See below for details about how we intend to handle cases like [a system being buggy after a livepatch update](https://web.archive.org/web/20240913235734/https://ubuntu.com/security/livepatch/docs/livepatch/reference/what_if_my_system_crashes).

---

# tuxtape-poc

This repo contains a proof of concept for TuxTape: a Linux kernel livepatching solution.

> Note: TuxTape only supports kernels based on minor versions currently supported by the mainline kernel maintainers. Do not expect TuxTape to provide backported LTS-like support to non-LTS kernels.

This branch does not contain all of the future aspects of TuxTape which will compile the patches and distribute them to clients, nor the client which makes requests for and installs those patches.

The proof of concept builds four different binaries, which are detailed below.

## tuxtape-cve-parser

Parses the CVEs catalogued by the Linux kernel maintainers and generates a sqlite database of patch files. 
Since this project requires the full Linux Stable branch to be pulled and thousands of patches to be generated and CVE data pulled from NIST APIs,
the first run will take a decent amount of time to complete (likely over an hour). Each successive run takes less time as the commit history of the kernel will only be pulled on first run, and successive runs only build patches
from the diff of the `HEAD` of the `vulns` repo at the last run and the current `HEAD`.
This should be run as a cronjob to update the database periodically. This database can be used in livepatching
solutions.

The database is hardcoded to reside at `~/.cache/tuxtape-server/db.db3`.

> WARNING: Since the patch files are automatically generated, this program should undergo extensive testing
which has not yet been done before being used in production.

## tuxtape-server

The server is used to query the sqlite database created by `tuxtape-cve-parser` and provide a gRPC API for clients like `tuxtape-dashboard` to utilize for the creation of `kpatch`-compatible patches (referred to as "deployable" patches).

## tuxtape-kernel-builder

This is an additional server that registers itself to `tuxtape-server` upon startup and serves requests to build kernels from configs generated by `tuxtape-dashboard`. Once it is done, it reports the build profile (what files were included in the build) back to `tuxtape-server` and it gets added to the database.

> Note: This also requires the full git history of the Linux kernel to be pulled, so the first open will take a rather long time. If you already have the repo cloned, feel free to copy it to `~/.cache/tuxtape-kernel-builder/git/linux`.

## tuxtape-dashboard

A TUI dashboard used to create deployable patches from the "raw" patches stored in `tuxtape-server` and added to its database created by `tuxtape-cve-parser`. It will also be used to review deployable patches written by other kernel developers and deploy them to the fleet once approved. This dashboard is also used to create new kernel configs.

> Note: This also requires the full git history of the Linux kernel to be pulled, so the first open will take a rather long time. If you already have the repo cloned, feel free to copy it to `~/.cache/tuxtape-dashboard/git/linux`.

More detailed information about the TUI architecture can be found at `src/dashboard/README.md`.

## Dependencies (Ubuntu 24.04)

Build dependencies:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

sudo apt install build-essential pkg-config libssl-dev protobuf-compiler 
```

Runtime dependencies for both `tuxtape-kernel-builder` and `tuxtape-dashboard`
```
sudo apt install libncurses-dev bison flex libelf-dev
```

Additional runtime dependency for `tuxtape-kernel-builder`
```
sudo apt install remake
```

## Running instructions

```
# To build
cargo build --all

# For the parser
cargo run --bin tuxtape-cve-parser

# For the server
cargo run --bin tuxtape-server

# For the kernel builder
cargo run --bin tuxtape-kernel-builder

# For the dashboard
cargo run --bin tuxtape-dashboard
```

## Testing TLS

If you wish to test TLS, you will need certificates. To create self-signed certificates, follow the directions below:

> Note: The following contains instructions for running only `tuxtape-server` and `tuxtape-dashboard` with TLS. To run `tuxtape-kernel-builder` with TLS, follow the same instructions, but keep in mind that you will need to generate a new CA with a different domain (like `tuxtape-kernel-builder.com`) as that is also a server, and you will need to create another entry for that domain in `/etc/hosts`.

1. Create an encrypted certificate authority

```
openssl genrsa -aes256 -out ca-key.pem 4096
```

2. Decrypt the certificate authority

```
openssl req -new -x509 -sha256 -days 365 -key ca-key.pem -out ca.pem
```

3. Extract the public certificate from the cert key

```
openssl genrsa -out cert-key.pem 4096
```

4. Create a certificate signing request

```
openssl req -new -sha256 -subj "/CN=tuxtapecn" -key cert-key.pem -out cert.csr
```

5. Create an extfile

```
echo "subjectAltName=DNS:tuxtape-server.com,IP:127.0.0.1" >> extfile.cnf
```

6. Create a complete certificate authority

```
openssl x509 -req -sha256 -days 365 -in cert.csr -CA ca.pem -CAkey ca-key.pem -out cert.pem -extfile extfile.cnf -CAcreateserial
```

7. Create a full chain

```
cat cert.pem > fullchain.pem
cat ca.pem >> fullchain.pem
```

8. Create a local domain name for the server in `/etc/hosts`.

```
sudo sh -c "echo '127.0.0.1 tuxtape-server.com' >> /etc/hosts"
```

9. Modify the `tuxtape-dashboard` config file at `.config/tuxtape-dashboard-config.toml` (this will eventually be moved to a config directory that doesn't reside in the source code) to enable TLS by setting the following values:

```
[database]
server_url = "tuxtape-server.com:50051"
use_tls = true
tls_cert_path = "ca.pem"
```


10. Run the server and client with the following arguments.

```
cargo run --bin tuxtape-server -- -t --tls-cert-path fullchain.pem --tls-key-path cert-key.pem --tls-ca-path ca.pem

cargo run --bin tuxtape-dashboard
```
