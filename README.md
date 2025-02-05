# TuxTape

TuxTape is an ecosystem for generating, compiling, deploying, and installing Linux kernel livepatches.

Kernel livepatching is a service provided by many large companies (Canonical, Red Hat, Oracle, SuSE, TuxCare, etc), but as of today, no open source toolchain exists to allow individuals to self manage such a service. Additionally, most of these companies (with the exception of TuxCare) only provide livepatching services for their own custom kernel, e.g. Red Hat will only provide livepatches for the RHEL kernel.

The mission of TuxTape is not to invalidate these services. Reviewing patches, monitoring the success of patch application, and maintaining infrastructure to distribute patches are tasks that will make sense for many system administrators to outsource. 

One should consider TuxTape if they, whether for security reasons, cost reasons, or requirements to maintain custom kernels, have the need to maintain their own livepatching solution.

## Development Status

TuxTape is currently exiting the proof of concept phase and entering the minimum viable product (MVP) phase, which is why the `main` branch is currently free of code. The proof of concept code, which varies greatly in implementation from the MVP, is accessible in the `poc` branch.

At this point in time, planning for the MVP is still in progress so implementation specifics are not yet available.

## Pieces

The full livepatch solution will consist of the following pieces: 

1. Common Vulnerabilities and Exposures (CVE) Scanner: The kernel community is its own CVE Numbering Authority (CNA) and publishes all CVE information in a [public mailing list](https://lore.kernel.org/linux-cve-announce/) and in [a git tree](https://git.kernel.org/pub/scm/linux/security/vulns.git). The CVE scanner will monitor this list for vulnerabilities which affect files which are compiled into our kernel. Fortunately, each email lists links to the patches fixing the vulnerability. The scanner can be run as a cronjob.

1. CVE Prioritizer: Unfortunately, since the kernel community believes that every bug is a possible security bug, the mailing list is very active. A method of prioritizing CVEs is still being devised.

1. Applicability Gauge: For any CVE which is deemed high enough priority, we must also decide whether it is applicable. This step is separated from the prioritizer because a basic priority applies for the CVE across all kernels, while applicability is per kernel. Since TuxTape is built to support multiple kernel configurations and distributions besides just mainline, some CVEs will stem from source files which are built into some but not all kernels. The applicability gauge will determine, for each kernel, whether a CVE is applicable.

1. Patch Generator: Once a CVE has been identified as worthy of live-patching, the Patch Generator will fetch the fixing commits and automatically generate a loadable module for the fix. In case the generator is unable to do so, it will send a notice to the system administrators to manually attempt to generate a livepatch module. Patches which are auto-generated will need to be carefully vetted through some combination of CI, heuristics, AI review, and human review.

1. Kernel Log Parser: Analyzes kernel warnings to determine whether a livepatch module has misbehaved.

1. Patch Archive: There is a need to publish all livepatch modules, as well as per-kernel and per-version lists of applicable modules. We are considering signing these using the [The Update Framework (TUF)](https://theupdateframework.io/) approach – signing using short-lived keys so that clients can be sure not to be handed stale data. The final state of the Patch Archive is still in discussion.

1. Fleet Client: Every node in the fleet will run a lightweight client which tracks the kernel version and livepatch status of the node on which it runs. It will periodically fetch the latest information from the Patch Archive. See below for details about how we intend to handle cases like [a system being buggy after a livepatch update](https://web.archive.org/web/20240913235734/https://ubuntu.com/security/livepatch/docs/livepatch/reference/what_if_my_system_crashes).
