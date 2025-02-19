# TuxTape

TuxTape is an ecosystem for generating, compiling, deploying, and installing Linux kernel livepatches. It is a toolchain for simplifying the workflow of [kpatch](https://github.com/dynup/kpatch). 

Kernel livepatching is a service provided by many large companies (Canonical, Red Hat, Oracle, SuSE, TuxCare, etc), but as of today, no open source toolchain exists to allow individuals to self manage such a service. Additionally, most of these companies (with the exception of TuxCare) only provide livepatching services for their own custom kernel, e.g. Red Hat will only provide livepatches for the RHEL kernel.

The mission of TuxTape is not to invalidate these services. Reviewing patches, monitoring the success of patch application, and maintaining infrastructure to distribute patches are tasks that will make sense for many system administrators to outsource. 

One should consider TuxTape if they, whether for security reasons, cost reasons, or requirements to maintain custom kernels, have the need to maintain their own livepatching solution.

**TODO: REWRITE README FOR MVP**
