# Self-hosted CI runners

Some WrenDNS CI jobs run on self-hosted runners: machines the project controls, instead of GitHub-hosted ones. Today they run the `clippy` job and the amd64 `test` job, with more CPU and memory and a warm build cache; the `migration` job, the first that binds fixed ports, and the `ui`, `oidc` and `native` jobs of `main.yml` are routed to them too and are being measured there. The `native` job is the old native job without its last two steps (Helm scaled mode on kind), which are the job `native-helm` and stay on GitHub-hosted runners. Since 2026-11-21 every runner is isolated: each one runs in its own container and is reset after every job (ADR-1076). Moving the other heavy jobs (the native build, the cluster and high-availability tests, the image build legs) is planned, one job type at a time, each measured before the next moves. This page describes what they are for, the rules that decide which jobs may use them, and how a host is set up. The design is decision ADR-1076 in `spec/11-decisions.md`, and the task is T39.9 in `spec/10-roadmap-and-tasks.md`.

The repository holds this page, the directory `deploy/ci-runners/` (its README and a read-only inspection script), and the workflow expressions described below. The host-side scripts and the base image recipe are kept by the maintainers on the build host, not in this repository.

## What they are for

- Running the `clippy` and `test` jobs of `main.yml` and `pr.yml`, the `migration` job of `main.yml`, the `ui` job of `main.yml`, and the `oidc` job of `main.yml`, and the `native` job of `main.yml` (the Compose bundle, the installer and its systemd unit, the cluster, watchdog and rolling-upgrade scripts, live DNSSEC and the cluster configuration from Git; routed there and being measured), when the runner variables route them there (the state today). `migration` is the first job that binds fixed ports to move, which is safe because each runner has its own network namespace and its own Docker daemon.
- Staying on GitHub-hosted runners: `native-helm` (Helm scaled mode on kind). kind starts a privileged node container with its own systemd and cgroup delegation, which an unprivileged container with nested Docker does not reliably provide, and nothing in the repository shows that it works there. The job builds its own binary, so it needs nothing from `native`.
- The `native` job has no `gh` on these runners: its rolling-upgrade step fetches the edge build with `curl` and the job token (read-only `contents`, the same token a hosted run has). Its systemd step installs a real unit and has not been run in a container yet; whether the unit's sandbox options start there is what the first runs show.
- Planned, not done yet: the other jobs that bind fixed ports (the high-availability tests) and the image build legs (ADR-1075), moved one at a time after each is measured on the isolated runners.
- Keeping compiled artefacts and package downloads in shared caches, so a job does not start cold.

They are not used for releases. Release builds and signing stay on GitHub-hosted runners (ADR-1076).

## Trust model

A self-hosted runner executes whatever code a job checks out, and a job can read the runner's own identity key. The boundary is therefore who may trigger a job, not what the job does.

- **Fork pull requests and Dependabot pull requests never run on these runners.** They build third-party code. The workflows send them to GitHub-hosted runners.
- **Trusted events and same-repository pull requests may run on them.** A push to `main`, a manual dispatch and other non-pull-request events are trusted, and so is a pull request opened from a branch of this repository.
- **The workflows enforce this, not the runners.** The `runs-on` expressions in `.github/workflows/main.yml` and `.github/workflows/pr.yml` name the rule. A pull request uses `vars.WRENDNS_PR_RUNNER` only when `github.event.pull_request.head.repo.full_name == github.repository` and the author is not `dependabot[bot]`. A pull request from a fork fails that comparison, and so does one whose fork was deleted (it has no head repository), so both run on `ubuntu-latest`. Every other event uses `vars.WRENDNS_RUNNER`. If the variable is unset, or the pull request is from a fork or Dependabot, the job falls back to `ubuntu-latest`.
- **Never route a `pull_request_target` or `workflow_run` job that checks out pull request code** to a self-hosted runner.

If you add a self-hosted job, keep the same guard in its `runs-on`.

## Design

Each runner is one LXD system container. The container runs its own Docker daemon, so the nested containers in a job are isolated from the host and from the other containers.

- **One job per container life.** A container starts from a clean snapshot, runs one job with `run.sh --once`, and powers off. A host-side supervisor then restores the snapshot and starts the container again. The reset is a copy-on-write restore on a btrfs pool, so it takes seconds whatever the job wrote.
- **Reset after every job.** A host-side sweep, run every ten minutes, stops a container that has no job in progress and is stuck, lost its job, or never began listening. It never stops a container that has a job running. The supervisor holds a restart while the host is short of disk or memory, so a restart never interrupts a job.
- **Identity is copied, not registered.** The runner was registered once, at provisioning, from a one-time token that was never stored. Its identity files (the runner settings and the RSA key that signs its token requests) are copied into the container's snapshot. No registration token and no GitHub token is stored on the host or in the container. Re-registering is not needed, and no workflow ever calls the registration API.
- **Be clear about the key.** The RSA key is a long-lived runner credential. It exists in the snapshot and in the storage pool file, readable by root and by members of the LXD group. Only trusted jobs reach the runner, for that reason.
- **Shared build caches** are mounted into every container with only the runner user's id mapped onto the host, so the runner user owns the files on both sides and root inside a container has no power over the host's copy. There are two caches: a Rust package cache (`CARGO_HOME`) and a compiler cache (sccache). Locks inside the package cache serialise concurrent writers. Each container's own state directory, for markers and logs, is separate.
- **Registry mirrors run on the host.** Mirrors for Docker Hub, ghcr.io and quay.io run on the host and are reached from each container at the bridge address, on three ports: `WRENDNS_HUB`, `WRENDNS_GHCR` and `WRENDNS_QUAY`. The bridge address in the examples here is `10.90.0.1`, an example value from the LXD default private range. The compose files and end-to-end scripts read these variables, with the public registries as defaults. The nested Docker daemon and BuildKit use the same mirrors through their configuration.
- **CPU and memory caps.** Each container has a limit of 12 CPUs and 10 GiB of memory, enforced hard, with no swap. Its CPU weight is kept low, so the containers together do not outweigh other workloads on the same host, and when the host runs short of memory a container's job is ended before anything else on the host.
- **No AVX2 on the build host.** The build host's CPU lacks AVX2. A job that needs the x86-64-v3 instruction level stays on a GitHub-hosted runner. Run `deploy/ci-runners/inspect.sh` on a host to see which instruction flags it has.
- **arm emulation comes from the host.** The emulators for arm64 and arm/v7 are registered once, on the host, and the containers use them. A container cannot register them itself, so a job routed to these runners must skip `docker/setup-qemu-action` (guard the step with `runner.environment == 'github-hosted'`).

## Adding a runner

A new runner is one more container made from the base image, with its own identity copied from a registered host runner directory.

1. Check the host with `deploy/ci-runners/inspect.sh` (see `deploy/ci-runners/README.md`).
2. Build the base image if it is not built yet (below).
3. Create the container from the base, copy in the runner's identity files, and take the snapshot `clean`. The creation script refuses to run while the host runner is still active, so one identity never runs in two places.
4. Start its supervisor. The supervisor starts the container, which listens for one job, and then resets it for the next.
5. Stop the host runner unit and leave its directory untouched. The unit is disabled, not removed, so rollback stays possible.

## Rebuilding the base image

The base is a sealed, stopped container built from Ubuntu 26.04. It holds the Rust toolchain, the compilers and linkers, Docker with the overlay2 driver, and the runner software at the same release as the host runners. Rebuild it when:

- GitHub publishes a newer runner release. Every reset restores the old one, so every job would download the update first. Rebuild with the new tarball and its published checksum, then recreate each runner's container from the new base.
- The toolchain pin changes. The image records the runner, Rust and base versions in `/etc/wrendns-image`.

Recreating a container keeps its identity, so GitHub still sees the same runner.

## Rolling back to host runners

Each runner can go back to its host unit at any stage. The rollback procedure does this:

1. It disables the runner's supervisor. A running job is allowed to finish. The rollback waits, and it never interrupts a job.
2. It stops the container's runner cleanly, so the runner deletes its GitHub session, and powers the container off. The container and its snapshot are kept, stopped, for a later retry.
3. It enables the host unit. The host runner directory was never modified, so the identity is the same as before the move.

To roll back all runners, run the rollback for each. To remove everything the setup created, disable the sweep timer, stop the mirror proxies and the firewall rules, delete the containers, images and storage pool, and restore the kernel limits. Every command is safe to repeat.

## Acceptance checklist

A host is ready for the self-hosted jobs when the maintainer has ticked each of these nine checks. Each check states what it proves.

- [ ] **V1, Docker inside.** Docker uses the overlay2 driver with cgroup v2. `docker compose` runs a service with a healthcheck on a service network. A buildx `docker-container` builder builds an image.
- [ ] **V2, isolation.** Two containers bind the same fixed host ports at the same time. Nothing appears on the host, and each Docker daemon sees only its own containers.
- [ ] **V3, mirrors.** The three mirrors answer on the bridge address, from a container and from a nested container. Docker Hub, ghcr.io and quay.io all serve.
- [ ] **V4, shared caches.** A write in one container is visible in another and on the host, with the runner user as owner, and root inside a container cannot create a root-owned or setuid file through the mount. Concurrent package-cache builds in two containers both succeed. The compiler cache uses the shared directory.
- [ ] **V5, arm limits.** arm64 and arm/v7 binaries run in nested Docker through the host's emulators. A buildx build produces both architectures. The container cannot change the emulator registration.
- [ ] **V6, a real job passes.** The `clippy` and `test (ubuntu-latest)` jobs of `main.yml` run on the host's container and succeed.
- [ ] **V7, a byte-clean reset.** After a run that leaves deliberate residue, the restored root filesystem matches the snapshot `clean` by checksum. Nothing of the run is visible after the start.
- [ ] **V8, identity.** The same runner id is used after at least three resets and after a forced stop. GitHub shows exactly one record, online. The identity files' checksums are unchanged. No registration token or GitHub token is stored on the host.
- [ ] **V9, no job lost.** A job queued while a runner is busy or resetting is picked up after the reset. The gap is measured. Nothing stays queued, and no job ends with a lost-communication error.

## Related

- `deploy/ci-runners/README.md`: what the directory holds, and how to run the inspection script.
- `docs/releasing.md`: the release workflow, which stays on GitHub-hosted runners.
- `CONTRIBUTING.md`, "Continuous integration": how pull requests reach the fast and full tiers.
