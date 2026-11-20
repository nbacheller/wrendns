# CI runners: deploy/ci-runners

This directory supports the self-hosted CI runners. The design, the trust model and the acceptance checklist are in `docs/ci-runners.md`. Read that page first.

## What is here

- `inspect.sh`: a read-only report on a build host. It shows the operating system and kernel, the CPU flags that x86-64-v3 needs, memory and committed memory, free disk and the filesystem type of `/`, the LXD state (version, storage pools, networks, instances and their snapshots), the firewall's FORWARD policy and the accept rules for the LXD bridge, the arm binfmt handlers, and, for a runner user and directory pattern you give it, the runner directories, their systemd units and state, and whether a job is running.
- `README.md`: this file.

The host-side scripts (the container supervisor, the sweep, the base image build and the move and rollback scripts) are not in this directory. They are kept by the maintainers on the build host.

## Running the inspection script

Run it with POSIX `sh`. It needs no arguments:

```sh
sh deploy/ci-runners/inspect.sh
```

To include the runner directories, give the runner user and a glob for the directory names under that user's home:

```sh
sh deploy/ci-runners/inspect.sh runner-user 'actions-runner-*'
```

Run on a host, it gives the most complete report with passwordless `sudo` available. Commands that need root run as `sudo -n`, so it never waits for a password. When that fails, the check is skipped with a `note:` line.

Run on a machine without LXD, the script still exits 0. It prints a `note:` for each tool that is missing, such as `lxc` or `iptables`. A missing tool is not an error.

## What it does not do

- It writes no file, and it changes no configuration.
- It installs nothing, and it starts, stops, restarts or enables no service.
- It never prints the contents of a credential file. For a runner directory it lists the file names, owners and modes only.

The script's header states this rule. Keep it true when you change the script: any new check must only read.

## Checking the script

```sh
sh -n deploy/ci-runners/inspect.sh
python scripts/check-spdx.py
python scripts/check-pipefail.py
```

`scripts/check-spdx.py` confirms the licence header, and `scripts/check-pipefail.py` confirms that the scripts under `deploy/` do not pipe `echo` or `printf` into `grep -q`.
