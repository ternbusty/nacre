# nacre

A Linux OCI container runtime written in Perl.

## Requirements

- Linux (kernel 5.x+)
- Perl 5.38+
- Kernel headers (`linux-libc-dev` on Debian and Ubuntu): nacre reads the syscall numbers for seccomp filters from them

## Install

```bash
# latest install
curl -fsSL https://raw.githubusercontent.com/ternbusty/nacre/main/scripts/install_nacre.sh | sudo bash

# extra: select version mode
curl -fsSL https://raw.githubusercontent.com/ternbusty/nacre/main/scripts/install_nacre.sh | sudo bash -s -- --version v0.2.0
```

## How to Run

A test bundle is included in the repository. To create and start a container from it

```bash
sudo nacre run --bundle test-bundle test
```

To create a container whose name is `test` from a bundle located at `test-bundle`

```bash
sudo nacre create --bundle test-bundle test
```

To start the container

```bash
sudo nacre start test
```

To get the status of the container

```bash
sudo nacre state test
```

To list all containers

```bash
sudo nacre list
```

To pause the container

```bash
sudo nacre pause test
```

To resume the container

```bash
sudo nacre resume test
```

To update the container's resource limits

```bash
sudo nacre update --memory 134217728 --pids-limit 100 test
```

To get a snapshot of the container's resource usage

```bash
sudo nacre events --stats test
```

To list processes in the container

```bash
sudo nacre ps test
```

To execute a process in the container

```bash
sudo nacre exec test -- sh -c "echo hello"
```

To stop the container

```bash
sudo nacre kill test SIGKILL
```

To delete the container

```bash
sudo nacre delete test
```

## Rootless

nacre runs as an unprivileged user, like runc:

```bash
# A spec with a user namespace mapping your own IDs, no network namespace
# and no cgroup limits
nacre spec --rootless

nacre run --bundle /path/to/bundle mycontainer
```

- State goes under `$XDG_RUNTIME_DIR/nacre` unless `--root` is given.
- Mapping more than your own UID/GID needs `newuidmap`/`newgidmap` (the `uidmap` package) and ranges in `/etc/subuid` and `/etc/subgid`.
- Resource limits need a cgroup delegated to you (set `linux.cgroupsPath` to it). Without one, a container with no limits and no `cgroupsPath` runs without a cgroup.
- On Ubuntu 23.10+, unprivileged user namespaces need an AppArmor profile granting `userns` for `perl` (see `/etc/apparmor.d/runc` for the pattern).
