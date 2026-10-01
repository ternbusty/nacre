# nacre

A Linux OCI container runtime written in Perl.

Implements the [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec) — the same interface as runc, crun, and youki.

## Requirements

- Linux (kernel 5.x+)
- Perl 5.20+
- libseccomp (libseccomp-dev)
- FFI::Platypus (cpan)

## Usage

```bash
# Generate a default OCI spec
nacre spec

# Create and start a container
nacre create --bundle /path/to/bundle mycontainer
nacre start mycontainer

# Or run directly
nacre run --bundle /path/to/bundle mycontainer
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

## OCI Commands

create, start, state, kill, delete, list, run, spec, features,
pause, resume, exec, update, events, ps
