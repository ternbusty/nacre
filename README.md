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

## OCI Commands

create, start, state, kill, delete, list, run, spec, features,
pause, resume, exec, update, events, ps
