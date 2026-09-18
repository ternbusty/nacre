# nacre

A Linux OCI container runtime written in Perl.

Implements the [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec).

## Requirements

- Linux (kernel 5.x+)
- Perl 5.38+
- libseccomp (libseccomp-dev)

FFI::Platypus is optional. If installed, the seccomp filter compiler uses it for efficient BPF assembly; otherwise nacre falls back to a pure-Perl implementation.

## Getting Started

```bash
curl -L https://github.com/ternbusty/nacre/archive/refs/tags/v0.2.0.tar.gz | tar xz
cd nacre-0.2.0
```

## Usage

```bash
# Generate a default OCI spec
sudo ./nacre spec --bundle mycontainer

# Create and start a container
sudo ./nacre run --bundle mycontainer mycontainer

# Or step by step
sudo ./nacre create --bundle mycontainer mycontainer
sudo ./nacre start mycontainer
sudo ./nacre delete mycontainer
```

## OCI Commands

create, start, state, kill, delete, list, run, spec, features,
pause, resume, exec, update, events, ps
