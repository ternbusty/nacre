# nacre

A Linux OCI container runtime written in Perl.

## Requirements

- Linux (kernel 5.x+)
- Perl 5.38+
- libseccomp (libseccomp-dev)

FFI::Platypus is optional. If installed, the seccomp filter is compiled via libseccomp's C API; otherwise nacre falls back to a pure-Perl BPF assembler.

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
