# SpeeXDP
![Version](https://img.shields.io/badge/version-0.1.0-blue.svg?cacheSeconds=2592000)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#)

> A linux XDP based firewall/loadbalancer with a gui and api

- [SpeeXDP](#speexdp)
  - [Features](#features)
    - [Firewall](#firewall)
    - [UI](#ui)
  - [What SpeeXDP is *NOT*](#what-speexdp-is-not)
  - [Install](#install)
    - [1. Dependencies](#1-dependencies)
    - [2. Download](#2-download)
    - [3. Build](#3-build)
  - [Usage](#usage)
    - [1. Run](#1-run)
    - [2. UI](#2-ui)
    - [3. API](#3-api)
  - [Development](#development)
    - [1. Dependencies](#1-dependencies-1)
    - [2. Prerequisites](#2-prerequisites)
    - [3. Compile \& Run](#3-compile--run)
    - [4. Debugging](#4-debugging)
        - [Additional Information](#additional-information)
    - [Run tests](#run-tests)
  - [Related Projects](#related-projects)

## Features

### Firewall
|Feature|Current Support|Future Support|
|---|---|-|
|Address Types|IPv4, IPv6|MAC|
|Address Filtering|Source|Destination|
|Protocols|TCP, UDP|ICMP, ARP|
|Ports|Single, Range||
|Actions|Allow, Block|Redirect|
|Protection||DDOS detection/mitigation|
|Performance||Quality of Service,<br>Rate Limiting|
### UI
|Feature|Current Support|Future Support|
|---|---|-|
|Debugging||Packet Path Simulation,<br> Packet Flow Visualization|
|Authentication||PAM, Basic|

## What SpeeXDP is *NOT*
* A web application firewall

## Install

### 1. Dependencies
Minimum Supported Kernel Version: SpeeXDP requires at least linux kernel version `6.0.8` to run. Run the following to check which version you have.
```sh
$ uname --kernel-name --kernel-release
Linux 6.0.8
```

Optional high performance network driver support. See if your network driver is supported (here)[https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp].

### 2. Download
Download the git repository and build SpeedXDP.

```sh
$ git clone --depth=1 https://github.com/FallingSnow/speexdp.git
```

### 3. Build
```sh
$ cd speexdp
$ cargo build
```

## Usage

### 1. Run
```
# cargo xtask run
```

### 2. UI
You can visit the web UI at [`http://localhost:6565`](http://localhost:6565).

### 3. API
Explorer API endpoints using the built in documentation viewer at [`http://localhost:6565/api`](http://localhost:6565/api).

## Development

### 1. Dependencies
* bpftool `6.0`
* libclang `14.0.6`

**Arch Linux**
```
# pacman -S bpf
```

### 2. Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

Ensure you have the at least the `MSRV`. It should be at least `1.62.0`.
```
$ rustc --version
rustc 1.62.0
```

### 3. Compile & Run
```sh
# $ cargo install bpf-linker
$ cargo xtask codegen           # Build bpf bindings
$ cargo xtask build-ebpf        # Build eBPF
$ cargo build                   # Build Userspace
$ cargo xtask run               # Run
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

### 4. Debugging
Running with debug output.
```sh
$ RUST_LOG=debug cargo xtask run
```

##### Additional Information
* Seeing what you can get out of bpftool's header generation.
```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

* Documentation on different bpf map types: https://docs.kernel.org/next/bpf/maps.html

* XDP command list:

|XDP command|Action/Reason|
|-----------|------|
|XDP_PASS|Allow|
|XDP_DROP|Deny|
|XDP_ABORTED|Error|
|XDP_REDIRECT|Another Interface|
|XDP_TX|Another Host|

> TX sends the packet out, REDIRECT redirects to the receive queue of another interface <br>
> If you want to redirect to another port on the same NIC, you mutate the packet and return pass <br>
> Socketmaps are for redirecting to existing sockets <br>
> https://discord.com/channels/855676609003651072/855676609003651075/1049099838781935758

### Run tests

```sh
$ cargo test
```

## Related Projects
* https://github.com/gamemann/XDP-Firewall