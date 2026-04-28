# KVM Manager

<!-- SPDX-FileCopyrightText: (C) 2025 Intel Corporation -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Get Started](#get-started)
- [Contribute](#contribute)

## Overview

KVM Manager is a component of the Edge Infrastructure Manager that provides KVM-over-IP session
management for Intel AMT/vPro enabled servers via the Management Presence Service (MPS).
It enables remote KVM console access for devices, allowing users to view and interact with a
device's graphical display remotely — including pre-boot access to BIOS settings and boot order
configuration. Both admin and non-admin users can access remote KVM sessions, with support for
Intel AMT Client Control Mode (CCM) and Admin Control Mode (ACM).

## Features

- KVM session lifecycle management (start, stop, consent handling)
- Integration with Intel AMT/vPro via Management Presence Service (MPS)
- User consent code display for KVM access authorization
- Protection against disruptive power operations during active KVM sessions

## Get Started

Enter into the `kvm-manager` folder and run `make build` to build the binary.

### Dependencies

Firstly, please verify that all dependencies have been installed.

```bash
# Return errors if any dependency is missing
make dependency-check
```

This code requires the following tools to be installed on your development machine:

- [Go\* programming language](https://go.dev) - check [$GOVERSION_REQ](../version.mk)
- [golangci-lint](https://github.com/golangci/golangci-lint) - check [$GOLINTVERSION_REQ](../version.mk)
- [go-junit-report](https://github.com/jstemmer/go-junit-report) - check [$GOJUNITREPORTVERSION_REQ](../version.mk)
- [gocover-cobertura](github.com/boumenot/gocover-cobertura) - check [$GOCOBERTURAVERSION_REQ](../version.mk)

You can install Go dependencies by running `make go-dependency`.

### Build the Binary

Build the project as follows:

```bash
# Build go binary
make build
```

The binary is installed in the [$OUT_DIR](../common.mk) folder.

### Usage

Run the binary with the required flags to connect to the inventory and MPS services:

```bash
./out/kvm-manager \
  --inventory-address <inventory-host:port> \
  --mps-address <mps-host> \
  --mps-port <mps-port>
```

## Contribute

To learn how to contribute to the project, see the [contributor's guide][contributors-guide-url]. The project will
accept contributions through Pull-Requests (PRs). PRs must be built successfully by the CI pipeline, pass linters
verifications and the unit tests.

There are several convenience make targets to support developer activities, you can use `help` to see a list of
makefile targets. The following is a list of makefile targets that support developer activities:

- `lint` to run a list of linting targets
- `test` to run the KVM Manager unit tests
- `go-tidy` to update the Go dependencies and regenerate the `go.sum` file
- `build` to build the project and generate executable files
- `docker-build` to build the KVM Manager Docker container

To learn more about internals and software architecture, see
[Edge Infrastructure Manager developer documentation][inframanager-dev-guide-url].

[inframanager-dev-guide-url]: https://docs.openedgeplatform.intel.com/edge-manage-docs/main/developer_guide/infra_manager/index.html
[contributors-guide-url]: https://docs.openedgeplatform.intel.com/edge-manage-docs/main/developer_guide/contributor_guide/index.html
