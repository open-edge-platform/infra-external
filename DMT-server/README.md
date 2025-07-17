# DMT-server

## Table of Contents
- [DMT-server](#dmt-server)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Features](#features)
  - [Get Started](#get-started)
  - [Contribute](#contribute)
  - [Structure](#structure)
  - [CI](#ci)
  - [Compliance](#compliance)

## Overview
DMT-server provides Docker build contexts for Intel Manageability Provisioning Server (MPS) and Remote Provisioning Server (RPS) images, pre-bundled with AWS and GCP root CA certificates. These images are intended for use in cloud environments where MPS and RPS must trust AWS and GCP endpoints.

## Features
- Dockerfiles for both dmt-mps and dmt-rps images
- Adds AmazonRootCA1 and GoogleRootCA to the system trust store

## Get Started
This repository only contains scripts to build the Docker images. You only need `docker` installed.

To build the images:

```bash
# Build the dmt-mps image
make docker-build-mps
# or manually
# docker build -f build/Dockerfile.mps-cloud-certs . -t dmt-mps:<VERSION>

# Build the dmt-rps image
make docker-build-rps
# or manually
# docker build -f build/Dockerfile.rps-cloud-certs . -t dmt-rps:<VERSION>
```

## Contribute
To learn how to contribute to the project, see the [contributor's guide][contributors-guide-url]. The project will accept contributions through Pull-Requests (PRs). PRs must be built successfully by the CI pipeline, pass linters verifications and the unit tests.

There are several convenience make targets to support developer activities, you can use `help` to see a list of makefile targets. The following is a list of makefile targets that support developer activities:

- `lint` to run a list of linting targets.
- `mdlint` to run linting of this file.
- `hadolint` to run linter on Dockerfile.
- `docker-build-mps` to build the dmt-mps container.
- `docker-build-rps` to build the dmt-rps container.

For the infrastructure manager development guide, visit the [infrastructure manager development guide][inframanager-dev-guide-url].
If you are contributing, please read the [contributors guide][contributors-guide-url].
For troubleshooting, see the [troubleshooting guide][troubleshooting-url].

[user-guide-onboard-edge-node]: https://docs.openedgeplatform.intel.com/edge-manage-docs/main/user_guide/set_up_edge_infra/index.html
[user-guide-url]: https://docs.openedgeplatform.intel.com/edge-manage-docs/main/user_guide/get_started_guide/index.html
[inframanager-dev-guide-url]: https://docs.openedgeplatform.intel.com/edge-manage-docs/main/developer_guide/infra_manager/index.html
[contributors-guide-url]: https://docs.openedgeplatform.intel.com/edge-manage-docs/main/developer_guide/contributor_guide/index.html
[troubleshooting-url]: https://docs.openedgeplatform.intel.com/edge-manage-docs/main/user_guide/troubleshooting/index.html
