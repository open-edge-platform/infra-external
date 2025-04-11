# Edge Infrastructure LOC-A Plugin

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Get Started](#get-started)
- [Contribute](#contribute)

## Overview

This sub-repository contains the Edge Infrastructure Manager Plugin implemented for Lenovo Open Cloud Automation
(LOC-A), enabling the integration of the Edge Infrastructure Manager with LOC-A.

## Features

- Securely onboard and manage Edge Nodes
- Provision Edge Nodes with a curated set of bare metal agents and software, enabling the deployment of additional
applications

## Get Started

Instructions on how to build and push the Edge Infrastructure Manager Plugin on your LOC-A instance.

### Request a LOC-A license

Visit the [LOC-A portal](https://www.lenovo.com/us/en/servers-storage/software/open-cloud-automation/) and navigate
to the `Contact Us` page to request a license.

### Configure LOC-A

Follow the Lenovo-provided documentation to set up LOC-A. After completing the configuration, verify its correctness
by accessing the LOC-A UI.

### Obtain the `plugin-tool` binary

Find the `plugin-tool` binary in the package provided by Lenovo under the obtained license and copy it in the current directory.

### Obtain the `decrypt.py` script

Locate the `decrypt.py` script in the Lenovo package and move it to the `edge-node/filter_plugins` directory.

### Dependencies

Create a virtual environment and install the required dependencies.

> **Note:** Ensure you have Python 3.x installed before proceeding.

```bash
# Create a virtual environment
make venv_locaplugin
```

### Activate the virtual environment

Activate the virtual environment created in the previous step to ensure that all dependencies are correctly isolated
and available for the plugin build process.

```bash
# Activate the virtual environment
source venv_locaplugin/bin/activate
```

### Configure credentials for LOC-A

Open the `configs.yml` file and enter the LOC-A URL and login credentials.

```yaml
# Example LOC-A credentials
locaUrl: https://loca.example.com
locaUser: admin
```

### Build and Publish the Edge Infrastructure Manager Plugin

Run the `create-loca-plugin.sh` script to build and publish the Edge Infrastructure Manager Plugin.

```bash
# Run the script
./create-loca-plugin.sh
```

> **Note:** Make sure to configure proxy on host and container tool of your choice, as build process runs inside
> the container that requires access to internet

See the [documentation][user-guide-url] if you want to learn more about using Edge Orchestrator.

## Contribute

To learn how to contribute to the project, see the [contributor's guide][contributors-guide-url]. The project will
accept contributions through Pull-Requests (PRs). PRs must be built successfully by the CI pipeline, pass linters
verifications and the unit tests.

There are several convenience make targets to support developer activities, you can use `help` to see a list of makefile
targets. The following is a list of makefile targets that support developer activities:

- `lint` to run a list of linting targets
- `ansiblelint` to lint ansible modules
- `mdlint` to lint markdown files
- `yamllint` to lint yaml files
- `reuse` to check the reuse compliance
- `shellcheck` to lint shell scripts
- `clean` to delete the virtual environment

To learn more about internals and software architecture, see
[Edge Infrastructure Manager developer documentation][inframanager-dev-guide-url].

[user-guide-url]: https://literate-adventure-7vjeyem.pages.github.io/edge_orchestrator/user_guide_main/content/user_guide/get_started_guide/gsg_content.html
[inframanager-dev-guide-url]: (https://literate-adventure-7vjeyem.pages.github.io/edge_orchestrator/user_guide_main/content/user_guide/get_started_guide/gsg_content.html)
[contributors-guide-url]: https://literate-adventure-7vjeyem.pages.github.io/edge_orchestrator/user_guide_main/content/user_guide/index.html
