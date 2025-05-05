# Edge Infrastructure Manager External

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/open-edge-platform/infra-external/badge)](https://scorecard.dev/viewer/?uri=github.com/open-edge-platform/infra-external)

## Overview

The repository includes the vendor extensions of the Edge Infrastructure Manager, part of the Edge Manageability Framework.

## Get Started

The repository comprises the following components and services:

- [**LOC-A Metadata Manager**](loca-metadata/): LOC-A resource manager that deals with the synchronization of locations
metadata between Edge Infrastructure Manager and Lenovo® Open Cloud Automation.
- [**LOC-A Onboarding Manager**](loca-onboarding/): LOC-A resource manager that synchronizes Host and Instances between
Edge Infrastructure Manager and Lenovo® Open Cloud Automation.
- [**LOC-A Templates Manager**](loca-metadata/): LOC-A resource manager that creates/removes Lenovo® Open Cloud
Automation instance templates based on the OS profiles deployed in Edge Infrastructure Manager.
- [**Edge Infrastructure LOC-A Plugin**](loca-plugin/): LOC-A plugin that provides the integration between
Edge Infrastructure Manager and Lenovo® Open Cloud Automation.
- [**Device Management Manager**](dm-manager): Device Management Manager that provides integration between
Intel AMT/vPro on the servers and Management Presence Service.
Read more about Edge Orchestrator in the [User Guide](https://docs.openedgeplatform.intel.com/edge-manage-docs/main/user_guide/index.html$0).

## Develop

To develop one of the Managers, please follow its guide in README.md located in its respective folder.

## Contribute

To learn how to contribute to the project, see the [Contributor's
Guide](https://docs.openedgeplatform.intel.com/edge-manage-docs/main/developer_guide/contributor_guide/index.html).

## Community and Support

To learn more about the project, its community, and governance, visit
the [Edge Orchestrator Community](https://docs.openedgeplatform.intel.com/edge-manage-docs/main/index.html).

For support, start with [Troubleshooting](https://docs.openedgeplatform.intel.com/edge-manage-docs/main/developer_guide/troubleshooting/index.html)

## License

Each component of the Edge Infrastructure core is licensed under [Apache 2.0][apache-license].

Last Updated Date: April 7, 2025

[apache-license]: https://www.apache.org/licenses/LICENSE-2.0
