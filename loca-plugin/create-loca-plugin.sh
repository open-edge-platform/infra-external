#!/bin/bash
# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

set -e

rm -rf output/
./plugin-tool build -c configs.yml
./plugin-tool publish -c configs.yml  -b intel_plugin.tar
