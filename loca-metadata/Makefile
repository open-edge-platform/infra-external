# Makefile for LOCA Metadata Manager

# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: help build test lint

#### Variables ####

# Optionally include tool version checks, not used in Docker builds
TOOL_VERSION_CHECK ?= 1

# Required Go Dependencies
GOLINT              := true
GOJUNITREPORT       := true
GOCOBERTURA         := true
MOCKGEN             := true

# Project variables
PROJECT_NAME        := locametamgr
PROJECT_NICKNAME    := lm
BINARY_NAME         := $(PROJECT_NAME)

# Versioning variables
VERSION             := $(shell cat VERSION)
VERSION_MAJOR       := $(shell cut -c 1 VERSION)
DOCKER_IMG_NAME     := $(PROJECT_NAME)
DOCKER_VERSION      ?= $(shell git branch --show-current | sed 's/\//_/g')
GIT_COMMIT          ?= $(shell git rev-parse HEAD)
GIT_TAG_PREFIX      := loca-metadata/v

# Test variables
# Set TEST_TARGET to '<testname1>' or '<testname1\|testname2>' to run specific tests or use regex '<testname.*>' - example:
#  TEST_TARGET='TestAuth.*' make test
TEST_TARGET         ?= .
# Default TEST_PKG, overwrite to select particular test pakages
TEST_PKG            ?= $(shell go list ./... | grep -v "pkg/api" | grep -v "cmd" | grep -v "testing" | tr '\n' ,)
TEST_COVER          := atomic ./...
TEST_ARGS           := -globalLogLevel=info
TEST_USE_DB         := true

# Include shared makefile
include ../common.mk

lint: common-lint ## Run all lint tools

test: go-test ## Run all unit tests

#### Sub-targets ####

$(OUT_DIR)/$(BINARY_NAME): $(SRC) $(DEPS) ## Build if sources or dependencies changed
	$(GOCMD) build $(GOEXTRAFLAGS) -o $(OUT_DIR)/$(BINARY_NAME) cmd/$(BINARY_NAME).go

go-run: build ## Run the resource manager
	$(GOCMD) run $(GOEXTRAFLAGS) ./cmd/$(BINARY_NAME).go

