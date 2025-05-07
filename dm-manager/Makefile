# Makefile for AMT Manager

# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: help build test lint

#### Variables ####

# Optionally include tool version checks, not used in Docker builds
TOOL_VERSION_CHECK ?= 1

# Tools versions
GOLINT             := true
GOJUNITREPORT      := true
MOCKERY            := true
OAPI_CODEGEN       := true
OASDIFF            := true

# Project variables
PROJECT_NAME       := dm-manager
BINARY_NAME        := $(PROJECT_NAME)

DB_CONTAINER_NAME  := $(PROJECT_NAME)-db

# Versioning variables
VERSION            := $(shell cat VERSION)
VERSION_MAJOR      := $(shell cut -c 1 VERSION)
DOCKER_IMG_NAME    := $(PROJECT_NAME)
DOCKER_VERSION     ?= $(shell git branch --show-current | sed 's/\//_/g')
GIT_COMMIT         ?= $(shell git rev-parse HEAD)

# Test variables
# Set TEST_TARGET to '<testname1>' or '<testname1\|testname2>' to run specific tests or use regex '<testname.*>' - example:
#  TEST_TARGET='TestAuth.*' make test
TEST_TARGET      ?= .
# Default TEST_PKG, overwrite to select particular test pakages
TEST_PKG         ?= $(shell go list ./... | grep -v "pkg/api" | grep -v "cmd" | tr '\n' ,)
TEST_COVER       := atomic ./...
TEST_ARGS        := ""
TEST_USE_DB      := false

# OpenAPI breaking check variables
BASE_BRANCH           := main # temp TODO remove
TEMP_BASE_OPENAPI_DIR := /tmp/dm-manager-main
OPENAPI_PATH          := pkg/api/**/*.json

# Include shared makefile
include ../common.mk

lint: oasdiff-breaking common-lint  ## Run all lint tools

test: go-test ## Run all unit tests

#### Sub-targets ####

$(OUT_DIR)/$(BINARY_NAME): $(SRC) $(DEPS) ## Build if sources or dependencies changed
	CGO_ENABLED=0 $(GOCMD) build $(GOEXTRAFLAGS) -o $(OUT_DIR)/$(BINARY_NAME) cmd/$(BINARY_NAME).go

go-run: $(OUT_DIR) ## Run the resource manager
	$(GOCMD) run $(GOEXTRAFLAGS) ./cmd/$(BINARY_NAME).go

generate:
	oapi-codegen -generate client,types -o pkg/api/mps/client.gen.go -package mps pkg/api/mps/swagger.json
	oapi-codegen -generate client,types -o pkg/api/rps/client.gen.go -package rps pkg/api/rps/swagger.json
	mockery
