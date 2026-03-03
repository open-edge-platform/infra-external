# Makefile for AMT Manager

# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: help build test lint generate-proto generate

#### Variables ####

# Optionally include tool version checks, not used in Docker builds
TOOL_VERSION_CHECK ?= 1

# Tools versions
GOLINT             := true
GOJUNITREPORT      := true
MOCKERY            := true
OAPI_CODEGEN       := true
OASDIFF            := true

# Open DMT service versions
# Always use the bundle release versions to ensure compatibility with the swagger specs and generated clients
# Note: These versions should be kept in sync with the versions used in the DMT repo for the swagger specs to avoid breaking changes in the generated clients
# Refer to bundle releases: https://device-management-toolkit.github.io/docs/2.32/release-notes/

OPEN_DMT_MPS_SERVICE_VERSION     := v2.26.0
OPEN_DMT_RPS_SERVICE_VERSION     := v2.31.3

# GitHub raw content base URL
GITHUB_RAW_BASE := https://raw.githubusercontent.com/device-management-toolkit

# Swagger file URLs - using src/ path as per DMT repo structure
OPEN_DMT_MPS_CLIENT_SWAGGER_FILE := $(GITHUB_RAW_BASE)/mps/$(OPEN_DMT_MPS_SERVICE_VERSION)/swagger.yaml
OPEN_DMT_RPS_CLIENT_SWAGGER_FILE := $(GITHUB_RAW_BASE)/rps/$(OPEN_DMT_RPS_SERVICE_VERSION)/swagger.yaml

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
TEST_USE_DB      := true

# OpenAPI breaking check variables
TEMP_BASE_OPENAPI_DIR := /tmp/dm-manager-main
OPENAPI_PATH          := pkg/api/**/*.json


# Include shared makefile
include ../common.mk

# Policy related
REGODIR           := $(shell pwd)/rego/
BUNDLE            := "$(shell pwd)/$(OUT_DIR)/policy_bundle.tar.gz"

lint: oasdiff-breaking common-lint ## Run all lint tools

test: go-test ## Run all unit tests

#### Sub-targets ####

$(OUT_DIR)/$(BINARY_NAME): $(SRC) $(DEPS) ## Build if sources or dependencies changed
	CGO_ENABLED=0 $(GOCMD) build $(GOEXTRAFLAGS) -o $(OUT_DIR)/$(BINARY_NAME) cmd/$(BINARY_NAME).go

go-run: $(OUT_DIR) ## Run the resource manager
	$(GOCMD) run $(GOEXTRAFLAGS) ./cmd/$(BINARY_NAME).go

generate: ## Generate API clients from swagger specs
	$(info >>> MPS swagger URL: $(OPEN_DMT_MPS_CLIENT_SWAGGER_FILE))
	$(info >>> RPS swagger URL: $(OPEN_DMT_RPS_CLIENT_SWAGGER_FILE))
	@mkdir -p pkg/api/mps pkg/api/rps
	wget -q -O pkg/api/mps/swagger.yaml "$(OPEN_DMT_MPS_CLIENT_SWAGGER_FILE)"
	wget -q -O pkg/api/rps/swagger.yaml "$(OPEN_DMT_RPS_CLIENT_SWAGGER_FILE)"
	@rm -f pkg/api/mps/client.gen.go pkg/api/rps/client.gen.go
	@rm -f pkg/api/mps/interface.gen.go pkg/api/rps/interface.gen.go
	oapi-codegen --config pkg/api/mps/.oapi-codegen.yaml pkg/api/mps/swagger.yaml
	oapi-codegen --config pkg/api/rps/.oapi-codegen.yaml pkg/api/rps/swagger.yaml
	GOPROXY=https://proxy.golang.org,direct GOSUMDB=sum.golang.org go mod tidy
	@echo ">>> Removing stale mocks before regeneration..."
	@rm -f pkg/api/mps/mocks.go
	@rm -f pkg/api/rps/mocks.go
	@rm -rf pkg/api/mps/mocks/
	@rm -rf pkg/api/rps/mocks/
	mockery

oasdiff-breaking: common-oasdiff-breaking ## Check for breaking changes in openapi using oasdiff

generate-proto:
	protoc --proto_path=pkg/api/dm-manager \
		--go_out=paths=source_relative:pkg/api/dm-manager \
		--go-grpc_out=paths=source_relative:pkg/api/dm-manager \
		--validate_out=lang=go,paths=source_relative:pkg/api/dm-manager \
		pkg/api/dm-manager/dm-manager.proto
