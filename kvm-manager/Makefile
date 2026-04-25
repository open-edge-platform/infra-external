# Makefile for KVM Manager

# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: help build test lint generate

#### Variables ####

# Optionally include tool version checks, not used in Docker builds
TOOL_VERSION_CHECK ?= 1

# Tools versions
GOLINT        := true
GOJUNITREPORT := true
MOCKERY       := true
OAPI_CODEGEN  := true
OASDIFF       := true

PROJECT_NAME  := kvm-manager
BINARY_NAME   := $(PROJECT_NAME)

# Versioning variables
VERSION          := $(shell cat VERSION)
VERSION_MAJOR    := $(shell cut -c 1 VERSION)
DOCKER_IMG_NAME  := $(PROJECT_NAME)
DOCKER_VERSION   ?= $(shell git branch --show-current | sed 's/\//_/g')
GIT_COMMIT       ?= $(shell git rev-parse HEAD)

# Test variables
# Set TEST_TARGET to run specific tests: TEST_TARGET='TestKVM.*' make test
TEST_TARGET  ?= .
TEST_PKG     ?= $(shell go list ./... | grep -v "pkg/api" | grep -v "cmd" | tr '\n' ,)
TEST_COVER   := atomic ./...

# OpenAPI breaking check variables
TEMP_BASE_OPENAPI_DIR := /tmp/kvm-manager-main
OPENAPI_PATH          := pkg/api/**/*.json

include ../common.mk

lint: oasdiff-breaking common-lint ## Run all lint tools

test: go-test ## Run all unit tests

#### Sub-targets ####

$(OUT_DIR)/$(BINARY_NAME): $(SRC) $(DEPS) ## Build if sources or dependencies changed
	CGO_ENABLED=0 $(GOCMD) build $(GOEXTRAFLAGS) -o $(OUT_DIR)/$(BINARY_NAME) cmd/$(BINARY_NAME).go

go-run: $(OUT_DIR) ## Run the KVM manager
	$(GOCMD) run $(GOEXTRAFLAGS) ./cmd/$(BINARY_NAME).go

generate: ## Regenerate MPS client and mocks
	oapi-codegen -generate client,types -o pkg/api/mps/client.gen.go -package mps pkg/api/mps/swagger.json
	mockery

oasdiff-breaking: common-oasdiff-breaking ## Check for breaking changes in openapi using oasdiff
