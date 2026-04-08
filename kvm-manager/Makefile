# Makefile for KVM Manager

# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: help build test lint go-build go-run docker-build docker-push docker-list hadolint

#### Variables ####

TOOL_VERSION_CHECK ?= 1

GOLINT        := true
GOJUNITREPORT := true
MOCKERY       := true

PROJECT_NAME  := kvm-manager
BINARY_NAME   := $(PROJECT_NAME)

VERSION       := $(shell cat VERSION)
DOCKER_IMG_NAME  := $(PROJECT_NAME)
DOCKER_VERSION   ?= $(shell git branch --show-current | sed 's/\//_/g')
GIT_COMMIT       ?= $(shell git rev-parse HEAD)

TEST_TARGET  ?= .
TEST_PKG     ?= $(shell go list ./... | grep -v "cmd" | tr '\n' ,)
TEST_COVER   := atomic ./...

include ../common.mk

lint: common-lint ## Run all lint tools

test: go-test ## Run all unit tests

$(OUT_DIR)/$(BINARY_NAME): $(SRC) $(DEPS)
	CGO_ENABLED=0 $(GOCMD) build $(GOEXTRAFLAGS) -o $(OUT_DIR)/$(BINARY_NAME) cmd/$(BINARY_NAME).go

go-run: $(OUT_DIR)
	$(GOCMD) run $(GOEXTRAFLAGS) ./cmd/$(BINARY_NAME).go
