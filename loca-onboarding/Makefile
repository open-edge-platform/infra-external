# Makefile for LOCA Onboarding Manager

# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: help build test lint

##### Variables #####

# Optionally include tool version checks, not used in Docker builds
TOOL_VERSION_CHECK ?= 1

# Required Go Dependencies
GOLINT             := true
GOJUNITREPORT      := true
GOCOBERTURA        := true
SWAGGER            := true
OASDIFF            := true

# Project variables
PROJECT_NAME       := locamgr
PROJECT_NICKNAME   := lo
BINARY_NAME        := $(PROJECT_NAME)

# Code Versions
VERSION            := $(shell cat VERSION)
VERSION_MAJOR      := $(shell cut -c 1 VERSION)
DOCKER_IMG_NAME    := $(PROJECT_NAME)
DOCKER_VERSION     ?= $(shell git branch --show-current | sed 's/\//_/g')
GIT_COMMIT         ?= $(shell git rev-parse HEAD)
GIT_TAG_PREFIX     := loca-onboarding/v

# Test variables
# Set TEST_TARGET to '<testname1>' or '<testname1\|testname2>' to run specific tests or use regex '<testname.*>' - example:
#  TEST_TARGET='TestAuth.*' make test
TEST_TARGET     ?= .
# Default TEST_PKG, overwrite to select particular test pakages
TEST_PKG        ?= $(shell go list ./... | grep -v "pkg/api" | grep -v "cmd" | grep -v "testing" | tr '\n' ,)
TEST_COVER      := atomic ./...
TEST_USE_DB     := true

PWD             := $(shell pwd)

# OpenAPI breaking check variables
BASE_BRANCH           := main # temp TODO remove
TEMP_BASE_OPENAPI_DIR := /tmp/loca-onboarding-main
OPENAPI_PATH          := pkg/api/loca/v3.3/loca-api-swagger.json

# Include shared makefile
include ../common.mk

lint: oasdiff-breaking generate common-lint ## Run all linters

test: go-test ## Run all tests

generate: swagger-gen

go-onboard-prerequisites: ## helper function to create Provider and OS resourcesfGOBIN
	$(GOCMD) run cmd/helper/prerequisite_onboarder.go

go-create-os: ## helper function to create OS resource for testing
	$(GOCMD) run cmd/simple_cli/simple_cli.go --onboardOSResource

go-create-site: ## helper function to create Site resource for testing
	$(GOCMD) run cmd/simple_cli/simple_cli.go --createSite

go-remove-sites: ## helper function to remove all Site resources
	$(GOCMD) run cmd/simple_cli/simple_cli.go --deleteSites

go-list-all: ## helper function to list all Hosts and Instances per Provider
	$(GOCMD) run cmd/simple_cli/simple_cli.go --listAllResources

go-list-sites: ## helper function to list all Sites per Provider
	$(GOCMD) run cmd/simple_cli/simple_cli.go --listSites

go-list-hosts: ## helper function to list all Hosts per Provider
	$(GOCMD) run cmd/simple_cli/simple_cli.go --listHosts

go-list-instances: ## helper function to list all Instances per Provider
	$(GOCMD) run cmd/simple_cli/simple_cli.go --listInstances

go-remove-hosts: ## helper function to remove Host for every Provider
	$(GOCMD) run cmd/simple_cli/simple_cli.go --removeHost

go-remove-instances: ## helper function to remove Instance for every Provider
	$(GOCMD) run cmd/simple_cli/simple_cli.go --removeInstance

go-list-loca-sites: ## helper function to list all Sites present at LOC-A
	$(GOCMD) run cmd/simple_cli/simple_loca_cli.go

$(OUT_DIR)/$(BINARY_NAME): $(SRC) $(DEPS) ## Build if sources or dependencies changed
	$(GOCMD) build -ldflags="-X 'main.RepoURL=$(LABEL_REPO_URL)' -X 'main.Version=$(LABEL_VERSION)' \
	-X 'main.Revision=$(LABEL_REVISION)' -X 'main.BuildDate=$(LABEL_BUILD_DATE)'" \
	-o $(OUT_DIR)/$(BINARY_NAME) cmd/$(BINARY_NAME).go

go-run: $(OUT_DIR) ## Run go run
	$(GOCMD) run -ldflags="-X 'main.RepoURL=$(LABEL_REPO_URL)' -X 'main.Version=$(LABEL_VERSION)' \
	-X 'main.Revision=$(LABEL_REVISION)' -X 'main.BuildDate=$(LABEL_BUILD_DATE)'" \
	./cmd/$(BINARY_NAME).go

swagger-gen: ## Generate client
	swagger generate client --skip-validation --default-scheme=https \
		--spec pkg/api/loca/v3.3/loca-api-swagger.json \
		--client-package=pkg/api/loca/v3.3/client \
		--model-package=pkg/api/loca/v3.3/model --with-flatten=minimal

oapi-docs: ## Generate docs
	docker run --rm -v $(PWD)/pkg/api/loca/v3.3/:/local \
		redocly/cli build-docs  /local/loca-api-swagger.json  --output=/local/loca-api-doc.html

oasdiff-breaking: common-oasdiff-breaking: ## Check for breaking changes in openapi using oasdiff
