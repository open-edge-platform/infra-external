# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: lint test clean docker-build-rps help

all: lint test docker-build-rps

# Variables
PROJECT_NAME_RPS := dmt-rps
BINARY_NAME      := dmt-rps

VERSION			:= $(shell cat VERSION)
VERSION_MAJOR   := $(shell cut -c 1 VERSION)
DOCKER_IMG_NAME := ${PROJECT_NAME_RPS}
DOCKER_VERSION  ?= $(shell git branch --show-current | sed 's/\//_/g')
IMG_VERSION     ?= $(VERSION)
GIT_COMMIT      ?= $(shell git rev-parse HEAD)
BRANCH_NAME     ?= $(shell git rev-parse --abbrev-ref HEAD | sed 's/\//_/g')

DOCKER_BUILD_ARGS = \
	--build-arg http_proxy="$(http_proxy)" --build-arg HTTP_PROXY="$(HTTP_PROXY)" \
	--build-arg https_proxy="$(https_proxy)" --build-arg HTTPS_PROXY="$(HTTPS_PROXY)" \
	--build-arg no_proxy="$(no_proxy)" --build-arg NO_PROXY="$(NO_PROXY)" \
	--build-arg REPO_URL="$(LABEL_REPO_URL)" \
	--build-arg VERSION="$(LABEL_VERSION)" \
	--build-arg REVISION="$(LABEL_REVISION)" \
	--build-arg BUILD_DATE="$(LABEL_BUILD_DATE)"

include ../common.mk

# Build RPS image
docker-build-rps:
	cp ../common.mk ../version.mk .
	docker build . -f build/Dockerfile.rps \
	-t $(DOCKER_IMG_NAME):$(VERSION) $(DOCKER_BUILD_ARGS)
	@rm -rf common.mk version.mk

docker-build: docker-build-rps
	@echo "Built dmt-rps images."

lint: license hadolint mdlint

test:
	@# Help: Runs test stage
	@echo "---MAKEFILE TEST---"
	echo $@
	@echo "---END MAKEFILE TEST---"

# Help
help:
	@echo "Available targets:"
	@echo "  all                Run lint, test, and build both images"
	@echo "  docker-build-rps   Build the dmt-rps image"
	@echo "  lint               Run linters (stub)"
	@echo "  test               Run tests (stub)"

dependency-check:
	@echo "Dependency check: no dependencies to verify in this project."

license:
	@echo "License check: no license check implemented."

hadolint:
	@echo "Hadolint: no Dockerfile linter implemented."

mdlint:
	@echo "Markdown lint: no markdown linter implemented."

go-dependency-check:
	@echo "No go dependency check implemented for this project."

go-build:
	@echo "No Go build in this folder."
