# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: lint test clean docker-build-mps help

all: lint test docker-build-mps

# Variables
PROJECT_NAME_MPS := dmt-mps
VERSION := $(shell cat VERSION)
DOCKER_BUILD_ARGS = \
	--build-arg http_proxy="$(http_proxy)" --build-arg HTTP_PROXY="$(HTTP_PROXY)" \
	--build-arg https_proxy="$(https_proxy)" --build-arg HTTPS_PROXY="$(HTTPS_PROXY)" \
	--build-arg no_proxy="$(no_proxy)" --build-arg NO_PROXY="$(NO_PROXY)" \
	--build-arg REPO_URL="$(LABEL_REPO_URL)" \
	--build-arg VERSION="$(LABEL_VERSION)" \
	--build-arg REVISION="$(LABEL_REVISION)" \
	--build-arg BUILD_DATE="$(LABEL_BUILD_DATE)"

include ../common.mk

# Build MPS image
docker-build-mps:
	cp ../common.mk ../version.mk .
	docker build . -f build/Dockerfile.mps \
	-t $(PROJECT_NAME_MPS):$(VERSION) $(DOCKER_BUILD_ARGS)
	@rm -rf common.mk version.mk

docker-build: docker-build-mps
	@echo "Built dmt-mps images."

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
	@echo "  docker-build-mps   Build the dmt-mps image"
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
