# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: lint test clean docker-build-mps docker-build-rps help

all: lint test docker-build-mps docker-build-rps

# Variables
PROJECT_NAME_MPS := dmt-mps
PROJECT_NAME_RPS := dmt-rps
VERSION := $(shell cat VERSION)
DOCKER_BUILD_ARGS = \
	--build-arg http_proxy="$(http_proxy)" --build-arg HTTP_PROXY="$(HTTP_PROXY)" \
	--build-arg https_proxy="$(https_proxy)" --build-arg HTTPS_PROXY="$(HTTPS_PROXY)" \
	--build-arg no_proxy="$(no_proxy)" --build-arg NO_PROXY="$(NO_PROXY)" \
	--build-arg REPO_URL="$(LABEL_REPO_URL)" \
	--build-arg VERSION="$(LABEL_VERSION)" \
	--build-arg REVISION="$(LABEL_REVISION)" \
	--build-arg BUILD_DATE="$(LABEL_BUILD_DATE)"

# Build MPS image
docker-build-mps:
	docker build . -f build/Dockerfile.mps \
	-t $(PROJECT_NAME_MPS):$(VERSION) $(DOCKER_BUILD_ARGS)

# Build RPS image
docker-build-rps:
	docker build . -f build/Dockerfile.rps \
	-t $(PROJECT_NAME_RPS):$(VERSION) $(DOCKER_BUILD_ARGS)

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
	@echo "  docker-build-rps   Build the dmt-rps image"
	@echo "  lint               Run linters (stub)"
	@echo "  test               Run tests (stub)"

dependency-check:
	@echo "Dependency check: no dependencies to verify in this project."

license:
	@echo "License check: no license check implemented."
