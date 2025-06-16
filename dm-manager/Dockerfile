# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.24.4-bookworm@sha256:ee7ff13d239350cc9b962c1bf371a60f3c32ee00eaaf0d0f0489713a87e51a67 AS build

ARG REPO_URL
ARG VERSION
ARG REVISION
ARG BUILD_DATE

COPY common.mk version.mk /go/src/github.com/open-edge-platform/infra-external/
COPY Makefile go.mod go.sum *.go *.mk /go/src/github.com/open-edge-platform/infra-external/dm-manager/
COPY cmd/ /go/src/github.com/open-edge-platform/infra-external/dm-manager/cmd/
COPY vendor/ /go/src/github.com/open-edge-platform/infra-external/dm-manager/vendor/
COPY pkg/ /go/src/github.com/open-edge-platform/infra-external/dm-manager/pkg/
WORKDIR /go/src/github.com/open-edge-platform/infra-external/dm-manager/
RUN LABEL_REPO_URL=${REPO_URL} LABEL_VERSION=${VERSION} LABEL_REVISION=${REVISION} LABEL_BUILD_DATE=${BUILD_DATE} make go-build


FROM gcr.io/distroless/static-debian12:nonroot@sha256:627d6c5a23ad24e6bdff827f16c7b60e0289029b0c79e9f7ccd54ae3279fb45f

USER nobody

ARG REPO_URL
ARG VERSION
ARG REVISION
ARG BUILD_DATE

LABEL org.opencontainers.image.version=${VERSION} \
      org.opencontainers.image.source=${REPO_URL} \
      org.opencontainers.image.revision=${REVISION} \
      org.opencontainers.image.created=${BUILD_DATE}

COPY --from=build --chown=nobody:nobody /go/src/github.com/open-edge-platform/infra-external/dm-manager/out/dm-manager /usr/local/bin/dm-manager

ENTRYPOINT  ["dm-manager"]
