# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.24.1-bookworm@sha256:fa1a01d362a7b9df68b021d59a124d28cae6d99ebd1a876e3557c4dd092f1b1d as build

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

ENV GO111MODULE=on
ARG MAKE_TARGET=go-build

# Arguments used to stamp the binary
ARG REPO_URL
ARG VERSION
ARG REVISION
ARG BUILD_DATE

COPY common.mk version.mk /go/src/github.com/open-edge-platform/infra-external/
COPY Makefile common.mk  version.mk go.mod go.sum /go/src/github.com/open-edge-platform/infra-external/loca-metadata/
COPY cmd/ /go/src/github.com/open-edge-platform/infra-external/loca-metadata/cmd/
COPY pkg/ /go/src/github.com/open-edge-platform/infra-external/loca-metadata/pkg/
COPY internal/ /go/src/github.com/open-edge-platform/infra-external/loca-metadata/internal/
COPY vendor/ /go/src/github.com/open-edge-platform/infra-external/loca-metadata/vendor/

WORKDIR /go/src/github.com/open-edge-platform/infra-external/loca-metadata

RUN CGO_ENABLED=0 \
  LABEL_REPO_URL=${REPO_URL} \
  LABEL_VERSION=${VERSION} \
  LABEL_REVISION=${REVISION} \
  LABEL_BUILD_DATE=${BUILD_DATE} \
  make ${MAKE_TARGET}

# From: https://github.com/GoogleContainerTools/distroless
FROM gcr.io/distroless/static-debian12:nonroot@sha256:627d6c5a23ad24e6bdff827f16c7b60e0289029b0c79e9f7ccd54ae3279fb45f

# Run as non-privileged user
USER nobody

ARG REPO_URL
ARG VERSION
ARG REVISION
ARG BUILD_DATE

LABEL org.opencontainers.image.version=${VERSION} \
      org.opencontainers.image.source=${REPO_URL} \
      org.opencontainers.image.revision=${REVISION} \
      org.opencontainers.image.created=${BUILD_DATE}

COPY --from=build --chown=nobody:nobody /go/src/github.com/open-edge-platform/infra-external/loca-metadata/out/locametamgr /usr/local/bin/locametamgr

ENTRYPOINT ["locametamgr"]
