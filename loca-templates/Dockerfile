# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.24.4-bookworm@sha256:ee7ff13d239350cc9b962c1bf371a60f3c32ee00eaaf0d0f0489713a87e51a67 AS build

ARG REPO_URL
ARG VERSION
ARG REVISION
ARG BUILD_DATE

COPY common.mk version.mk /go/src/github.com/open-edge-platform/infra-external/
COPY Makefile go.mod go.sum *.go *.mk /go/src/github.com/open-edge-platform/infra-external/loca-templates/
COPY cmd/ /go/src/github.com/open-edge-platform/infra-external/loca-templates/cmd/
COPY vendor/ /go/src/github.com/open-edge-platform/infra-external/loca-templates/vendor/
COPY pkg/ /go/src/github.com/open-edge-platform/infra-external/loca-templates/pkg/
WORKDIR /go/src/github.com/open-edge-platform/infra-external/loca-templates/
RUN LABEL_REPO_URL=${REPO_URL} LABEL_VERSION=${VERSION} LABEL_REVISION=${REVISION} LABEL_BUILD_DATE=${BUILD_DATE} make go-build


FROM gcr.io/distroless/static-debian12:nonroot@sha256:c0f429e16b13e583da7e5a6ec20dd656d325d88e6819cafe0adb0828976529dc

USER nobody

ARG REPO_URL
ARG VERSION
ARG REVISION
ARG BUILD_DATE

LABEL org.opencontainers.image.version=${VERSION} \
      org.opencontainers.image.source=${REPO_URL} \
      org.opencontainers.image.revision=${REVISION} \
      org.opencontainers.image.created=${BUILD_DATE}

COPY --from=build --chown=nobody:nobody /go/src/github.com/open-edge-platform/infra-external/loca-templates/out/loca-templates-manager /usr/local/bin/loca-templates-manager

ENTRYPOINT  ["loca-templates-manager"]
