# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.24.1-bookworm@sha256:fa1a01d362a7b9df68b021d59a124d28cae6d99ebd1a876e3557c4dd092f1b1d as build

ENV GO111MODULE=on
ARG MAKE_TARGET=go-build
# Arguments used to stamp the binary
ARG REPO_URL
ARG VERSION
ARG REVISION
ARG BUILD_DATE

COPY common.mk version.mk /go/src/github.com/open-edge-platform/infra-external/
COPY Makefile go.mod go.sum /go/src/github.com/open-edge-platform/infra-external/loca-onboarding/
COPY cmd/ /go/src/github.com/open-edge-platform/infra-external/loca-onboarding/cmd/
COPY internal/ /go/src/github.com/open-edge-platform/infra-external/loca-onboarding/internal/
COPY pkg/ /go/src/github.com/open-edge-platform/infra-external/loca-onboarding/pkg/
COPY vendor/ /go/src/github.com/open-edge-platform/infra-external/loca-onboarding/vendor/

WORKDIR /go/src/github.com/open-edge-platform/infra-external/loca-onboarding

RUN CGO_ENABLED=0 LABEL_REPO_URL=${REPO_URL} LABEL_VERSION=${VERSION} LABEL_REVISION=${REVISION} LABEL_BUILD_DATE=${BUILD_DATE} make ${MAKE_TARGET}

FROM gcr.io/distroless/static-debian12:nonroot@sha256:c0f429e16b13e583da7e5a6ec20dd656d325d88e6819cafe0adb0828976529dc
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

COPY --from=build --chown=nobody:nobody /go/src/github.com/open-edge-platform/infra-external/loca-onboarding/out/locamgr /usr/local/bin/locamgr

ENTRYPOINT ["locamgr"]
