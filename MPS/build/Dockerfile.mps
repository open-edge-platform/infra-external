# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# Dockerfile for Intel MPS with AWS and GCP root CA certificates
FROM docker.io/intel/oact-mps:v2.14.2

# Add AWS and GCP root CA certificates to a writable location
ADD https://www.amazontrust.com/repository/AmazonRootCA1.pem /usr/local/share/ca-certificates/AmazonRootCA1.crt
ADD https://pki.goog/roots.pem /usr/local/share/ca-certificates/GoogleRootCA.crt

# Switch to root to install packages and update CA certificates
USER root
RUN apk update && \
    apk add --no-cache ca-certificates && \
    apk upgrade c-ares icu-data-en icu-libs nodejs sqlite-libs && \
    update-ca-certificates && \
    rm -rf /var/cache/apk/*

