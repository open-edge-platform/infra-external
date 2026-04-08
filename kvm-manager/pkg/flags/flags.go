// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// Package flags defines CLI flag names and descriptions for kvm-manager.
package flags

// Flag names and descriptions used by cmd/kvm-manager.go.
const (
	MpsAddressFlag  = "mpsAddress"
	MpsDomainFlag   = "mpsDomain"
	ReconcilePeriod = "reconcilePeriod"
	RequestTimeout  = "requestTimeout"

	MpsAddressDescription      = "Base HTTP address of MPS, e.g. http://mps.orch-infra.svc:3000"
	MpsDomainDescription       = "Public MPS WebSocket relay hostname written into kvm_session_url, e.g. mps-wss.example.com"
	ReconcilePeriodDescription = "How often to perform full reconciliation of all hosts"
	RequestTimeoutDescription  = "Timeout for requests performed by kvm-manager"
	InsecureDescription        = "Skip TLS verification for MPS. Not recommended for production."
)
