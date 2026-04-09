// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package flags

const (
	MpsAddressFlag              = "mpsAddress"
	RpsAddressFlag              = "rpsAddress"
	SOLServerAddressFlag        = "solServerAddress"
	PasswordPolicyFlag          = "passwordPolicy"
	ReconcilePeriodFlag         = "reconcilePeriod"
	RequestTimeoutFlag          = "requestTimeout"
	StatusChangeGracePeriodFlag = "statusChangeGracePeriod"

	ReconcilePeriodDescription = "How often perform full reconciliation for every tenant"
	RequestTimeoutDescription  = "Timeout for requests that are performed by SOL manager"
	PasswordPolicyDescription  = "One of two password policies: 'static' or 'dynamic'. " +
		"In 'static' same user-provided password is used for every device, " +
		"in 'dynamic' it is automatically generated per-device."
	MpsAddressDescription      = "Address of Management Presence Service (MPS)"
	RpsAddressDescription      = "Address of Remote Provisioning Service (RPS)"
	SOLServerAddressDescription = "Address of SOL Manager gRPC/WebSocket service"
	InsecureDescription        = "Skip TLS verification for MPS/RPS. " +
		"Not recommended for production and should be used only for development."
	StatusChangeGracePeriodDescription = "Defines for how long SOL manager waits for reported status to change " +
		"until it marks the SOL state as 'Error'"
)
