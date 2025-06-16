/*
 * // SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * // SPDX-License-Identifier: Apache-2.0
 */

package flags

const (
	MpsAddressFlag              = "mpsAddress"
	RpsAddressFlag              = "rpsAddress"
	PasswordPolicyFlag          = "passwordPolicy"
	ReconcilePeriodFlag         = "reconcilePeriod"
	RequestTimeoutFlag          = "requestTimeout"
	StatusChangeGracePeriodFlag = "statusChangeGracePeriod"

	ReconcilePeriodDescription = "How often perform full reconciliation for every tenant"
	RequestTimeoutDescription  = "Timeout for requests that are performed by DM manager"
	PasswordPolicyDescription  = "One of two password policies: 'static' or 'dynamic'. " +
		"In 'static' same user-provided password is used for every device," +
		"in 'dynamic' it is automatically generated per-device."
	MpsAddressDescription = "Address of Management Presence Service (MPS)"
	RpsAddressDescription = "Address of Remote Provisioning Service (RPS)"
	InsecureDescription   = "Skip TLS verification for MPS/RPS. " +
		"Does not recommended for production and should be used only for development."
	StatusChangeGracePeriodDescription = "Defines for how long Device manager waits for reported power status to change " +
		"until it will mark power state as 'Error'"
)
