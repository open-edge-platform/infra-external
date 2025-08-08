// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package status

import (
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	inv_status "github.com/open-edge-platform/infra-core/inventory/v2/pkg/status"
)

var (

	// Resource statuses for AMT activation.
	AMTActivationStatusUnknown    = inv_status.New("Unknown", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
	AMTActivationStatusInProgress = inv_status.New("AMT Activation In Progress",
		statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS)
	AMTActivationStatusFailed = inv_status.New("AMT Activation Failed", statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	AMTActivationStatusDone   = inv_status.New("AMT Activation Done", statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// Resource statuses for AMT deactivation.
	AMTDeactivationStatusFailed     = inv_status.New("AMT Deactivation Failed", statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	AMTDeactivationStatusDone       = inv_status.New("AMT Deactivation Done", statusv1.StatusIndication_STATUS_INDICATION_IDLE)
	AMTDeactivationStatusInProgress = inv_status.New("AMT Deactivation In Progress",
		statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS)

	// Resource statuses for AMT status.
	AMTStatusUnknown  = inv_status.New("AMT Status Unknown", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
	AMTStatusEnabled  = inv_status.New("AMT Status Enabled", statusv1.StatusIndication_STATUS_INDICATION_IDLE)
	AMTStatusDisabled = inv_status.New("AMT Status Disabled", statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// Resource statuses for Host
	DefaultHostPowerOff     = []string{"No Connection", "Invalidated"}
	DefaultHostPowerOn      = []string{"Running", "Booting", "Invalidating", "Deleting"}
	DefaultHostPowerUnknown = []string{"Unknown", "Error"}
)
